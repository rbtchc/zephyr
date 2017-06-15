/*
 * Copyright (c) 2017 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * TODO:
 * Support PULL transfer method (from server)
 */

#define SYS_LOG_DOMAIN "lwm2m_obj_firmware_pull"
#define SYS_LOG_LEVEL CONFIG_SYS_LOG_LWM2M_LEVEL
#include <logging/sys_log.h>

#include <stdio.h>
#include <net/zoap.h>
#include <net/net_core.h>
#include <net/net_pkt.h>

#include "lwm2m_object.h"
#include "lwm2m_engine.h"

#if defined(CONFIG_NET_IPV6)
#define LWM2M_AF_INET		AF_INET6
#define IN_ADDR			struct in6_addr
#define NET_SIN_FAMILY(s)	net_sin6(s)->sin6_family
#define NET_SIN_ADDR(s)		net_sin6(s)->sin6_addr
#define NET_SIN_PORT(s)		net_sin6(s)->sin6_port
#define NET_SIN_SIZE		sizeof(struct sockaddr_in6)
#define NET_SIN_ADDR_SIZE	NET_IPV6_ADDR_LEN
#define NET_IP_HDR		NET_IPV6_HDR
#elif defined(CONFIG_NET_IPV4)
#define LWM2M_AF_INET		AF_INET
#define IN_ADDR			struct in_addr
#define NET_SIN_FAMILY(s)	net_sin(s)->sin_family
#define NET_SIN_ADDR(s)		net_sin(s)->sin_addr
#define NET_SIN_PORT(s)		net_sin(s)->sin_port
#define NET_SIN_SIZE		sizeof(struct sockaddr_in)
#define NET_SIN_ADDR_SIZE	NET_IPV4_ADDR_LEN
#define NET_IP_HDR		NET_IPV4_HDR
#endif

#define STATE_IDLE		0
#define STATE_CONNECTING	1

static u8_t transfer_state;
static struct k_work firmware_work;
static char *firmware_uri;
static struct sockaddr firmware_addr;
static struct net_context *firmware_net_ctx;
static struct k_delayed_work retransmit_work;

#define NUM_PENDINGS	CONFIG_LWM2M_ENGINE_MAX_PENDING
#define NUM_REPLIES	CONFIG_LWM2M_ENGINE_MAX_REPLIES
static struct zoap_pending pendings[NUM_PENDINGS];
static struct zoap_reply replies[NUM_REPLIES];
static struct zoap_block_context firmware_block_ctx;

/* for debugging: to print IP addresses */
static inline char *
sprint_ip_addr(const struct sockaddr *addr)
{
	static char buf[NET_IPV6_ADDR_LEN];

#if defined(CONFIG_NET_IPV6)
	if (addr->family == AF_INET6) {
		return net_addr_ntop(AF_INET6, &net_sin6(addr)->sin6_addr,
				     buf, sizeof(buf));
	}
#endif
#if defined(CONFIG_NET_IPV4)
	if (addr->family == AF_INET) {
		return net_addr_ntop(AF_INET, &net_sin(addr)->sin_addr,
				     buf, sizeof(buf));
	}
#endif

	SYS_LOG_ERR("Unknown IP address family:%d", addr->family);
	return NULL;
}

static inline char *sprint_token(const u8_t *token, u8_t tkl)
{
	int i;
	static char buf[32];
	int pos = 0;

	for (i = 0; i < tkl; i++) {
		pos += snprintf(&buf[pos], 31 - pos, "%x", token[i]);
	}
	buf[pos] = '\0';
	return buf;
}

static int
zoap_init_message(struct zoap_packet *zpkt, struct net_pkt **pkt, u8_t type,
		  u8_t code, u16_t mid, const u8_t *token, u8_t tkl,
		  zoap_reply_t reply_cb)
{
	struct net_buf *frag;
	struct zoap_reply *reply = NULL;
	int r;

	*pkt = net_pkt_get_tx(firmware_net_ctx, K_FOREVER);
	if (!*pkt) {
		SYS_LOG_ERR("Unable to get TX packet, not enough memory.");
		return -ENOMEM;
	}

	frag = net_pkt_get_data(firmware_net_ctx, K_FOREVER);
	if (!frag) {
		SYS_LOG_ERR("Unable to get DATA buffer, not enough memory.");
		net_pkt_unref(*pkt);
		*pkt = NULL;
		return -ENOMEM;
	}

	net_pkt_frag_add(*pkt, frag);

	r = zoap_packet_init(zpkt, *pkt);
	if (r < 0) {
		SYS_LOG_ERR("zoap packet init error (err:%d)", r);
		return r;
	}

	/* FIXME: Could be that zoap_packet_init() sets some defaults */
	zoap_header_set_version(zpkt, 1);
	zoap_header_set_type(zpkt, type);
	zoap_header_set_code(zpkt, code);
	if (mid > 0) {
		zoap_header_set_id(zpkt, mid);
	} else {
		zoap_header_set_id(zpkt, zoap_next_id());
	}

	if (token && tkl > 0) {
		zoap_header_set_token(zpkt, token, tkl);
	} else if (tkl == 0) {
		zoap_header_set_token(zpkt, zoap_next_token(), 8);
	}

	/* set the reply handler */
	if (reply_cb) {
		reply = zoap_reply_next_unused(replies, NUM_REPLIES);
		if (!reply) {
			SYS_LOG_ERR("No resources for waiting for replies.");
			net_pkt_unref(*pkt);
			*pkt = NULL;
			return -1;
		}

		zoap_reply_init(reply, zpkt);
		reply->reply = reply_cb;
	}

	return 0;
}

static void
firmware_udp_receive(struct net_context *ctx, struct net_pkt *pkt, int status,
		     void *user_data)
{
	struct zoap_pending *pending;
	struct zoap_reply *reply;
	struct zoap_packet response;
	int header_len, r;
	const u8_t *token;
	u8_t tkl;
	struct sockaddr from_addr;

	/* Log the response */
	net_ipaddr_copy(&NET_SIN_ADDR(&from_addr),
			&NET_IP_HDR(pkt)->src);
	NET_SIN_PORT(&from_addr) = NET_UDP_HDR(pkt)->src_port;
	NET_SIN_FAMILY(&from_addr) = LWM2M_AF_INET;

	SYS_LOG_DBG("UDP Response Received [%s:%d]",
		sprint_ip_addr(&from_addr),
		ntohs(NET_SIN_PORT(&from_addr)));

	/*
	 * zoap expects that buffer->data starts at the
	 * beginning of the CoAP header
	 */
	header_len = net_pkt_appdata(pkt) - pkt->frags->data;
	net_buf_pull(pkt->frags, header_len);

	r = zoap_packet_parse(&response, pkt);
	if (r < 0) {
		SYS_LOG_ERR("Invalid data received (err:%d)", r);
		goto cleanup;
	}

	token = zoap_header_get_token(&response, &tkl);
	SYS_LOG_DBG("MESSAGE INFO type:%d code:%d.%d mid:%d token:'%s'",
		zoap_header_get_type(&response),
		ZOAP_RESPONSE_CODE_CLASS(zoap_header_get_code(&response)),
		ZOAP_RESPONSE_CODE_DETAIL(zoap_header_get_code(&response)),
		zoap_header_get_id(&response),
		sprint_token(token, tkl));

	pending = zoap_pending_received(&response, pendings,
					NUM_PENDINGS);
	if (pending) {
		/* If necessary cancel retransmissions */
	}

	SYS_LOG_DBG("checking for reply from [%s]",
		    sprint_ip_addr(&from_addr));
	reply = zoap_response_received(&response, &from_addr,
				       replies, NUM_REPLIES);
	if (!reply) {
		SYS_LOG_ERR("No handler for response");
	} else {
		SYS_LOG_DBG("reply handled reply:%p", reply);
		zoap_reply_clear(reply);
	}

cleanup:
	if (pkt) {
		net_pkt_unref(pkt);
	}
}

static void retransmit_request(struct k_work *work)
{
	struct zoap_pending *pending;
	int r;

	pending = zoap_pending_next_to_expire(pendings, NUM_PENDINGS);
	if (!pending) {
		return;
	}

	r = net_context_sendto(pending->pkt, &firmware_addr, NET_SIN_SIZE,
			       NULL, K_NO_WAIT, NULL, NULL);
	if (r < 0) {
		return;
	}

	if (!zoap_pending_cycle(pending)) {
		zoap_pending_clear(pending);
		return;
	}

	k_delayed_work_submit(&retransmit_work, pending->timeout);
}

static int transfer_request(struct zoap_block_context *ctx,
			    const u8_t *token, u8_t tkl,
			    int (*reply_cb)(const struct zoap_packet *response,
					struct zoap_reply *reply,
					const struct sockaddr *from))
{
	struct zoap_packet request;
	struct net_pkt *pkt = NULL;
	struct zoap_pending *pending;
	int ret;

	/* send request */
	ret = zoap_init_message(&request, &pkt, ZOAP_TYPE_CON,
				ZOAP_METHOD_GET, 0, token, tkl,
				reply_cb);
	if (ret) {
		goto cleanup;
	}

	ret = zoap_add_option(&request, ZOAP_OPTION_URI_PATH,
			"large-create", strlen("large-create"));
	ret = zoap_add_option(&request, ZOAP_OPTION_URI_PATH,
			"1", strlen("1"));
	if (ret < 0) {
		SYS_LOG_ERR("Error adding URI_QUERY 'large'");
		goto cleanup;
	}

	ret = zoap_add_block2_option(&request, ctx);
	if (ret) {
		SYS_LOG_ERR("Unable to add block2 option.");
		goto cleanup;
	}

	pending = zoap_pending_next_unused(pendings, NUM_PENDINGS);
	if (!pending) {
		SYS_LOG_ERR("Unable to find a free pending to track "
			    "retransmissions.");
		ret = -ENOMEM;
		goto cleanup;
	}

	ret = zoap_pending_init(pending, &request, &firmware_addr);
	if (ret < 0) {
		SYS_LOG_ERR("Unable to initialize a pending "
			    "retransmission (err:%d).", ret);
		goto cleanup;
	}

	ret = net_context_sendto(pkt, &firmware_addr, NET_SIN_SIZE, NULL,
				 0, NULL, NULL);
	if (ret < 0) {
		SYS_LOG_ERR("Error sending LWM2M packet (err:%d).",
			    ret);
		goto cleanup;
	}

	zoap_pending_cycle(pending);
	k_delayed_work_submit(&retransmit_work, pending->timeout);

	return 0;

cleanup:
	if (pkt) {
		net_pkt_unref(pkt);
	}

	return ret;
}

static int
do_firmware_transfer_reply_cb(const struct zoap_packet *response,
			      struct zoap_reply *reply,
			      const struct sockaddr *from)
{
	int ret;
	const u8_t *token;
	u8_t tkl;
	u16_t payload_len;
	u8_t *payload;
	struct zoap_packet *check_response = (struct zoap_packet *)response;
	lwm2m_block_received_cb_t callback;

	SYS_LOG_DBG("TRANSFER REPLY");

	ret = zoap_update_from_block(check_response, &firmware_block_ctx);
	if (ret < 0) {
		SYS_LOG_ERR("Error from block update: %d", ret);
		return ret;
	}

	/* TODO: Process incoming data */
	payload = zoap_packet_get_payload(check_response, &payload_len);
	if (payload_len > 0) {
		/* TODO: Determine when to actually advance to next block */
		zoap_next_block(&firmware_block_ctx);

		SYS_LOG_DBG("total: %zd, current: %zd",
			    firmware_block_ctx.total_size,
			    firmware_block_ctx.current);

		/* callback */
		callback = lwm2m_firmware_get_block_received_cb();
		if (callback) {
			ret = callback(payload, payload_len,
				(firmware_block_ctx.current ==
					firmware_block_ctx.total_size),
				firmware_block_ctx.total_size);
			if (ret < 0) {
				SYS_LOG_ERR("firmware callback err: %d", ret);
			}
		}
	}

	/* TODO: Determine actual completion criteria */
	if (firmware_block_ctx.current < firmware_block_ctx.total_size) {
		token = zoap_header_get_token(check_response, &tkl);
		ret = transfer_request(&firmware_block_ctx, token, tkl,
				       do_firmware_transfer_reply_cb);
	}

	return ret;
}

static void firmware_transfer(struct k_work *work)
{
#if defined(CONFIG_NET_IPV6)
	static struct sockaddr_in6 any_addr = { .sin6_addr = IN6ADDR_ANY_INIT,
						.sin6_family = AF_INET6 };
#elif defined(CONFIG_NET_IPV4)
	static struct sockaddr_in any_addr = { .sin_addr = INADDR_ANY_INIT,
					       .sin_family = AF_INET };
#endif
	struct net_if *iface;
	int ret;

	/* Server Peer IP information */
	/* TODO: use server URI data from security */
	net_addr_pton(LWM2M_AF_INET, firmware_uri,
		      &NET_SIN_ADDR(&firmware_addr));
	NET_SIN_FAMILY(&firmware_addr) = LWM2M_AF_INET;
	NET_SIN_PORT(&firmware_addr) = htons(5685);

	ret = net_context_get(LWM2M_AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			    &firmware_net_ctx);
	if (ret) {
		NET_ERR("Could not get an UDP context (err:%d)", ret);
		return;
	}

	iface = net_if_get_default();
	if (!iface) {
		NET_ERR("Could not find default interface");
		goto cleanup;
	}

	ret = net_context_bind(firmware_net_ctx, (struct sockaddr *)&any_addr,
			       sizeof(any_addr));
	if (ret) {
		NET_ERR("Could not bind the UDP context (err:%d)", ret);
		goto cleanup;
	}

	SYS_LOG_DBG("Attached to port: %d",
		    htons(net_sin_ptr(&firmware_net_ctx->local)->sin_port));

	ret = net_context_recv(firmware_net_ctx, firmware_udp_receive, 0, NULL);
	if (ret) {
		SYS_LOG_ERR("Could not set receive for net context (err:%d)",
			    ret);
		goto cleanup;
	}

	/* reset block transfer context */
#if defined(NET_L2_BLUETOOTH)
	zoap_block_transfer_init(&firmware_block_ctx, ZOAP_BLOCK_64, 0);
#else
	zoap_block_transfer_init(&firmware_block_ctx, ZOAP_BLOCK_256, 0);
#endif

	transfer_request(&firmware_block_ctx, NULL, 0,
			 do_firmware_transfer_reply_cb);
	return;

cleanup:
	if (firmware_net_ctx) {
		net_context_put(firmware_net_ctx);
	}
}

/* TODO: */
int lwm2m_firmware_cancel_transfer(void)
{
	return 0;
}

int lwm2m_firmware_start_transfer(char *package_uri)
{
	/* free up old context */
	if (firmware_net_ctx) {
		net_context_put(firmware_net_ctx);
	}

	if (transfer_state == STATE_IDLE) {
		k_work_init(&firmware_work, firmware_transfer);
		k_delayed_work_init(&retransmit_work, retransmit_request);

		/* start file transfer work */
		firmware_uri = package_uri;
		k_work_submit(&firmware_work);
		return 0;
	}

	return -1;
}
