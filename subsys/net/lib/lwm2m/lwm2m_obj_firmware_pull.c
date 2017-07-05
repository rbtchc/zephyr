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

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <net/zoap.h>
#include <net/net_core.h>
#include <net/net_pkt.h>
#include <net/http_parser.h>

#include "lwm2m_object.h"
#include "lwm2m_engine.h"

#define STATE_IDLE		0
#define STATE_CONNECTING	1

#define PACKAGE_URI_LEN				255

static u8_t transfer_state;
static struct k_work firmware_work;
static char firmware_uri[PACKAGE_URI_LEN];
static struct sockaddr firmware_addr;
static struct http_parser_url parsed_uri;
static struct net_context *firmware_net_ctx;
static struct k_delayed_work retransmit_work;

#define NUM_PENDINGS	CONFIG_LWM2M_ENGINE_MAX_PENDING
#define NUM_REPLIES	CONFIG_LWM2M_ENGINE_MAX_REPLIES
static struct zoap_pending pendings[NUM_PENDINGS];
static struct zoap_reply replies[NUM_REPLIES];
static struct zoap_block_context firmware_block_ctx;

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

	/* Save the from address */
#if defined(CONFIG_NET_IPV6)
	if (net_pkt_family(pkt) == AF_INET6) {
		net_ipaddr_copy(&net_sin6(&from_addr)->sin6_addr,
				&NET_IPV6_HDR(pkt)->src);
		net_sin6(&from_addr)->sin6_port = NET_TCP_HDR(pkt)->src_port;
		net_sin6(&from_addr)->sin6_family = AF_INET6;
	}
#endif

#if defined(CONFIG_NET_IPV4)
	if (net_pkt_family(pkt) == AF_INET) {
		net_ipaddr_copy(&net_sin(&from_addr)->sin_addr,
				&NET_IPV4_HDR(pkt)->src);
		net_sin(&from_addr)->sin_port = NET_TCP_HDR(pkt)->src_port;
		net_sin(&from_addr)->sin_family = AF_INET;
	}
#endif

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

	r = net_context_sendto(pending->pkt, &pending->addr,
			       NET_SOCKADDR_MAX_SIZE,
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
			    zoap_reply_t reply_cb)
{
	struct zoap_packet request;
	struct net_pkt *pkt = NULL;
	struct zoap_pending *pending;
	struct net_buf *frag;
	struct zoap_reply *reply = NULL;
	int ret;

	u16_t off;
	u16_t len;
	char *cursor;
	int path_len;

	/* send request */
	pkt = net_pkt_get_tx(firmware_net_ctx, K_FOREVER);
	if (!pkt) {
		SYS_LOG_ERR("Unable to get TX packet, not enough memory.");
		return -ENOMEM;
	}

	frag = net_pkt_get_data(firmware_net_ctx, K_FOREVER);
	if (!frag) {
		SYS_LOG_ERR("Unable to get DATA buffer, not enough memory.");
		ret = -ENOMEM;
		goto cleanup;
	}

	net_pkt_frag_add(pkt, frag);

	ret = zoap_packet_init(&request, pkt);
	if (ret < 0) {
		SYS_LOG_ERR("zoap packet init error (err:%d)", ret);
		return ret;
	}

	/* FIXME: Could be that zoap_packet_init() sets some defaults */
	zoap_header_set_version(&request, 1);
	zoap_header_set_type(&request, ZOAP_TYPE_CON);
	zoap_header_set_code(&request, ZOAP_METHOD_GET);
	zoap_header_set_id(&request, zoap_next_id());

	if (token && tkl > 0) {
		zoap_header_set_token(&request, token, tkl);
	} else if (tkl == 0) {
		zoap_header_set_token(&request, zoap_next_token(), 8);
	}

	/* set the reply handler */
	if (reply_cb) {
		reply = zoap_reply_next_unused(replies, NUM_REPLIES);
		if (!reply) {
			SYS_LOG_ERR("No resources for waiting for replies.");
			ret = -ENOMEM;
			goto cleanup;
		}

		zoap_reply_init(reply, &request);
		reply->reply = reply_cb;
	}

	/* if path is not available, off/len will be zero */
	off = parsed_uri.field_data[UF_PATH].off;
	len = parsed_uri.field_data[UF_PATH].len;
	cursor = firmware_uri+off;
	path_len = 0;
	for (int i = 0; i < len; i++) {
		if (firmware_uri[off+i] == '/') {
			if (path_len > 0) {
				ret = zoap_add_option(&request,
						ZOAP_OPTION_URI_PATH,
						cursor, path_len);
				if (ret < 0) {
					SYS_LOG_ERR("Error adding URI_PATH");
					goto cleanup;
				}
				cursor += (path_len+1);
				path_len = 0;
			} else {
				/* skip current slash */
				cursor += 1;
			}
			continue;
		}
		if (i == len-1) {
			/* flush the rest */
			ret = zoap_add_option(&request, ZOAP_OPTION_URI_PATH,
					cursor, path_len+1);
			if (ret < 0) {
				SYS_LOG_ERR("Error adding URI_PATH");
				goto cleanup;
			}
			break;
		}
		path_len += 1;
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

	ret = net_context_sendto(pkt, &firmware_addr, NET_SOCKADDR_MAX_SIZE,
				 NULL, 0, NULL, NULL);
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
	lwm2m_engine_set_data_cb_t callback;

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
		callback = lwm2m_firmware_get_write_cb();
		if (callback) {
			callback(0, payload, payload_len,
				(firmware_block_ctx.current ==
					firmware_block_ctx.total_size),
				firmware_block_ctx.total_size);
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
	static struct sockaddr_in6 any_addr6 = { .sin6_addr = IN6ADDR_ANY_INIT,
						.sin6_family = AF_INET6 };
#endif
#if defined(CONFIG_NET_IPV4)
	static struct sockaddr_in any_addr4 = { .sin_addr = INADDR_ANY_INIT,
					       .sin_family = AF_INET };
#endif
	struct net_if *iface;
	int ret, family;

	u16_t off;
	u16_t len;
	char tmp;

	/* Server Peer IP information */
	family = AF_INET;

	ret = http_parser_parse_url(firmware_uri,
				    strlen(firmware_uri),
				    0,
				    &parsed_uri);
	if (ret != 0) {
		SYS_LOG_ERR("Invalid firmware URI: %s", firmware_uri);
		return;
	}

	/* Check schema and only support coap for now */
	if (!(parsed_uri.field_set & (1 << UF_SCHEMA))) {
		SYS_LOG_ERR("No schema in package uri");
		return;
	}

	off = parsed_uri.field_data[UF_SCHEMA].off;
	len = parsed_uri.field_data[UF_SCHEMA].len;
	if (len != 4 || memcmp(firmware_uri+off, "coap", 4)) {
		SYS_LOG_ERR("Unsupported schema");
		return;
	}

	if (!(parsed_uri.field_set & (1 << UF_PORT))) {
		/* Set to default port of CoAP */
		parsed_uri.port = 5683;
	}

	off = parsed_uri.field_data[UF_HOST].off;
	len = parsed_uri.field_data[UF_HOST].len;
	/* IPv6 is wrapped by brackets */
	if (off > 0 && firmware_uri[off-1] == '[') {
		family = AF_INET6;
#if !defined(CONFIG_NET_IPV6)
		SYS_LOG_ERR("Doesn't support IPv6");
		return;
#endif
	} else {
		family = AF_INET;
		/* Distinguish IPv4 or DNS */
		for (int i = off; i < off+len; i++) {
			if (!isdigit(firmware_uri[i]) &&
			    firmware_uri[i] != '.') {
				SYS_LOG_ERR("Doesn't support DNS lookup");
				return;
			}
		}
		if (family == AF_INET) {
#if !defined(CONFIG_NET_IPV4)
			SYS_LOG_ERR("Doesn't support IPv4");
			return;
#endif
		}
	}

	tmp = firmware_uri[off+len];
	firmware_uri[off+len] = '\0';
#if defined(CONFIG_NET_IPV6)
	if (family == AF_INET6) {
		firmware_addr.family = family;
		/* HACK: use firmware_uri directly as IP address */
		net_addr_pton(firmware_addr.family, firmware_uri+off,
			      &net_sin6(&firmware_addr)->sin6_addr);
		net_sin6(&firmware_addr)->sin6_port = htons(parsed_uri.port);
	}
#endif

#if defined(CONFIG_NET_IPV4)
	if (family == AF_INET) {
		firmware_addr.family = family;
		net_addr_pton(firmware_addr.family, firmware_uri+off,
			      &net_sin(&firmware_addr)->sin_addr);
		net_sin(&firmware_addr)->sin_port = htons(parsed_uri.port);
	}
#endif
	/* restore firmware_uri */
	firmware_uri[off+len] = tmp;

	ret = net_context_get(firmware_addr.family, SOCK_DGRAM, IPPROTO_UDP,
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

#if defined(CONFIG_NET_IPV6)
	if (firmware_addr.family == AF_INET6) {
		ret = net_context_bind(firmware_net_ctx,
				       (struct sockaddr *)&any_addr6,
				       sizeof(any_addr6));
	}
#endif

#if defined(CONFIG_NET_IPV4)
	if (firmware_addr.family == AF_INET) {
		ret = net_context_bind(firmware_net_ctx,
				       (struct sockaddr *)&any_addr4,
				       sizeof(any_addr4));
	}
#endif

	if (ret) {
		NET_ERR("Could not bind the UDP context (err:%d)", ret);
		goto cleanup;
	}

	SYS_LOG_DBG("Attached to port: %d", parsed_uri.port);
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
		strcpy(firmware_uri, package_uri);
		k_work_submit(&firmware_work);
		return 0;
	}

	return -1;
}
