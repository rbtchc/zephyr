/*
 * Copyright (c) 2017 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Copyright (c) 2015, Yanzi Networks AB.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Original authors:
 *         Joakim Eriksson <joakime@sics.se>
 *         Niclas Finne <nfi@sics.se>
 *         Joel Hoglund <joel@sics.se>
 */

#define SYS_LOG_DOMAIN "lib/lwm2m_rd_client"
#define SYS_LOG_LEVEL CONFIG_SYS_LOG_LWM2M_LEVEL
#include <logging/sys_log.h>

#include <assert.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <init.h>
#include <misc/printk.h>
#include <net/net_app.h>
#include <net/net_pkt.h>
#include <net/zoap.h>
#include <net/lwm2m.h>
#include <net/http_parser.h>

#include "lwm2m_object.h"
#include "lwm2m_engine.h"

#define LWM2M_RD_CLIENT_URI "rd"

#define SECONDS_TO_UPDATE_EARLY	2
#define STATE_MACHINE_UPDATE_INTERVAL 500

#define LWM2M_PEER_PORT		CONFIG_LWM2M_PEER_PORT
#define LWM2M_BOOTSTRAP_PORT	CONFIG_LWM2M_BOOTSTRAP_PORT

/* Leave room for 32 hexadeciaml digits (UUID) + NULL */
#define CLIENT_EP_LEN		33

/* The states for the RD client state machine */
/*
 * When node is unregistered it ends up in UNREGISTERED
 * and this is going to be there until use X or Y kicks it
 * back into INIT again
 */
enum sm_engine_state {
	ENGINE_INIT,
	ENGINE_DO_BOOTSTRAP,
	ENGINE_BOOTSTRAP_SENT,
	ENGINE_BOOTSTRAP_DONE,
	ENGINE_DO_REGISTRATION,
	ENGINE_REGISTRATION_SENT,
	ENGINE_REGISTRATION_DONE,
	ENGINE_UPDATE_SENT,
	ENGINE_DEREGISTER,
	ENGINE_DEREGISTER_SENT,
	ENGINE_DEREGISTER_FAILED,
	ENGINE_DEREGISTERED
};

struct lwm2m_rd_client_info {
	u16_t lifetime;
	u16_t ssid;
	struct net_app_ctx ctx;
	struct sockaddr bs_server;
	struct sockaddr reg_server;
	u8_t engine_state;
	u8_t use_bootstrap;
	u8_t has_bs_server_info;
	u8_t use_registration;
	u8_t has_registration_info;
	u8_t registered;
	u8_t bootstrapped; /* bootstrap done */
	u8_t trigger_update;

	s64_t last_update;

	char ep_name[CLIENT_EP_LEN];
	char server_ep[CLIENT_EP_LEN];
};

static K_THREAD_STACK_DEFINE(lwm2m_rd_client_thread_stack,
			     CONFIG_LWM2M_RD_CLIENT_STACK_SIZE);
struct k_thread lwm2m_rd_client_thread_data;

/* HACK: remove when engine transactions are ready */
#define NUM_PENDINGS	CONFIG_LWM2M_ENGINE_MAX_PENDING
#define NUM_REPLIES	CONFIG_LWM2M_ENGINE_MAX_REPLIES

extern struct zoap_pending pendings[NUM_PENDINGS];
extern struct zoap_reply replies[NUM_REPLIES];
extern struct k_delayed_work retransmit_work;

/* buffers */
static char query_buffer[64]; /* allocate some data for queries and updates */
static u8_t client_data[256]; /* allocate some data for the RD */

#define CLIENT_INSTANCE_COUNT	CONFIG_LWM2M_RD_CLIENT_INSTANCE_COUNT
static struct lwm2m_rd_client_info clients[CLIENT_INSTANCE_COUNT];
static int client_count;

/* net_app_connect wait time */
#define CONNECT_TIME	K_SECONDS(10)
#define WAIT_TIME	K_SECONDS(10)

#if defined(CONFIG_NET_APP_DTLS)
#define HOSTNAME "localhost"   /* for cert verification if that is enabled */

/* The result buf size is set to large enough so that we can receive max size
 * buf back. Note that mbedtls needs also be configured to have equal size
 * value for its buffer size. See MBEDTLS_SSL_MAX_CONTENT_LEN option in DTLS
 * config file.
 */
#define RESULT_BUF_SIZE 1500
static u8_t dtls_result_ipv6[RESULT_BUF_SIZE];
static u8_t dtls_result_ipv4[RESULT_BUF_SIZE];

#if !defined(CONFIG_NET_APP_TLS_STACK_SIZE)
#define CONFIG_NET_APP_TLS_STACK_SIZE		6144
#endif /* CONFIG_NET_APP_TLS_STACK_SIZE */

#define INSTANCE_INFO "Zephyr DTLS echo-client #1"

/* Note that each net_app context needs its own stack as there will be
 * a separate thread needed.
 */
NET_STACK_DEFINE(NET_APP_DTLS_IPv4, net_app_dtls_stack_ipv4,
		 CONFIG_NET_APP_TLS_STACK_SIZE, CONFIG_NET_APP_TLS_STACK_SIZE);

NET_STACK_DEFINE(NET_APP_DTLS_IPv6, net_app_dtls_stack_ipv6,
		 CONFIG_NET_APP_TLS_STACK_SIZE, CONFIG_NET_APP_TLS_STACK_SIZE);

NET_APP_TLS_POOL_DEFINE(dtls_pool, 10);
#else
#define dtls_result_ipv6 NULL
#define dtls_result_ipv4 NULL
#define net_app_dtls_stack_ipv4 NULL
#define net_app_dtls_stack_ipv6 NULL
#endif /* CONFIG_NET_APP_TLS */

#if defined(CONFIG_NET_APP_TLS)
/* Load the certificates and private RSA key. */

#include "test_certs.h"

static int setup_cert(struct net_app_ctx *ctx, void *cert)
{
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
	mbedtls_ssl_conf_psk(&ctx->tls.mbedtls.conf,
			     client_psk, sizeof(client_psk),
			     (const unsigned char *)client_psk_id,
			     sizeof(client_psk_id) - 1);
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
	{
		mbedtls_x509_crt *ca_cert = cert;
		int ret;

		ret = mbedtls_x509_crt_parse_der(ca_cert,
						 ca_certificate,
						 sizeof(ca_certificate));
		if (ret != 0) {
			SYS_LOG_ERR("mbedtls_x509_crt_parse_der failed "
				"(-0x%x)", -ret);
			return ret;
		}

		mbedtls_ssl_conf_ca_chain(&ctx->tls.mbedtls.conf,
					  ca_cert, NULL);

		/* In this example, we skip the certificate checks. In real
		 * life scenarios, one should always verify the certificates.
		 */
		mbedtls_ssl_conf_authmode(&ctx->tls.mbedtls.conf,
					  MBEDTLS_SSL_VERIFY_REQUIRED);

		mbedtls_ssl_conf_cert_profile(&ctx->tls.mbedtls.conf,
					      &mbedtls_x509_crt_profile_default);
#define VERIFY_CERTS 0
#if VERIFY_CERTS
		mbedtls_ssl_conf_authmode(&ctx->tls.mbedtls.conf,
					  MBEDTLS_SSL_VERIFY_OPTIONAL);
#else
		;
#endif /* VERIFY_CERTS */
	}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

	return 0;
}
#endif /* CONFIG_NET_APP_TLS */

extern int get_security_obj(u16_t ssid, bool bootstrap,
			    struct security_object **obj);
extern int put_security_obj(const char *server_uri, bool bootstrap);

static void disconnect_udp(struct net_app_ctx *ctx);

static void set_sm_state(int index, u8_t state)
{
	/* TODO: add locking? */
	clients[index].engine_state = state;
}

static u8_t get_sm_state(int index)
{
	/* TODO: add locking? */
	return clients[index].engine_state;
}

int engine_bootstrap_done(bool success)
{
	u8_t state;
	int index;

	for (index = 0; index < client_count; index++) {
		if (clients[index].use_bootstrap) {
			/* Check engine_state */
			state = get_sm_state(index);
			if (state < ENGINE_DO_BOOTSTRAP &&
			    state > ENGINE_DO_REGISTRATION) {
				continue;
			}

			if (clients[index].bootstrapped) {
				SYS_LOG_ERR("Already bootstrapped!");
				return -EINVAL;
			}

			if (success) {
				set_sm_state(index, ENGINE_BOOTSTRAP_DONE);
			} else {
				/* TODO: rollback changes */
				disconnect_udp(&clients[index].ctx);
				set_sm_state(index, ENGINE_INIT);
			}
			return 0;
		}
	}
	return -ENOENT;
}

/* Check whether system is still bootstrapping */
bool engine_bootstrapping(void)
{
	int i;
	u8_t state;

	/* Only bootstrap serve is allowed */
	for (i = 0; i < client_count; i++) {
		state = get_sm_state(i);
		if (state >= ENGINE_DO_BOOTSTRAP &&
		    state < ENGINE_DO_REGISTRATION) {
			return true;
		}
	}
	return false;
}

/* Check if the address matches the bootstrap server address */
int engine_validate_bootstrap_server(const struct sockaddr *addr)
{
	int i;

	for (i = 0; i < client_count; i++) {
		if (clients[i].use_bootstrap &&
		    memcmp(addr, &clients[i].bs_server, sizeof(addr)) == 0) {
			return 0;
		}
	}
	return -ENOENT;
}

static int find_clients_index(const struct sockaddr *addr,
				  bool check_bs_server)
{
	int index = -1, i;

	for (i = 0; i < client_count; i++) {
		if (check_bs_server) {
			if (memcmp(addr, &clients[i].bs_server,
				   sizeof(addr)) == 0) {
				index = i;
				break;
			}
		} else {
			if (memcmp(addr, &clients[i].reg_server,
				   sizeof(addr)) == 0) {
				index = i;
				break;
			}
		}
	}

	return index;
}

static void disconnect_udp(struct net_app_ctx *ctx)
{
	net_app_close(ctx);
	net_app_release(ctx);
}

/* Connect to bootstrap/registraion server */
static int connect_udp(int index, bool bootstrap)
{
	struct security_object *obj;
	struct http_parser_url parser;
	char uri[SECURITY_URI_LEN];
	u16_t off;
	u16_t len;
	int ret;

	assert(clients[index].ctx.is_init == false);

	ret = get_security_obj(clients[index].ssid, bootstrap, &obj);
	if (ret < 0) {
		SYS_LOG_ERR("No matched server info");
		return ret;
	}

	/* Check server URI from security object */
	ret = http_parser_parse_url(obj->security_uri,
				    strlen(obj->security_uri),
				    0, &parser);
	if (ret != 0 || !(parser.field_set & (1 << UF_SCHEMA))) {
		SYS_LOG_ERR("Invalid server URI: %s",
			    obj->security_uri);
		return ret;
	}

	strncpy(uri, obj->security_uri, SECURITY_URI_LEN);

	/* TODO: enable coaps when DTLS is ready */
	off = parser.field_data[UF_SCHEMA].off;
	len = parser.field_data[UF_SCHEMA].len;
	if (len != 4 || memcmp(uri+off, "coap", 4)) {
		SYS_LOG_ERR("Unsupported schema");
		return -EINVAL;
	}

	if (!(parser.field_set & (1 << UF_PORT))) {
		/* Set to default port of CoAP */
		parser.port = 5683;
	}

	off = parser.field_data[UF_HOST].off;
	len = parser.field_data[UF_HOST].len;
	uri[off+len] = '\0';

	SYS_LOG_DBG("Connect to %s:%d", uri+off, parser.port);

	ret = net_app_init_udp_client(&clients[index].ctx, NULL, NULL,
				      uri+off, parser.port,
				      WAIT_TIME, NULL);
	if (ret < 0) {
		SYS_LOG_ERR("Cannot init UDP client (%d)", ret);
		return ret;
	}

#if defined(CONFIG_NET_CONTEXT_NET_PKT_POOL)
	net_app_set_net_pkt_pool(&clients[index].ctx, lwm2m_tx_udp_slab,
				 lwm2m_data_udp_pool);
#endif

	/* Setup LWM2M engine for callbacks */
	ret = lwm2m_engine_start(&clients[index].ctx);
	if (ret < 0) {
		SYS_LOG_ERR("Cannot init LWM2M engine (%d)", ret);
		goto cleanup;
	}

#if defined(CONFIG_NET_APP_DTLS)
	ret = net_app_client_tls(&clients[index].ctx,
				 dtls_result_ipv4,
				 sizeof(dtls_result_ipv4),
				 INSTANCE_INFO,
				 strlen(INSTANCE_INFO),
				 setup_cert,
				 HOSTNAME,
				 NULL,
				 &dtls_pool,
				 net_app_dtls_stack_ipv4,
				 K_THREAD_STACK_SIZEOF(
					 net_app_dtls_stack_ipv4));
	if (ret < 0) {
		SYS_LOG_ERR("Cannot init DTLS: %d", ret);
		goto cleanup;
	}
#endif

	ret = net_app_connect(&clients[index].ctx, CONNECT_TIME);
	if (ret < 0) {
		SYS_LOG_ERR("Cannot connect UDP (%d", ret);
		goto cleanup;
	}

	return 0;

cleanup:
	disconnect_udp(&clients[index].ctx);

	return ret;
}

/* force re-update with remote peer(s) */
void engine_trigger_update(void)
{
	int index;

	for (index = 0; index < client_count; index++) {
		/* TODO: add locking? */
		clients[index].trigger_update = 1;
	}
}

/* state machine reply callbacks */
static int do_bootstrap_reply_cb(const struct zoap_packet *response,
				 struct zoap_reply *reply,
				 const struct sockaddr *from)
{
	u8_t code;
	int index;

	code = zoap_header_get_code(response);
	SYS_LOG_DBG("Bootstrap callback (code:%u.%u)",
		    ZOAP_RESPONSE_CODE_CLASS(code),
		    ZOAP_RESPONSE_CODE_DETAIL(code));

	index = find_clients_index(from, true);
	if (index < 0) {
		SYS_LOG_ERR("Bootstrap client index not found.");
		return 0;
	}

	/*
	 * Expecting code == ZOAP_RESPONSE_CODE_CHANGED to kickoff
	 * bootstrap process. Bootstrap is done when server call /bs
	 */
	if (code == ZOAP_RESPONSE_CODE_CHANGED) {
		SYS_LOG_DBG("Kicking off bootstrap process");
	} else if (code == ZOAP_RESPONSE_CODE_NOT_FOUND) {
		SYS_LOG_ERR("Failed: NOT_FOUND.  Not Retrying.");
		set_sm_state(index, ENGINE_DO_REGISTRATION);
	} else {
		/* TODO: Read payload for error message? */
		SYS_LOG_ERR("Failed with code %u.%u. Retrying ...",
			    ZOAP_RESPONSE_CODE_CLASS(code),
			    ZOAP_RESPONSE_CODE_DETAIL(code));
		set_sm_state(index, ENGINE_INIT);
		disconnect_udp(&clients[index].ctx);
	}

	return 0;
}

static int do_registration_reply_cb(const struct zoap_packet *response,
				    struct zoap_reply *reply,
				    const struct sockaddr *from)
{
	struct zoap_option options[2];
	u8_t code;
	int ret, index;

	code = zoap_header_get_code(response);
	SYS_LOG_DBG("Registration callback (code:%u.%u)",
		    ZOAP_RESPONSE_CODE_CLASS(code),
		    ZOAP_RESPONSE_CODE_DETAIL(code));

	index = find_clients_index(from, false);
	if (index < 0) {
		SYS_LOG_ERR("Registration client index not found.");
		return 0;
	}

	/* check state and possibly set registration to done */
	if (code == ZOAP_RESPONSE_CODE_CREATED) {
		ret = zoap_find_options(response, ZOAP_OPTION_LOCATION_PATH,
					options, 2);
		if (ret < 0) {
			return ret;
		}

		if (ret < 2) {
			SYS_LOG_ERR("Unexpected endpoint data returned.");
			return -EINVAL;
		}

		/* option[0] should be "rd" */

		if (options[1].len + 1 > sizeof(clients[index].server_ep)) {
			SYS_LOG_ERR("Unexpected length of query: "
				    "%u (expected %zu)\n",
				    options[1].len,
				    sizeof(clients[index].server_ep));
			return -EINVAL;
		}

		memcpy(clients[index].server_ep, options[1].value,
		       options[1].len);
		clients[index].server_ep[options[1].len] = '\0';
		set_sm_state(index, ENGINE_REGISTRATION_DONE);
		clients[index].registered = 1;
		SYS_LOG_INF("Registration Done (EP='%s')",
			    clients[index].server_ep);

		return 0;
	} else if (code == ZOAP_RESPONSE_CODE_NOT_FOUND) {
		SYS_LOG_ERR("Failed: NOT_FOUND.  Not Retrying.");
		set_sm_state(index, ENGINE_REGISTRATION_DONE);
		return 0;
	}

	/* TODO: Read payload for error message? */
	/* Possible error response codes: 4.00 Bad request & 4.03 Forbidden */
	SYS_LOG_ERR("failed with code %u.%u. Re-init network",
		    ZOAP_RESPONSE_CODE_CLASS(code),
		    ZOAP_RESPONSE_CODE_DETAIL(code));

	disconnect_udp(&clients[index].ctx);

	set_sm_state(index, ENGINE_INIT);
	return 0;
}

static int do_update_reply_cb(const struct zoap_packet *response,
			      struct zoap_reply *reply,
			      const struct sockaddr *from)
{
	u8_t code;
	int index;

	code = zoap_header_get_code(response);
	SYS_LOG_DBG("Update callback (code:%u.%u)",
		    ZOAP_RESPONSE_CODE_CLASS(code),
		    ZOAP_RESPONSE_CODE_DETAIL(code));

	index = find_clients_index(from, false);
	if (index < 0) {
		SYS_LOG_ERR("Registration client index not found.");
		return 0;
	}

	/* If NOT_FOUND just continue on */
	if ((code == ZOAP_RESPONSE_CODE_CHANGED) ||
	    (code == ZOAP_RESPONSE_CODE_CREATED)) {
		set_sm_state(index, ENGINE_REGISTRATION_DONE);
		SYS_LOG_DBG("Update Done");
		return 0;
	}

	/* TODO: Read payload for error message? */
	/* Possible error response codes: 4.00 Bad request & 4.04 Not Found */
	SYS_LOG_ERR("Failed with code %u.%u. Retrying registration",
		    ZOAP_RESPONSE_CODE_CLASS(code),
		    ZOAP_RESPONSE_CODE_DETAIL(code));
	clients[index].registered = 0;
	set_sm_state(index, ENGINE_DO_REGISTRATION);

	disconnect_udp(&clients[index].ctx);

	return 0;
}

static int do_deregister_reply_cb(const struct zoap_packet *response,
				  struct zoap_reply *reply,
				  const struct sockaddr *from)
{
	u8_t code;
	int index;

	code = zoap_header_get_code(response);
	SYS_LOG_DBG("Deregister callback (code:%u.%u)",
		    ZOAP_RESPONSE_CODE_CLASS(code),
		    ZOAP_RESPONSE_CODE_DETAIL(code));

	index = find_clients_index(from, false);
	if (index < 0) {
		SYS_LOG_ERR("Registration clients index not found.");
		return 0;
	}

	if (code == ZOAP_RESPONSE_CODE_DELETED) {
		clients[index].registered = 0;
		SYS_LOG_DBG("Deregistration success");
		set_sm_state(index, ENGINE_DEREGISTERED);

	} else {
		SYS_LOG_ERR("failed with code %u.%u",
			    ZOAP_RESPONSE_CODE_CLASS(code),
			    ZOAP_RESPONSE_CODE_DETAIL(code));
		if (get_sm_state(index) == ENGINE_DEREGISTER_SENT) {
			set_sm_state(index, ENGINE_DEREGISTER_FAILED);
		}
	}

	return 0;
}

/* state machine step functions */

static int sm_do_init(int index)
{
	SYS_LOG_DBG("RD Client started with endpoint "
		    "'%s' and client lifetime %d",
		    clients[index].ep_name,
		    clients[index].lifetime);
	clients[index].registered = 0;
	clients[index].bootstrapped = 0;
	clients[index].trigger_update = 0;
	if (clients[index].lifetime == 0) {
		clients[index].lifetime = CONFIG_LWM2M_ENGINE_DEFAULT_LIFETIME;
	}
	/* Do bootstrap or registration */
	if (clients[index].use_bootstrap) {
		set_sm_state(index, ENGINE_DO_BOOTSTRAP);
	} else {
		set_sm_state(index, ENGINE_DO_REGISTRATION);
	}

	return 0;
}

static int sm_do_bootstrap(int index)
{
	struct zoap_packet request;
	struct net_pkt *pkt = NULL;
	struct zoap_pending *pending = NULL;
	struct zoap_reply *reply = NULL;
	int ret = 0;

	if (clients[index].use_bootstrap &&
	    clients[index].bootstrapped == 0 &&
	    clients[index].has_bs_server_info) {
		ret = connect_udp(index, true);
		if (ret < 0) {
			SYS_LOG_ERR("Cannot connect to bs sever: %d", ret);
			return ret;
		}

		/* Copy sockaddr to bs_server for later use */
		memcpy(&clients[index].bs_server,
		       &clients[index].ctx.default_ctx->remote,
		       sizeof(struct sockaddr));

		ret = lwm2m_init_message(&clients[index].ctx,
					 &request, &pkt, ZOAP_TYPE_CON,
					 ZOAP_METHOD_POST, 0, NULL, 0);
		if (ret) {
			goto cleanup;
		}

		zoap_add_option(&request, ZOAP_OPTION_URI_PATH,
				"bs", strlen("bs"));

		snprintf(query_buffer, sizeof(query_buffer) - 1,
			 "ep=%s", clients[index].ep_name);
		zoap_add_option(&request, ZOAP_OPTION_URI_QUERY,
				query_buffer, strlen(query_buffer));

		pending = lwm2m_init_message_pending(&request,
						     &clients[index].bs_server,
						     pendings, NUM_PENDINGS);
		if (!pending) {
			ret = -ENOMEM;
			goto cleanup;
		}

		reply = zoap_reply_next_unused(replies, NUM_REPLIES);
		if (!reply) {
			SYS_LOG_ERR("No resources for waiting for replies.");
			ret = -ENOMEM;
			goto cleanup;
		}

		zoap_reply_init(reply, &request);
		reply->reply = do_bootstrap_reply_cb;

		/* log the bootstrap attempt */
		SYS_LOG_DBG("Register ID with bootstrap server [%s] as '%s'",
			    lwm2m_sprint_ip_addr(&clients[index].bs_server),
			    query_buffer);

		ret = net_app_send_pkt(&clients[index].ctx, pkt,
				       &clients[index].bs_server,
				       NET_SOCKADDR_MAX_SIZE, K_NO_WAIT, NULL);
		if (ret < 0) {
			SYS_LOG_ERR("Error sending LWM2M packet (err:%d).",
				    ret);
			goto cleanup;
		}

		zoap_pending_cycle(pending);
		k_delayed_work_submit(&retransmit_work, pending->timeout);
		set_sm_state(index, ENGINE_BOOTSTRAP_SENT);
	}
	return ret;

cleanup:
	lwm2m_init_message_cleanup(pkt, pending, reply);
	disconnect_udp(&clients[index].ctx);

	return ret;
}

static int sm_bootstrap_done(int index)
{

	/* check that we should still use bootstrap */
	if (clients[index].use_bootstrap) {
#ifdef CONFIG_LWM2M_SECURITY_OBJ_SUPPORT
		int ret;
		struct security_object *obj;

		/* TODO: iterate through all available server? */

		/* Get first available registration server info */
		ret = get_security_obj(0, false, &obj);
		if (ret < 0) {
			SYS_LOG_ERR("No registration server info available");
			set_sm_state(index, ENGINE_INIT);
			/* close connection */
			disconnect_udp(&clients[index].ctx);
			return ret;
		}

		clients[index].has_registration_info = 1;
		clients[index].use_registration = 1;
		clients[index].registered = 0;
		clients[index].bootstrapped++;
		clients[index].ssid = obj->short_server_id;

		/* close connection to the bootstrap server */
		disconnect_udp(&clients[index].ctx);
#endif
		set_sm_state(index, ENGINE_DO_REGISTRATION);
	}

	return 0;
}

static int sm_send_registration(int index, bool send_obj_support_data,
				zoap_reply_t reply_cb)
{
	struct zoap_packet request;
	struct net_pkt *pkt = NULL;
	struct zoap_pending *pending = NULL;
	struct zoap_reply *reply = NULL;
	u8_t *payload;
	u16_t client_data_len, len;
	int ret = 0;

	/* remember the last reg time */
	clients[index].last_update = k_uptime_get();
	ret = lwm2m_init_message(&clients[index].ctx,
				 &request, &pkt, ZOAP_TYPE_CON,
				 ZOAP_METHOD_POST, 0, NULL, 0);
	if (ret) {
		goto cleanup;
	}

	zoap_add_option(&request, ZOAP_OPTION_URI_PATH,
			LWM2M_RD_CLIENT_URI,
			strlen(LWM2M_RD_CLIENT_URI));

	if (!clients[index].registered) {
		/* include client endpoint in URI QUERY on 1st registration */
		zoap_add_option_int(&request, ZOAP_OPTION_CONTENT_FORMAT,
				    LWM2M_FORMAT_APP_LINK_FORMAT);
		snprintf(query_buffer, sizeof(query_buffer) - 1,
			 "lwm2m=%s", LWM2M_PROTOCOL_VERSION);
		zoap_add_option(&request, ZOAP_OPTION_URI_QUERY,
				query_buffer, strlen(query_buffer));
		snprintf(query_buffer, sizeof(query_buffer) - 1,
			 "ep=%s", clients[index].ep_name);
		zoap_add_option(&request, ZOAP_OPTION_URI_QUERY,
				query_buffer, strlen(query_buffer));
	} else {
		/* include server endpoint in URI PATH otherwise */
		zoap_add_option(&request, ZOAP_OPTION_URI_PATH,
				clients[index].server_ep,
				strlen(clients[index].server_ep));
	}

	snprintf(query_buffer, sizeof(query_buffer) - 1,
		 "lt=%d", clients[index].lifetime);
	zoap_add_option(&request, ZOAP_OPTION_URI_QUERY,
			query_buffer, strlen(query_buffer));
	/* TODO: add supported binding query string */

	if (send_obj_support_data) {
		/* generate the rd data */
		client_data_len = lwm2m_get_rd_data(client_data,
							   sizeof(client_data));
		payload = zoap_packet_get_payload(&request, &len);
		if (!payload) {
			ret = -EINVAL;
			goto cleanup;
		}

		memcpy(payload, client_data, client_data_len);
		ret = zoap_packet_set_used(&request, client_data_len);
		if (ret) {
			goto cleanup;
		}
	}

	pending = lwm2m_init_message_pending(&request,
					     &clients[index].reg_server,
					     pendings, NUM_PENDINGS);
	if (!pending) {
		ret = -ENOMEM;
		goto cleanup;
	}

	reply = zoap_reply_next_unused(replies, NUM_REPLIES);
	if (!reply) {
		SYS_LOG_ERR("No resources for waiting for replies.");
		ret = -ENOMEM;
		goto cleanup;
	}

	zoap_reply_init(reply, &request);
	reply->reply = reply_cb;

	/* log the registration attempt */
	SYS_LOG_DBG("registration sent [%s]",
		    lwm2m_sprint_ip_addr(&clients[index].reg_server));

	ret = net_app_send_pkt(&clients[index].ctx, pkt,
			       &clients[index].reg_server,
			       NET_SOCKADDR_MAX_SIZE, K_NO_WAIT, NULL);
	if (ret < 0) {
		SYS_LOG_ERR("Error sending LWM2M packet (err:%d).",
			    ret);
		goto cleanup;
	}

	zoap_pending_cycle(pending);
	k_delayed_work_submit(&retransmit_work, pending->timeout);
	return ret;

cleanup:
	lwm2m_init_message_cleanup(pkt, pending, reply);
	return ret;
}

static int sm_do_registration(int index)
{
	int ret;

	if (clients[index].use_registration &&
	    !clients[index].registered &&
	    clients[index].has_registration_info) {
		ret = connect_udp(index, false);
		if (ret < 0) {
			SYS_LOG_ERR("Error when connect to reg sever: %d",
				    ret);
			return ret;
		}

		/* Copy sockaddr to reg_server for later use */
		memcpy(&clients[index].reg_server,
		       &clients[index].ctx.default_ctx->remote,
		       sizeof(struct sockaddr));

		ret = sm_send_registration(index, true,
					   do_registration_reply_cb);
		if (!ret) {
			set_sm_state(index, ENGINE_REGISTRATION_SENT);
		} else {
			SYS_LOG_ERR("Registration err: %d", ret);
			goto cleanup;
		}
	}

	return 0;

cleanup:
	disconnect_udp(&clients[index].ctx);

	return ret;
}

static int sm_registration_done(int index)
{
	int ret = 0;
	bool forced_update;

	/* check for lifetime seconds - 1 so that we can update early */
	if (clients[index].registered &&
	    (clients[index].trigger_update ||
	     ((clients[index].lifetime - SECONDS_TO_UPDATE_EARLY) <=
	      (k_uptime_get() - clients[index].last_update) / 1000))) {
		forced_update = clients[index].trigger_update;
		clients[index].trigger_update = 0;
		ret = sm_send_registration(index, forced_update,
					   do_update_reply_cb);
		if (!ret) {
			set_sm_state(index, ENGINE_UPDATE_SENT);
		} else {
			SYS_LOG_ERR("Registration update err: %d", ret);
		}
	}

	return ret;
}

static int sm_do_deregister(int index)
{

	struct zoap_packet request;
	struct net_pkt *pkt = NULL;
	struct zoap_pending *pending = NULL;
	struct zoap_reply *reply = NULL;
	int ret;

	ret = lwm2m_init_message(&clients[index].ctx,
				 &request, &pkt, ZOAP_TYPE_CON,
				 ZOAP_METHOD_DELETE, 0, NULL, 0);
	if (ret) {
		goto cleanup;
	}

	zoap_add_option(&request, ZOAP_OPTION_URI_PATH,
			clients[index].server_ep,
			strlen(clients[index].server_ep));

	pending = lwm2m_init_message_pending(&request,
					     &clients[index].reg_server,
					     pendings, NUM_PENDINGS);
	if (!pending) {
		ret = -ENOMEM;
		goto cleanup;
	}

	reply = zoap_reply_next_unused(replies, NUM_REPLIES);
	if (!reply) {
		SYS_LOG_ERR("No resources for waiting for replies.");
		ret = -ENOMEM;
		goto cleanup;
	}

	zoap_reply_init(reply, &request);
	reply->reply = do_deregister_reply_cb;

	SYS_LOG_INF("Deregister from '%s'", clients[index].server_ep);

	ret = net_app_send_pkt(&clients[index].ctx, pkt,
			       &clients[index].reg_server,
			       NET_SOCKADDR_MAX_SIZE, K_NO_WAIT, NULL);
	if (ret < 0) {
		SYS_LOG_ERR("Error sending LWM2M packet (err:%d).",
			    ret);
		goto cleanup;
	}

	zoap_pending_cycle(pending);
	k_delayed_work_submit(&retransmit_work, pending->timeout);
	set_sm_state(index, ENGINE_DEREGISTER_SENT);
	return ret;

cleanup:
	lwm2m_init_message_cleanup(pkt, pending, reply);
	return ret;
}

static void lwm2m_rd_client_service(void)
{
	int index;

	while (true) {
		for (index = 0; index < client_count; index++) {
			switch (get_sm_state(index)) {

			case ENGINE_INIT:
				sm_do_init(index);
				break;

			case ENGINE_DO_BOOTSTRAP:
				sm_do_bootstrap(index);
				break;

			case ENGINE_BOOTSTRAP_SENT:
				/* wait for bootstrap to be done */
				break;

			case ENGINE_BOOTSTRAP_DONE:
				sm_bootstrap_done(index);
				break;

			case ENGINE_DO_REGISTRATION:
				sm_do_registration(index);
				break;

			case ENGINE_REGISTRATION_SENT:
				/* wait registration to be done */
				break;

			case ENGINE_REGISTRATION_DONE:
				sm_registration_done(index);
				break;

			case ENGINE_UPDATE_SENT:
				/* wait update to be done */
				break;

			case ENGINE_DEREGISTER:
				sm_do_deregister(index);
				break;

			case ENGINE_DEREGISTER_SENT:
				break;

			case ENGINE_DEREGISTER_FAILED:
				set_sm_state(index, ENGINE_DEREGISTERED);
				break;

			case ENGINE_DEREGISTERED:
				disconnect_udp(&clients[index].ctx);
				break;

			default:
				SYS_LOG_ERR("Unhandled state: %d",
					    get_sm_state(index));

			}

			k_yield();
		}

		/*
		 * TODO: calculate the diff between the start of the loop
		 * and subtract that from the update interval
		 */
		k_sleep(K_MSEC(STATE_MACHINE_UPDATE_INTERVAL));
	}
}

int lwm2m_rd_client_start(const char *uri,
			  bool bootstrap,
			  const char *ep_name)
{
	int index;
	int ssid;

	SYS_LOG_ERR("URI = %s", uri);

	if (client_count + 1 > CLIENT_INSTANCE_COUNT) {
		return -ENOMEM;
	}

	/* Setup lwm2m server uri for later use */
	ssid = put_security_obj(uri, bootstrap);
	if (ssid < 0) {
		SYS_LOG_ERR("Setup server fail: %d", ssid);
		return ssid;
	}

	index = client_count;
	client_count++;

	/* Base on input to setup reg or bs server */
	if (bootstrap) {
		clients[index].has_bs_server_info = 1;
		clients[index].use_bootstrap = 1;
	} else {
		clients[index].has_registration_info = 1;
		clients[index].use_registration = 1;
	}
	clients[index].ssid = (u16_t)ssid;

	set_sm_state(index, ENGINE_INIT);
	strncpy(clients[index].ep_name, ep_name, CLIENT_EP_LEN - 1);
	SYS_LOG_INF("LWM2M Client: %s", clients[index].ep_name);

	return 0;
}

static int lwm2m_rd_client_init(struct device *dev)
{
	k_thread_create(&lwm2m_rd_client_thread_data,
			&lwm2m_rd_client_thread_stack[0],
			K_THREAD_STACK_SIZEOF(lwm2m_rd_client_thread_stack),
			(k_thread_entry_t) lwm2m_rd_client_service,
			NULL, NULL, NULL, K_PRIO_COOP(7), 0, K_NO_WAIT);
	SYS_LOG_DBG("LWM2M RD client thread started");
	return 0;
}

SYS_INIT(lwm2m_rd_client_init, APPLICATION,
	 CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
