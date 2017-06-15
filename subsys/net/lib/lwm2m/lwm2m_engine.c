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
 * Original Authors:
 *         Joakim Eriksson <joakime@sics.se>
 *         Niclas Finne <nfi@sics.se>
 *         Joel Hoglund <joel@sics.se>
 */

/*
 * TODO:
 *
 * - Use server / security object instance 0 for initial connection
 * - Add DNS support for IPv4
 * - Block-transfer support / Large response messages
 *   (use Block2 to limit message size to 64 bytes for 6LOWPAN compat.)
 * - BOOTSTRAP cleanup
 * - Shrink / remove usage of lwm2m_engine_info
 * - Handle WRITE_ATTRIBUTES (pmin=10&pmax=60)
 *
 * Re-write LWM2M Engine API:
 *
 * - Resources are currently stored as struct obj_path (4 u16_t member vars).
 *   Nix that as a storage method and move to char *"#/#/#".  Then use an
 *   object registry to return object instances ("#/#/") and send the resource
 *   remainer to the object's operation callback.
 *
 * - Reorganize "Engine Context" as a list of "Transactions".  Every time a NEW
 *   request comes in via UDP, we use a new transaction to manage it's state --
 *   until it's DONE.  This could mean several messages back and forth
 *   (block transfer).  The same would be true for registration / bootstrap and
 *   observe notifications (anything coming from the client).  These get a new
 *   transaction to manage the data send/receive process till it's done.
 *
 * - Readers / Writers use data pipe type APIs with generic buffers underneath.
 *   The engine will assemble the data buffer back into the net_pkt or hand it
 *   off to the various LWM2M objects (Security, Server, Device etc).
 *   If the Reader / Writer needs more space they get it via generic Zephyr data
 *   buffer allocations.
 *
 * - LWM2M objects will establish themselves in the registry and provide
 *   individual callbacks:
 *   > WRITE (transaction, input pipe)
 *   > READ (transaction, resource id, output pipe)
 *   > EXECUTE (transaction)
 *   > CREATE (transaction) (where object allows more than 1)
 *   these callbacks can/will be used several times for 1 transaction
 *
 * - LWM2M objects will create meta data for their member resources
 *   to allow the engine to better pre-process the data buffer going into it:
 *   RESOURCE ID
 *   RESOURCE PERMISSION: RWX
 *   RESOURCE INSTANCE MAX(optional): 1 for normal, more for multi
 *   RESOURCE Friendly Name: "Manufacturer"
 *   RESOURCE DATA TYPE: String, Int32, Int64, Boolean, Opaque
 *   RESOURCE DATA MAX SIZE: (for string / opaque)
 *   RESOURCE DATA BUFFER POINTER(array for multi-instance)
 *   RESOURCE callbacks for custom application behavior:
 *     Read, Write, Execute
 *   Example for "Device"
 *   0,R,1,"Manufacturer",STRING,255, <pointer to data>
 *   1,R,1,"Model Number",STRING,255, <pointer to data>
 *   2,R,1,"Serial Number",STRING,255, <pointer to data>
 *   3,R,1,"Firmware Version",STRING,32, <pointer to data>
 *   4,X,1,"Reboot",,,,
 *   set_callback(3,0,4,X, <callback>)
 *   5,X,1,"Reset Default",,,,
 *   set_callback(3,0,5,X, <callback>)
 *
 * - LWM2M Engine will handle:
 *   > OBSERVE
 *   < NOTIFY
 *   > WRITE_ATTR (for notification purposes)
 *
 * - Zephyr App code will use a generic LWM2M engine get/set functions using
 *   the path "3/0/5" and PLAIN_TEXT data passed to set LWM2M resources:
 *   So "lwm2m_device_set_manufacturer(LWM2M_DEVICE_MANUFACTURER);" becomes
 *   "engine_set_string("3/0/0", LWM2M_DEVICE_MANUFACTURER);"
 *   The engine takes this function call:
 *   - Looks up the object "3/", object instance "0/" and sends the plain text
 *   data as a WRITE buffer to the object exactly like it would from external
 *   sources (except that a special flag is passed in):
 *   engine_set_int32(<resource uri>, data)
 *   engine_set_int64(<resource uri>, data)
 *   engine_set_string(<resource uri>, data)
 *   engine_set_bool(<resource uri>, data)
 *   NOTE: <resource uri> can include resource instance id "3/0/6/1"
 *   Example enabling "Internal Battery" for "Available Power" in a Device Object:
 *   engine_set_bool("3/0/6/1", true)
 */

#define SYS_LOG_DOMAIN "lib/lwm2m_engine"
#define SYS_LOG_LEVEL CONFIG_SYS_LOG_LWM2M_LEVEL
#include <logging/sys_log.h>

#include <zephyr/types.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <misc/printk.h>
#include <net/net_pkt.h>
#include <net/zoap.h>
#include <net/lwm2m.h>

#include "lwm2m_object.h"
#include "lwm2m_engine.h"
#ifdef CONFIG_LWM2M_SECURITY_OBJ_SUPPORT
#include "lwm2m_obj_security.h"
#endif
#include "lwm2m_rw_plain_text.h"
#ifdef CONFIG_LWM2M_RW_JSON_SUPPORT
#include "lwm2m_rw_json.h"
#endif
#ifdef CONFIG_LWM2M_RW_OMA_TLV_SUPPORT
#include "lwm2m_rw_oma_tlv.h"
#endif

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

#define LWM2M_PEER_PORT		CONFIG_LWM2M_PEER_PORT
#define LWM2M_BOOTSTRAP_PORT	CONFIG_LWM2M_BOOTSTRAP_PORT

/* MACROS for getting out resource ID from resource array ID + flags */
#define RSC_ID(x) (x & 0xffff)
#define RSC_READABLE(x) ((x & LWM2M_RESOURCE_READ) > 0)
#define RSC_WRITABLE(x) ((x & LWM2M_RESOURCE_WRITE) > 0)

/* writer modes */
#define MODE_NONE      0
#define MODE_INSTANCE  1
#define MODE_VALUE     2
#define MODE_READY     3

#define LWM2M_RD_CLIENT_URI "rd"

#define SECONDS_TO_UPDATE_EARLY	2
#define STATE_MACHINE_UPDATE_INTERVAL 500

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

struct lwm2m_engine_info {
	struct net_context *net_ctx;
	u16_t lifetime;
	struct zoap_observer bs_server_ep;
	struct zoap_observer server_ep;
	u8_t engine_state;
	u8_t use_bootstrap;
	u8_t has_bs_server_info;
	u8_t use_registration;
	u8_t has_registration_info;
	u8_t registered;
	u8_t bootstrapped; /* bootstrap done */
	u8_t trigger_update;

	s64_t last_update;

	char ep[32];
	char assigned_ep[32];
};

struct observe_node {
	sys_snode_t node;
	bool used;
	struct sockaddr addr;
	struct lwm2m_obj_path path;
	u8_t  token[8];
	u8_t  tkl;
	s64_t event_timestamp;
	s64_t last_timestamp;
	u32_t min_period_sec;
	u32_t max_period_sec;
	u32_t counter;
};

#define LWM2M_STACK_SIZE CONFIG_LWM2M_ENGINE_STACK_SIZE
char lwm2m_thread_stack[LWM2M_STACK_SIZE];
struct k_thread lwm2m_thread_data;

/* buffers */
static char query_buffer[64]; /* allocate some data for queries and updates */
static u8_t client_data[128]; /* allocate some data for the RD */

#define NUM_PENDINGS	CONFIG_LWM2M_ENGINE_MAX_PENDING
#define NUM_REPLIES	CONFIG_LWM2M_ENGINE_MAX_REPLIES
static struct zoap_pending pendings[NUM_PENDINGS];
static struct zoap_reply replies[NUM_REPLIES];
static struct k_delayed_work retransmit_work;
static struct lwm2m_engine_info engine_info;

static struct observe_node observe_node_data[CONFIG_LWM2M_ENGINE_MAX_OBSERVER];

static sys_slist_t engine_obj_list;
static sys_slist_t engine_observer_list;

/* periodic / notify / observe handling stack */
static char engine_thread_stack[CONFIG_LWM2M_ENGINE_STACK_SIZE];
static struct k_thread engine_thread_data;

/* for debugging: to print IP addresses */
static inline char *sprint_ip_addr(const struct sockaddr *addr)
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

/* state machine state management */

static void
set_sm_state(u8_t state)
{
	/* TODO: add locking? */
	engine_info.engine_state = state;
}

static u8_t
get_sm_state(void)
{
	/* TODO: add locking? */
	return engine_info.engine_state;
}

void
engine_trigger_update(void)
{
	/* TODO: add locking? */
	engine_info.trigger_update = 1;
}

/* list functions */

void
engine_add_object(struct lwm2m_engine_obj *obj)
{
	sys_slist_append(&engine_obj_list, &obj->node);
}

void
engine_remove_object(struct lwm2m_engine_obj *obj)
{
	sys_slist_remove(&engine_obj_list, NULL, &obj->node);
}

int
engine_notify_observer(u16_t obj_id, u16_t obj_inst_id, u16_t res_id)
{
	struct observe_node *check_obj;
	int ret = 0;

	/* look for observers which match our resource */
	SYS_SLIST_FOR_EACH_CONTAINER(&engine_observer_list, check_obj, node) {
		if (check_obj->path.obj_id == obj_id &&
		    check_obj->path.obj_inst_id == obj_inst_id &&
		    (check_obj->path.level < 3 ||
		     check_obj->path.res_id == res_id)) {
			/* update the event time for this observer */
			check_obj->event_timestamp = k_uptime_get();
			SYS_LOG_DBG("NOTIFY EVENT %u/%u/%u",
				    obj_id, obj_inst_id, res_id);
			ret++;
		}
	}

	return ret;
}

int
engine_notify_observer_path(struct lwm2m_obj_path *path)
{
	return engine_notify_observer(path->obj_id, path->obj_inst_id,
				      path->res_id);
}

static int
engine_add_observer(struct sockaddr *addr, const u8_t *token, u8_t tkl,
		    struct lwm2m_obj_path *path)
{
	struct observe_node *check_obj;
	int i;

	if (!addr) {
		SYS_LOG_ERR("sockaddr is required");
		return -EINVAL;
	}

	/* make sure this observer doesn't exist already */
	SYS_SLIST_FOR_EACH_CONTAINER(&engine_observer_list, check_obj, node) {
		if (memcmp(&check_obj->addr, addr, sizeof(addr)) == 0 &&
			memcmp(&check_obj->path, path, sizeof(*path)) == 0) {
			/* quietly update the token information */
			memcpy(check_obj->token, token, tkl);
			check_obj->tkl = tkl;
			SYS_LOG_DBG("OBSERVER DUPLICATE %u/%u/%u(%u) [%s]",
				    path->obj_id, path->obj_inst_id,
				    path->res_id, path->level,
				    sprint_ip_addr(addr));
			return 0;
		}
	}

	/* find an unused observer index node */
	for (i = 0; i < CONFIG_LWM2M_ENGINE_MAX_OBSERVER; i++) {
		if (!observe_node_data[i].used) {
			break;
		}
	}

	/* couldn't find an index */
	if (i == CONFIG_LWM2M_ENGINE_MAX_OBSERVER) {
		return -ENOMEM;
	}

	/* copy the values and add it to the list */
	observe_node_data[i].used = true;
	memcpy(&observe_node_data[i].addr, addr, sizeof(*addr));
	memcpy(&observe_node_data[i].path, path, sizeof(*path));
	memcpy(observe_node_data[i].token, token, tkl);
	observe_node_data[i].tkl = tkl;
	observe_node_data[i].last_timestamp = k_uptime_get();
	observe_node_data[i].event_timestamp =
			observe_node_data[i].last_timestamp;
	/* TODO: use server object instance values */
	observe_node_data[i].min_period_sec = 10;
	observe_node_data[i].max_period_sec = 60;
	observe_node_data[i].counter = 1;
	sys_slist_append(&engine_observer_list,
			 &observe_node_data[i].node);
	SYS_LOG_DBG("OBSERVER ADDED %u/%u/%u(%u) token:'%s' addr:%s",
		    path->obj_id, path->obj_inst_id, path->res_id, path->level,
		    sprint_token(token, tkl), sprint_ip_addr(addr));
	return 0;
}

static int
engine_remove_observer(const u8_t *token, u8_t tkl)
{
	struct observe_node *check_obj, *found_obj = NULL;

	if (!token || tkl == 0) {
		SYS_LOG_ERR("token(%p) and token length(%u) must be valid.",
			    token, tkl);
		return -EINVAL;
	}

	/* find the node index */
	SYS_SLIST_FOR_EACH_CONTAINER(&engine_observer_list, check_obj, node) {
		if (memcmp(check_obj->token, token, tkl) == 0) {
			found_obj = check_obj;
			break;
		}
	}

	if (!found_obj) {
		return -ENOENT;
	}

	sys_slist_remove(&engine_observer_list, NULL, &found_obj->node);
	SYS_LOG_DBG("oberver '%s' removed", sprint_token(token, tkl));
	return 0;
}

static struct lwm2m_engine_obj *
get_engine_obj(int obj_id, int obj_inst_id, int level)
{
	struct lwm2m_engine_obj *check_obj;

	SYS_SLIST_FOR_EACH_CONTAINER(&engine_obj_list, check_obj, node) {
		if (check_obj->obj_id == obj_id &&
		    (level < 2 || check_obj->obj_inst_id == obj_inst_id)) {
			return check_obj;
		}
	}

	return NULL;
}

static struct lwm2m_engine_obj *
next_engine_obj(struct lwm2m_engine_obj *last,
		int obj_id, int obj_inst_id, int level)
{
	while (last) {
		last = SYS_SLIST_PEEK_NEXT_CONTAINER(last, node);
		if (last && last->obj_id == obj_id &&
		    (level < 2 || last->obj_inst_id == obj_inst_id)) {
			return last;
		}
	}

	return NULL;
}

/* utility functions */

static void
engine_clear_context(struct lwm2m_engine_context *context)
{
	if (context->in) {
		memset(context->in, 0, sizeof(struct lwm2m_input_context));
	}

	if (context->out) {
		memset(context->out, 0, sizeof(struct lwm2m_output_context));
	}

	if (context->path) {
		memset(context->path, 0, sizeof(struct lwm2m_obj_path));
	}
	context->operation = 0;
}

static u16_t
atou16(u8_t *buf, u16_t buflen, u16_t *len)
{
	u16_t val = 0;
	u16_t pos = 0;
	char c = 0;

	/* we should get a value first - consume all numbers */
	while (pos < buflen && (c = buf[pos]) >= '0' && c <= '9') {
		val = val * 10 + (c - '0');
		pos++;
	}

	*len = pos;
	return val;
}

static int
zoap_init_message(struct zoap_packet *zpkt, struct net_pkt **pkt, u8_t type,
		  u8_t code, u16_t mid, const u8_t *token, u8_t tkl,
		  zoap_reply_t reply_cb)
{
	struct net_buf *frag;
	struct zoap_reply *reply = NULL;
	int r;

	*pkt = net_pkt_get_tx(engine_info.net_ctx, K_FOREVER);
	if (!*pkt) {
		SYS_LOG_ERR("Unable to get TX packet, not enough memory.");
		return -ENOMEM;
	}

	frag = net_pkt_get_data(engine_info.net_ctx, K_FOREVER);
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

	/* tkl == 0 is for a new TOKEN, tkl == -1 means dont set */
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

static int
endpoint_is_connected(const struct zoap_observer *ep)
{
#if defined(CONFIG_LWM2M_WITH_DTLS)
	dtls_peer_t *peer;

	if (ep->secure) {
		peer = dtls_get_peer(dtls_context, ep);
		if (peer) {
			/* only if handshake is done! */
			return dtls_peer_is_connected(peer);
		}

		return 0;
	}
#endif /* CONFIG_LWM2M_WITH_DTLS */
	/* Assume that the UDP socket is already up... */
	return 1;
}

static struct lwm2m_engine_obj *
create_engine_obj(struct lwm2m_engine_obj *obj,
		  struct lwm2m_engine_context *context)
{
	enum lwm2m_status status;

	SYS_LOG_DBG("CREATE OP on object %d", obj->obj_id);
	context->operation = LWM2M_OP_CREATE;
	status = obj->op_callback(obj, context);
	if (status == LWM2M_STATUS_OK) {
		SYS_LOG_DBG("Created obj instance: %d",
			    obj->obj_inst_id);
		obj = get_engine_obj(obj->obj_id, obj->obj_inst_id,
				     context->path->level);
		context->operation = LWM2M_OP_WRITE;
		zoap_header_set_code(context->in->in_zpkt,
				     ZOAP_RESPONSE_CODE_CREATED);
		engine_trigger_update();
		return obj;
	}

	return NULL;
}

static enum lwm2m_content_format
lwm2m_engine_select_writer(struct lwm2m_output_context *out,
			   enum lwm2m_content_format accept)
{
	switch (accept) {

	case PLAIN_TEXT:
	case LWM2M_TEXT_PLAIN:
		out->writer = &plain_text_writer;
		break;

#ifdef CONFIG_LWM2M_RW_JSON_SUPPORT
	case LWM2M_JSON:
	case LWM2M_OLD_JSON:
		out->writer = &json_writer;
		break;
#endif

#ifdef CONFIG_LWM2M_RW_OMA_TLV_SUPPORT
	case LWM2M_TLV:
	case LWM2M_OLD_TLV:
		out->writer = &oma_tlv_writer;
		break;
#endif

	default:
		SYS_LOG_ERR("Unknown Accept type %u, using LWM2M plain text",
			    accept);
		out->writer = &plain_text_writer;
		accept = LWM2M_TEXT_PLAIN;
		break;

	}

	return accept;
}

static enum lwm2m_content_format
lwm2m_engine_select_reader(struct lwm2m_input_context *in,
			   enum lwm2m_content_format format)
{
	switch (format) {

	case LWM2M_TEXT_PLAIN:
		in->reader = &plain_text_reader;
		break;

#ifdef CONFIG_LWM2M_RW_OMA_TLV_SUPPORT
	case LWM2M_TLV:
	case LWM2M_OLD_TLV:
		in->reader = &oma_tlv_reader;
		break;
#endif

	default:
		SYS_LOG_ERR("Unknown content type %u, using LWM2M plain text",
			    format);
		in->reader = &plain_text_reader;
		format = LWM2M_TEXT_PLAIN;
		break;

	}

	return format;
}

static enum lwm2m_status
multi_read_op_process(struct lwm2m_engine_obj *obj,
		      struct lwm2m_engine_context *context,
		      int *pos, u8_t *num_read,
		      u8_t *initialized)
{
	struct lwm2m_output_context *out = context->out;
	struct lwm2m_obj_path *path = context->path;
	int len = 0;
	enum lwm2m_status success;
	u8_t lv;
	const u32_t obj_rsc_id = obj->rsc_ids[out->last_rpos];

	if (path->level < 3 ||
	    path->res_id == RSC_ID(obj_rsc_id)) {
		/* Do not allow a read on a non-readable */
		if (path->level == 3 &&
		    !RSC_READABLE(obj_rsc_id)) {
			return LWM2M_STATUS_OP_NOT_ALLOWED;
		}

		/* Set the resource ID is ctx->level < 3 */
		if (path->level < 3) {
			path->res_id = RSC_ID(obj_rsc_id);
		}

		if (path->level < 2) {
			path->obj_inst_id = obj->obj_inst_id;
		}

		if (RSC_READABLE(obj_rsc_id)) {
			lv = path->level;
			path->level = 3;
			if (!*initialized) {
				/*
				 * Due to the way ZoAP API needs to
				 * write the net_pkt buffer in the
				 * correct order, we need to make sure
				 * out->outbuf has been initialized
				 * here.  For example all of the LWM2M
				 * OPTION data must be added to the
				 * buffer prior to the payload marker.
				 */
				if (!out->outbuf) {
					out->outbuf =
					zoap_packet_get_payload(
						out->out_zpkt,
						&out->outsize);
				}

				len = engine_write_begin(out, path);
				SYS_LOG_DBG("INIT WRITE len:%d", len);
				*initialized = 1;
			}

			success = obj->op_callback(obj, context);
			path->level = lv;
			if (success != LWM2M_STATUS_OK) {
				/* What to do here? */
				SYS_LOG_ERR("OP callback failed: %d",
					    success);
				return success;
			}

			*num_read += 1;
			SYS_LOG_DBG("Called %u/%u/%u outlen:%u ok:%u",
				    path->obj_id,
				    path->obj_inst_id,
				    path->res_id,
				    out->outlen, success);
			*pos = out->outlen;
		}
	}

	out->last_rpos++;
	return LWM2M_STATUS_OK;
}

/* Multi read will handle read of JSON / TLV or Discovery (Link Format) */
static enum lwm2m_status
multi_read_op(struct lwm2m_engine_obj *obj,
	      struct lwm2m_engine_context *context)
{
	struct lwm2m_output_context *out = context->out;
	struct lwm2m_obj_path *path = context->path;
	int pos = 0;
	u8_t num_read = 0;
	u8_t initialized; /* used for commas, etc */

	out->last_rpos = 0;
	SYS_LOG_DBG("path:%u/%u/%u(%u)", path->obj_id, path->obj_inst_id,
		    path->res_id, path->level);

	while (obj) {
		initialized = 0;
		if (obj->rsc_ids && obj->rsc_count > 0) {
			/* show all the available resources (or read all) */
			while (out->last_rpos < obj->rsc_count) {
				if (multi_read_op_process(obj, context, &pos,
							  &num_read,
							  &initialized) > 0) {
					/* stop if reading a single item */
					if (path->level == 3) {
						break;
					}

					out->last_rpos++;
				}
			}
		}

		obj = next_engine_obj(obj, path->obj_id,
				      path->obj_inst_id,
				      path->level);
		SYS_LOG_DBG("END Writer");
		engine_write_end(out, path);
		pos = out->outlen;
		out->last_rpos = 0;
	}

	/* did not read anything even if we should have - on single item */
	if (num_read == 0 && path->level == 3) {
		return LWM2M_STATUS_NOT_FOUND;
	}

	out->outlen = pos;
	return LWM2M_STATUS_OK;
}

#if defined(CONFIG_LWM2M_RW_JSON_SUPPORT) || defined(CONFIG_LWM2M_RW_OMA_TLV_SUPPORT)
static int
check_write(struct lwm2m_engine_obj *obj, int res_id)
{
	int i;

	if (obj && obj->rsc_ids && obj->rsc_count > 0) {
		for (i = 0; i < obj->rsc_count; i++) {
			if (RSC_ID(obj->rsc_ids[i]) == res_id &&
			    RSC_WRITABLE(obj->rsc_ids[i])) {
				/* yes - writable */
				return 1;
			}
		}
	}

	return 0;
}

static struct lwm2m_engine_obj *
get_or_create_engine_obj(struct lwm2m_engine_context *context,
			 u16_t obj_inst_id2,
			 u8_t *created)
{
	struct lwm2m_engine_obj *obj;
	struct lwm2m_obj_path *path = context->path;

	obj = get_engine_obj(path->obj_id, path->obj_inst_id, path->level);
	SYS_LOG_DBG("object instance: %u/%u/%u(%u) = %p",
		    path->obj_id, path->obj_inst_id, path->res_id,
		    path->level, obj);

	/*
	 * by default we assume that the object instance is not created...
	 * so we set flag to zero
	 */
	if (created) {
		*created = 0;
	}

	if (!obj) {
		path->obj_inst_id = obj_inst_id2;
		path->level = 2;
		obj = create_engine_obj(obj, context);
		if (obj) {
			SYS_LOG_DBG("object instance %d created",
				    obj->obj_inst_id);
			/* set created flag to one */
			if (created) {
				*created = 1;
			}
		}
	}

	return obj;
}
#endif

#ifdef CONFIG_LWM2M_RW_OMA_TLV_SUPPORT
static enum lwm2m_status
multi_write_op_tlv_process(struct lwm2m_engine_context *context,
			   u8_t *data, int len)
{
	struct lwm2m_input_context *in = context->in;
	struct lwm2m_obj_path *path = context->path;
	struct lwm2m_engine_obj *obj;
	u8_t created = 0;

	in->inbuf = data;
	in->inpos = 0;
	in->insize = len;

	SYS_LOG_DBG("Doing OP callback to %u/%u/%u",
		    path->obj_id, path->obj_inst_id, path->res_id);
	obj = get_or_create_engine_obj(context, path->obj_inst_id, &created);
	if (obj && obj->op_callback) {
		if (created || check_write(obj, path->res_id)) {
			return obj->op_callback(obj, context);
		} else {
			return LWM2M_STATUS_OP_NOT_ALLOWED;
		}
	}

	return LWM2M_STATUS_ERROR;
}

static enum lwm2m_status
multi_write_op_tlv(struct lwm2m_engine_obj *obj,
		   struct lwm2m_engine_context *context)
{
	struct lwm2m_input_context *in = context->in;
	struct lwm2m_obj_path *path = context->path;
	size_t len;
	struct oma_tlv tlv;
	int tlvpos = 0;
	enum lwm2m_status status;

	while (tlvpos < in->insize) {
		len = oma_tlv_read(&tlv, &in->inbuf[tlvpos],
				   in->insize - tlvpos);

		SYS_LOG_DBG("Got TLV format First is: type:%d id:%d "
			    "len:%d (p:%d len:%d/%d)",
			    tlv.type, tlv.id, (int) tlv.length,
			    (int) tlvpos, (int) len, (int) in->insize);

		if (tlv.type == OMA_TLV_TYPE_OBJECT_INSTANCE) {
			struct oma_tlv tlv2;
			int len2;
			int pos = 0;

			path->obj_inst_id = tlv.id;
			if (tlv.length == 0) {
				/* Create only - no data */
				obj = create_engine_obj(obj, context);
				if (!obj) {
					return LWM2M_STATUS_ERROR;
				}
			}

			while (pos < tlv.length &&
			       (len2 = oma_tlv_read(&tlv2, &tlv.value[pos],
						    tlv.length - pos))) {
				SYS_LOG_DBG("   TLV type:%d id:%d "
					    "len:%d (len:%d/%d)\n",
					    tlv2.type, tlv2.id,
					    (int) tlv2.length,
					    (int) len2, (int) in->insize);

				if (tlv2.type == OMA_TLV_TYPE_RESOURCE) {
					path->res_id = tlv2.id;
					path->level = 3;
					status = multi_write_op_tlv_process(
							context,
							(u8_t *)&tlv.value[pos],
							len2);
					if (status != LWM2M_STATUS_OK) {
						return status;
					}
				}

				pos += len2;
			}
		} else if (tlv.type == OMA_TLV_TYPE_RESOURCE) {
			path->res_id = tlv.id;
			path->level = 3;
			status = multi_write_op_tlv_process(context,
							    &in->inbuf[tlvpos],
							    len);
			if (status != LWM2M_STATUS_OK) {
				return status;
			}

			zoap_header_set_code(context->out->out_zpkt,
					     ZOAP_RESPONSE_CODE_CHANGED);
		}

		tlvpos += len;
	}

	return LWM2M_STATUS_OK;
}
#endif

#ifdef CONFIG_LWM2M_RW_JSON_SUPPORT
static int
parse_path(const u8_t *strpath, u16_t strlen, struct lwm2m_obj_path *path)
{
	int ret = 0;
	int pos = 0;
	u16_t val;
	u8_t c = 0;

	do {
		val = 0;
		c = strpath[pos];
		/* we should get a value first - consume all numbers */
		while (pos < strlen && c >= '0' && c <= '9') {
			val = val * 10 + (c - '0');
			c = strpath[++pos];
		}

		/*
		 * Slash will mote thing forward
		 * and the end will be when pos == pl
		 */
		if (c == '/' || pos == strlen) {
			SYS_LOG_DBG("Setting %u = %u", ret, val);
			if (ret == 0) {
				path->obj_id = val;
			} else if (ret == 1) {
				path->obj_inst_id = val;
			} else if (ret == 2) {
				path->res_id = val;
			}

			ret++;
			pos++;
		} else {
			SYS_LOG_ERR("Error: illegal char '%c' at pos:%d",
				    c, pos);
			return -1;
		}
	} while (pos < strlen);

	return ret;
}

static enum lwm2m_status
multi_write_op_json(struct lwm2m_engine_obj *obj,
		    struct lwm2m_engine_context *context)
{
	struct lwm2m_input_context *in = context->in;
	struct lwm2m_obj_path *path = context->path;
	struct json_data json;
	u8_t olv = 0;
	u8_t *inbuf, created;
	int inpos, i;
	size_t insize;
	u8_t mode = MODE_NONE;

	olv    = path->level;
	inbuf  = in->inbuf;
	inpos  = in->inpos;
	insize = in->insize;

	while (json_next_token(in, &json)) {
		i = 0;
		created = 0;
		if (json.name[0] == 'n') {
			path->level = parse_path(json.value, json.value_len,
						 path);
			if (i > 0) {
				/* TODO: verify this function -- seems broken */
				obj = get_or_create_engine_obj(context,
							       path->obj_id,
							       &created);
				if (obj && obj->op_callback) {
					mode |= MODE_INSTANCE;
				} else {
					/* Failure... */
					return LWM2M_STATUS_ERROR;
				}
			}
		} else {
			/* HACK: assume value node: can it be anything else? */
			mode |= MODE_VALUE;
			/* update values */
			inbuf = in->inbuf;
			inpos = in->inpos;
			in->inbuf = json.value;
			in->inpos = 0;
			in->insize = json.value_len;
		}

		if (mode == MODE_READY) {
			/* allow write if just created - otherwise not */
			if (!created &&
			    !check_write(obj, path->res_id)) {
				return LWM2M_STATUS_OP_NOT_ALLOWED;
			}

			if (obj->op_callback(obj, context) != LWM2M_STATUS_OK) {
				/* TODO: what to do here? */
			}

			mode = MODE_NONE;
			in->inbuf = inbuf;
			in->inpos = inpos;
			in->insize = insize;
			path->level = olv;
		}
	}

	return LWM2M_STATUS_OK;
}
#endif

static enum lwm2m_status
multi_write_op(struct lwm2m_engine_obj *obj,
	       struct lwm2m_engine_context *context,
	       enum lwm2m_content_format format)
{
	u8_t created = 0;

	switch (format) {

	case PLAIN_TEXT:
	case LWM2M_TEXT_PLAIN:
		context->path->level = 3;
		context->in->inpos = 0;

		SYS_LOG_DBG("Doing OP callback to %u/%u/%u",
			    context->path->obj_id,
			    context->path->obj_inst_id,
			    context->path->res_id);
		obj = get_or_create_engine_obj(context,
					       context->path->obj_inst_id,
					       &created);
		if (obj && obj->op_callback) {
			if (created ||
			    check_write(obj, context->path->res_id)) {
				return obj->op_callback(obj, context);
			} else {
				return LWM2M_STATUS_OP_NOT_ALLOWED;
			}
		}

		return LWM2M_STATUS_OK;

#ifdef CONFIG_LWM2M_RW_JSON_SUPPORT
	case LWM2M_JSON:
	case LWM2M_OLD_JSON:
		return multi_write_op_json(obj, context);
#endif

#ifdef CONFIG_LWM2M_RW_OMA_TLV_SUPPORT
	case LWM2M_TLV:
	case LWM2M_OLD_TLV:
		return multi_write_op_tlv(obj, context);
#endif

	default:
		SYS_LOG_ERR("Unsupported format: %u", format);
		return LWM2M_STATUS_ERROR;

	}
}

static u16_t
lwm2m_engine_get_rd_data(u8_t *client_data, u16_t size)
{
	struct lwm2m_engine_obj *check_obj;
	u8_t temp[32];
	u16_t pos = 0;
	int len;

	SYS_SLIST_FOR_EACH_CONTAINER(&engine_obj_list, check_obj, node) {
		len = snprintf(temp, sizeof(temp), "%s</%u/%u>",
			       (pos > 0) ? "," : "", check_obj->obj_id,
			       check_obj->obj_inst_id);
		if (pos + len < size) {
			memcpy(&client_data[pos], temp, len);
			pos += len;
		} else {
			/* full buffer -- exit loop */
			break;
		}
	}

	client_data[pos] = '\0';
	return pos;
}

static int
get_observe_option(const struct zoap_packet *zpkt)
{
	struct zoap_option option = {};
	u16_t count = 1;
	int r;

	r = zoap_find_options(zpkt, ZOAP_OPTION_OBSERVE, &option, count);
	if (r <= 0) {
		return -ENOENT;
	}

	return zoap_option_value_to_int(&option);
}

#define DISCOVER_PREFACE	"</.well-known/core>;ct=40"

static enum lwm2m_status
discover_op(struct lwm2m_engine_context *context)
{
	struct lwm2m_output_context *out = context->out;
	struct lwm2m_engine_obj *check_obj;
	int i = 0;

	/* init the outbuffer */
	out->outbuf = zoap_packet_get_payload(out->out_zpkt,
					      &out->outsize);

	/* </.well-known/core>,**;ct=40 */
	memcpy(out->outbuf, DISCOVER_PREFACE, strlen(DISCOVER_PREFACE));
	out->outlen += strlen(DISCOVER_PREFACE);

	SYS_SLIST_FOR_EACH_CONTAINER(&engine_obj_list, check_obj, node) {
		/* avoid discovery for security and server objects */
		if (check_obj->obj_id <= LWM2M_OBJECT_SERVER_ID) {
			continue;
		}

		out->outlen += sprintf(&out->outbuf[out->outlen], ",</%u/%u>",
				       check_obj->obj_id,
				       check_obj->obj_inst_id);

		for (i = 0; i < check_obj->rsc_count; i++) {
			out->outlen += sprintf(&out->outbuf[out->outlen],
					       ",</%u/%u/%u>",
					       check_obj->obj_id,
					       check_obj->obj_inst_id,
					       RSC_ID(check_obj->rsc_ids[i]));
		}
	}

	out->outbuf[out->outlen] = '\0';
	SYS_LOG_DBG("discovery:%s", out->outbuf);

	return LWM2M_STATUS_OK;
}

static enum lwm2m_status handle_request(struct zoap_packet *request,
					struct zoap_packet *response,
					struct sockaddr *from_addr)
{
	int ret;
	u8_t code;
	enum lwm2m_status success;
	struct zoap_option options[4];
	struct lwm2m_engine_obj *obj;
	const u8_t *token;
	u8_t tkl = 0;
	enum lwm2m_content_format format;
	enum lwm2m_content_format accept;
	struct lwm2m_input_context in;
	struct lwm2m_output_context out;
	struct lwm2m_obj_path path;
	struct lwm2m_engine_context context;
	int observe = -1; /* default to -1, 0 = ENABLE, 1 = DISABLE */
	bool discover = false;
	u16_t len;

	/* setup engine context */
	context.in   = &in;
	context.out  = &out;
	context.path = &path;
	engine_clear_context(&context);

	/* set ZoAP request / response */
	in.in_zpkt = request;
	out.out_zpkt = response;

	/* set default reader/writer */
	in.reader = &plain_text_reader;
	out.writer = &plain_text_writer;

	/* parse the URL path into components */
	ret = zoap_find_options(in.in_zpkt, ZOAP_OPTION_URI_PATH, options, 4);
	if (ret > 0) {

		/* check for .well-known/core URI query (DISCOVER) */
		if (ret == 2 &&
		    (options[0].len == 11 &&
		     strncmp(options[0].value,".well-known", 11) == 0) &&
		    (options[1].len == 4 &&
		     strncmp(options[1].value,"core", 4) == 0)) {
			discover = true;
		} else {
			path.level = ret;

			path.obj_id = atou16(options[0].value,
					     options[0].len, &len);
			if (len == 0) {
				path.level = 0;
			}

			if (path.level > 1) {
				path.obj_inst_id = atou16(options[1].value,
							  options[1].len, &len);
				if (len == 0) {
					path.level = 1;
				}
			}

			if (path.level > 2) {
				path.res_id = atou16(options[2].value,
						     options[2].len, &len);
				if (len == 0) {
					path.level = 2;
				}
			}

			if (path.level > 3) {
				path.res_inst_id = atou16(options[3].value,
							  options[3].len, &len);
				if (len == 0) {
					path.level = 3;
				}
			}
		}
	}

	/* read Content Format */
	ret = zoap_find_options(in.in_zpkt, ZOAP_OPTION_CONTENT_FORMAT,
				options, 1);
	if (ret > 0) {
		format = zoap_option_value_to_int(&options[0]);
	} else {
		SYS_LOG_DBG("No content-format given. Assume text plain.");
		format = LWM2M_TEXT_PLAIN;
	}
	SYS_LOG_DBG("FORMAT: %d", format);

	/* read Accept */
	ret = zoap_find_options(in.in_zpkt, ZOAP_OPTION_ACCEPT, options, 1);
	if (ret > 0) {
		accept = zoap_option_value_to_int(&options[0]);
	} else {
		SYS_LOG_DBG("No Accept header: use same as content-format(%d)",
			    format);
		accept = format;
	}
	SYS_LOG_DBG("ACCEPT: %u", accept);

	/* TODO: Handle bootstrap deleted */

	code = zoap_header_get_code(in.in_zpkt);
	obj = get_engine_obj(path.obj_id, path.obj_inst_id, path.level);
	if (!obj || !obj->op_callback) {
		/* No matching object/instance found - ignore request */
		return LWM2M_STATUS_NOT_FOUND;
	}

	format = lwm2m_engine_select_reader(&in, format);
	accept = lwm2m_engine_select_writer(&out, accept);

	/* set the operation */
	switch (code & ZOAP_REQUEST_MASK) {

	case ZOAP_METHOD_GET:
		SYS_LOG_DBG("ZOAP_METHOD_GET");
		if (discover || format == APP_LINK_FORMAT) {
			SYS_LOG_DBG("*DISCOVERY*");
			context.operation = LWM2M_OP_DISCOVER;
			accept = APP_LINK_FORMAT;
		} else {
			context.operation = LWM2M_OP_READ;
		}
		/* check for observe */
		observe = get_observe_option(in.in_zpkt);
		zoap_header_set_code(out.out_zpkt, ZOAP_RESPONSE_CODE_CONTENT);
		break;

	case ZOAP_METHOD_POST:
		SYS_LOG_DBG("ZOAP_METHOD_POST");
		if (path.level < 2) {
			/* write to a object instance */
			context.operation = LWM2M_OP_WRITE;
		} else {
			context.operation = LWM2M_OP_EXECUTE;
		}
		zoap_header_set_code(out.out_zpkt, ZOAP_RESPONSE_CODE_CHANGED);
		break;

	case ZOAP_METHOD_PUT:
		SYS_LOG_DBG("ZOAP_METHOD_PUT");
		context.operation = LWM2M_OP_WRITE;
		zoap_header_set_code(out.out_zpkt, ZOAP_RESPONSE_CODE_CHANGED);
		break;

	case ZOAP_METHOD_DELETE:
		SYS_LOG_DBG("ZOAP_METHOD_DELETE");
		context.operation = LWM2M_OP_DELETE;
		zoap_header_set_code(out.out_zpkt, ZOAP_RESPONSE_CODE_DELETED);
		break;

	default:
		break;
	}

	/* set response token */
	token = zoap_header_get_token(in.in_zpkt, &tkl);
	if (tkl) {
		zoap_header_set_token(out.out_zpkt, token, tkl);
	}

	in.inpos = 0;
	in.inbuf = zoap_packet_get_payload(in.in_zpkt, &in.insize);

	/* TODO: check for block transfer? */

	switch (context.operation) {

	case LWM2M_OP_DISCOVER:
		/* set output content-format */
		ret = zoap_add_option_int(out.out_zpkt,
					  ZOAP_OPTION_CONTENT_FORMAT,
					  APP_LINK_FORMAT);
		success = discover_op(&context);
		break;

	case LWM2M_OP_READ:
		if (observe == 0) {
			/* add new observer */
			if (token) {
				ret = zoap_add_option_int(out.out_zpkt,
							  ZOAP_OPTION_OBSERVE,
							  1);
				if (ret) {
					SYS_LOG_ERR("OBSERVE option error: %d",
						    ret);
				}

				ret = engine_add_observer(from_addr, token, tkl,
							  &path);
				if (ret) {
					SYS_LOG_ERR("add OBSERVE error: %d",
						    ret);
				}
			} else {
				SYS_LOG_ERR("OBSERVE request missing token");
			}
		} else if (observe == 1) {
			/* use token from this request */
			token = zoap_header_get_token(in.in_zpkt, &tkl);
			/* remove observer */
			ret = engine_remove_observer(token, tkl);
			if (ret) {
				SYS_LOG_ERR("remove obserer error: %d", ret);
			}
		}

		/* set output content-format */
		ret = zoap_add_option_int(out.out_zpkt,
					  ZOAP_OPTION_CONTENT_FORMAT, accept);
		if (ret > 0) {
			SYS_LOG_ERR("Unable to set response content-format: %d",
				    ret);
		}

		success = multi_read_op(obj, &context);
		break;

	case LWM2M_OP_WRITE:
		success = multi_write_op(obj, &context, format);
		break;

	default:
		success = obj->op_callback(obj, &context);
		break;
	}

	if (success == LWM2M_STATUS_OK) {
		/* TODO: Handle blockwise 1 */

		if (out.outlen > 0) {
			SYS_LOG_DBG("replying with %u bytes", out.outlen);
			zoap_packet_set_used(out.out_zpkt, out.outlen);
		} else {
			SYS_LOG_DBG("no data in reply");
		}
	} else {
		if (success == LWM2M_STATUS_NOT_FOUND) {
			zoap_header_set_code(out.out_zpkt,
					     ZOAP_RESPONSE_CODE_NOT_FOUND);
		} else if (success == LWM2M_STATUS_OP_NOT_ALLOWED) {
			zoap_header_set_code(out.out_zpkt,
					     ZOAP_RESPONSE_CODE_NOT_ALLOWED);
		} else {
			/* Failed to handle the request */
			zoap_header_set_code(out.out_zpkt,
					     ZOAP_RESPONSE_CODE_INTERNAL_ERROR);
		}
	}

	return success;
}

static void
udp_receive(struct net_context *ctx, struct net_pkt *pkt, int status,
	    void *user_data)
{
	struct zoap_pending *pending;
	struct zoap_reply *reply;
	struct zoap_packet response;
	struct sockaddr from_addr;
	struct zoap_packet response2;
	struct net_pkt *pkt2;
	int header_len, r;
	enum lwm2m_status success;
	const u8_t *token;
	u8_t tkl;

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
		/*
		 * If no normal response handler is found, then this is
		 * a new request coming from the server.  Let's look
		 * at registered objects to find a handler.
		 */
		if (zoap_header_get_type(&response) == ZOAP_TYPE_CON) {
			/* Create a response packet if we reach this point */
			r = zoap_init_message(&response2, &pkt2, ZOAP_TYPE_ACK,
					      zoap_header_get_code(&response),
					      zoap_header_get_id(&response),
					      NULL, -1, NULL);
			if (r < 0) {
				if (pkt2) {
					net_pkt_unref(pkt2);
				}
				goto cleanup;
			}

			/*
			 * The "response" here is actually a new request
			 */
			success = handle_request(&response, &response2,
						 &from_addr);
			if (success == LWM2M_STATUS_OK) {
				SYS_LOG_DBG("Message handled");
			} else {
				SYS_LOG_ERR("No handler for response (err:%u)",
					    success);
			}

			r = net_context_sendto(pkt2, &from_addr, NET_SIN_SIZE,
					       NULL, K_NO_WAIT, NULL, NULL);
			if (r < 0) {
				SYS_LOG_ERR("Err sending response: %d", r);
			}
		} else {
			SYS_LOG_ERR("No handler for response");
		}
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

	r = net_context_sendto(pending->pkt, &engine_info.bs_server_ep.addr,
			       NET_SIN_SIZE, NULL, K_NO_WAIT, NULL, NULL);
	if (r < 0) {
		return;
	}

	if (!zoap_pending_cycle(pending)) {
		zoap_pending_clear(pending);
		return;
	}

	k_delayed_work_submit(&retransmit_work, pending->timeout);
}

/* state machine reply callbacks */

static int do_bootstrap_reply_cb(const struct zoap_packet *response,
				 struct zoap_reply *reply,
				 const struct sockaddr *from)
{
	u8_t code;

	code = zoap_header_get_code(response);
	SYS_LOG_DBG("Bootstrap callback (code:%u.%u)",
		    ZOAP_RESPONSE_CODE_CLASS(code),
		    ZOAP_RESPONSE_CODE_DETAIL(code));

	if (code == ZOAP_RESPONSE_CODE_CHANGED) {
		SYS_LOG_DBG("Considered done!");
		set_sm_state(ENGINE_BOOTSTRAP_DONE);
	} else if (code == ZOAP_RESPONSE_CODE_NOT_FOUND) {
		SYS_LOG_ERR("Failed: NOT_FOUND.  Not Retrying.");
		set_sm_state(ENGINE_DO_REGISTRATION);
	} else {
		/* TODO: Read payload for error message? */
		SYS_LOG_ERR("Failed with code %u.%u. Retrying ...",
			    ZOAP_RESPONSE_CODE_CLASS(code),
			    ZOAP_RESPONSE_CODE_DETAIL(code));
		set_sm_state(ENGINE_INIT);
	}

	return 0;
}

static int do_registration_reply_cb(const struct zoap_packet *response,
				    struct zoap_reply *reply,
				    const struct sockaddr *from)
{
	struct zoap_option options[2];
	u8_t code;
	int ret;

	code = zoap_header_get_code(response);
	SYS_LOG_DBG("Registration callback (code:%u.%u)",
		    ZOAP_RESPONSE_CODE_CLASS(code),
		    ZOAP_RESPONSE_CODE_DETAIL(code));

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

		if (options[1].len + 1 > sizeof(engine_info.assigned_ep)) {
			SYS_LOG_ERR("Unexpected length of query: "
				    "%u (expected %zu)\n",
				    options[1].len,
				    sizeof(engine_info.assigned_ep));
			return -EINVAL;
		}

		memcpy(engine_info.assigned_ep, options[1].value,
		       options[1].len);
		engine_info.assigned_ep[options[1].len] = '\0';
		set_sm_state(ENGINE_REGISTRATION_DONE);
		engine_info.registered = 1;
		SYS_LOG_INF("Registration Done (EP='%s')",
			    engine_info.assigned_ep);

		return 0;
	} else if (code == ZOAP_RESPONSE_CODE_NOT_FOUND) {
		SYS_LOG_ERR("Failed: NOT_FOUND.  Not Retrying.");
		set_sm_state(ENGINE_REGISTRATION_DONE);
		return 0;
	}

	/* TODO: Read payload for error message? */
	/* Possible error response codes: 4.00 Bad request & 4.03 Forbidden */
	SYS_LOG_ERR("failed with code %u.%u. Re-init network",
		    ZOAP_RESPONSE_CODE_CLASS(code),
		    ZOAP_RESPONSE_CODE_DETAIL(code));
	set_sm_state(ENGINE_INIT);
	return 0;
}

static int do_update_reply_cb(const struct zoap_packet *response,
			      struct zoap_reply *reply,
			      const struct sockaddr *from)
{
	u8_t code;

	code = zoap_header_get_code(response);
	SYS_LOG_DBG("Update callback (code:%u.%u)",
		    ZOAP_RESPONSE_CODE_CLASS(code),
		    ZOAP_RESPONSE_CODE_DETAIL(code));

	/* If NOT_FOUND just continue on */
	if ((code == ZOAP_RESPONSE_CODE_CHANGED) ||
	    (code == ZOAP_RESPONSE_CODE_CREATED)) {
		set_sm_state(ENGINE_REGISTRATION_DONE);
		SYS_LOG_DBG("Update Done");
		return 0;
	}

	/* TODO: Read payload for error message? */
	/* Possible error response codes: 4.00 Bad request & 4.04 Not Found */
	SYS_LOG_ERR("Failed with code %u.%u. Retrying registration",
		    ZOAP_RESPONSE_CODE_CLASS(code),
		    ZOAP_RESPONSE_CODE_DETAIL(code));
	engine_info.registered = 0;
	set_sm_state(ENGINE_DO_REGISTRATION);

	return 0;
}

static int do_deregister_reply_cb(const struct zoap_packet *response,
				  struct zoap_reply *reply,
				  const struct sockaddr *from)
{
	u8_t code;

	code = zoap_header_get_code(response);
	SYS_LOG_DBG("Deregister callback (code:%u.%u)",
		    ZOAP_RESPONSE_CODE_CLASS(code),
		    ZOAP_RESPONSE_CODE_DETAIL(code));

	if (code == ZOAP_RESPONSE_CODE_DELETED) {
		engine_info.registered = 0;
		SYS_LOG_DBG("Deregistration success");
		set_sm_state(ENGINE_DEREGISTERED);
	} else {
		SYS_LOG_ERR("failed with code %u.%u",
			    ZOAP_RESPONSE_CODE_CLASS(code),
			    ZOAP_RESPONSE_CODE_DETAIL(code));
		if (get_sm_state() == ENGINE_DEREGISTER_SENT) {
			set_sm_state(ENGINE_DEREGISTER_FAILED);
		}
	}

	return 0;
}

/* state machine step functions */

static int sm_do_init(void)
{
	SYS_LOG_DBG("RD Client started with endpoint "
		    "'%s' and client lifetime %d",
		    engine_info.ep,
		    engine_info.lifetime);
	/* Zephyr has joined network already */
	engine_info.has_registration_info = 1;
	engine_info.registered = 0;
	engine_info.bootstrapped = 0;
	engine_info.trigger_update = 0;
#if defined(CONFIG_LWM2M_BOOTSTRAP_SERVER)
	engine_info.use_bootstrap = 1;
#else
	engine_info.use_registration = 1;
#endif
	if (engine_info.lifetime == 0) {
		engine_info.lifetime = CONFIG_LWM2M_ENGINE_DEFAULT_LIFETIME;
	}
	/* Do bootstrap or registration */
	if (engine_info.use_bootstrap) {
		set_sm_state(ENGINE_DO_BOOTSTRAP);
	} else {
		set_sm_state(ENGINE_DO_REGISTRATION);
	}

	return 0;
}

static int sm_do_bootstrap(void)
{
	struct zoap_packet request;
	struct net_pkt *pkt = NULL;
	struct zoap_pending *pending;
	int ret = 0;

	if (engine_info.use_bootstrap &&
	    engine_info.bootstrapped == 0 &&
	    engine_info.has_bs_server_info) {

		ret = zoap_init_message(&request, &pkt, ZOAP_TYPE_CON,
					ZOAP_METHOD_POST, 0, NULL, 0,
					do_bootstrap_reply_cb);
		if (ret) {
			goto cleanup;
		}

		zoap_add_option(&request, ZOAP_OPTION_URI_PATH,
				"bs", strlen("bs"));

		snprintf(query_buffer, sizeof(query_buffer) - 1,
			 "ep=%s", engine_info.ep);
		zoap_add_option(&request, ZOAP_OPTION_URI_QUERY,
				query_buffer, strlen(query_buffer));

		/* log the bootstrap attempt */
		SYS_LOG_DBG("Register ID with bootstrap server [%s:%d] as '%s'",
			    sprint_ip_addr(&engine_info.bs_server_ep.addr),
			    ntohs(NET_SIN_PORT(
				&engine_info.bs_server_ep.addr)),
			    query_buffer);

		pending = zoap_pending_next_unused(pendings, NUM_PENDINGS);
		if (!pending) {
			SYS_LOG_ERR("Unable to find a free pending to track "
				    "retransmissions.");
			ret = -ENOMEM;
			goto cleanup;
		}

		ret = zoap_pending_init(pending, &request,
					&engine_info.bs_server_ep.addr);
		if (ret < 0) {
			SYS_LOG_ERR("Unable to initialize a pending "
				    "retransmission (err:%d).", ret);
			goto cleanup;
		}

		ret = net_context_sendto(pkt, &engine_info.bs_server_ep.addr,
				       NET_SIN_SIZE,
				       NULL, 0, NULL, NULL);
		if (ret < 0) {
			SYS_LOG_ERR("Error sending LWM2M packet (err:%d).",
				    ret);
			goto cleanup;
		}

		zoap_pending_cycle(pending);
		k_delayed_work_submit(&retransmit_work, pending->timeout);
		set_sm_state(ENGINE_BOOTSTRAP_SENT);
	}

cleanup:
	if (pkt) {
		net_pkt_unref(pkt);
	}

	return ret;
}

static int sm_bootstrap_done(void)
{
	/* TODO: Fix this */
	/* check that we should still use bootstrap */
	if (engine_info.use_bootstrap) {
#ifdef CONFIG_LWM2M_SECURITY_OBJ_SUPPORT
		const struct lwm2m_security_data *sec_data = NULL;
		int i;

		SYS_LOG_DBG("*** Bootstrap - checking for server info ...");

		/* get the sec_data object - ignore bootstrap servers */
		for (i = 0; i < lwm2m_security_instance_count(); i++) {
			sec_data = lwm2m_security_get_instance(i);
			if (sec_data && !sec_data->bootstrap)
				break;
			sec_data = NULL;
		}

		if (sec_data) {
			/* get the server URI */
			if (sec_data->server_uri_len > 0) {
				/* TODO: Write endpoint parsing function */
#if 0
				if (!parse_endpoint(sec_data->server_uri,
						    sec_data->server_uri_len,
						    &engine_info.server_ep)) {
#else
				if (true) {
#endif
					SYS_LOG_ERR("Failed to parse URI!");
				} else {
					engine_info.has_registration_info = 1;
					engine_info.registered = 0;
					engine_info.bootstrapped++;
				}
			} else {
				SYS_LOG_ERR("** failed to parse URI");
			}
		}

		/* if we did not register above - then fail this and restart */
		if (engine_info.bootstrapped == 0) {
			/* Not ready - Retry with the bootstrap server again */
			set_sm_state(ENGINE_DO_BOOTSTRAP);
		} else {
			set_sm_state(ENGINE_DO_REGISTRATION);
		}
	} else {
#endif
		set_sm_state(ENGINE_DO_REGISTRATION);
	}

	return 0;
}

static int sm_do_registration(void)
{
	struct zoap_packet request;
	struct net_pkt *pkt = NULL;
	struct zoap_pending *pending;
	u8_t *payload;
	u16_t client_data_len, len;
	int ret = 0;

	if (!endpoint_is_connected(&engine_info.server_ep)) {
		/* Not connected... wait a bit... */
		SYS_LOG_INF("Wait until connected ...");
		return 0;
	}

	if (engine_info.use_registration &&
	    !engine_info.registered &&
	    engine_info.has_registration_info) {

		ret = zoap_init_message(&request, &pkt, ZOAP_TYPE_CON,
					ZOAP_METHOD_POST, 0, NULL, 0,
					do_registration_reply_cb);
		if (ret) {
			goto cleanup;
		}

		zoap_add_option(&request, ZOAP_OPTION_URI_PATH,
				LWM2M_RD_CLIENT_URI,
				strlen(LWM2M_RD_CLIENT_URI));

		/* TODO: use security / server data */
		snprintf(query_buffer, sizeof(query_buffer) - 1,
			 "ep=%s", engine_info.ep);
		zoap_add_option(&request, ZOAP_OPTION_URI_QUERY,
				query_buffer, strlen(query_buffer));
		snprintf(query_buffer, sizeof(query_buffer) - 1,
			 "lt=%d", engine_info.lifetime);
		/* TODO: add supported binding query string */
		zoap_add_option(&request, ZOAP_OPTION_URI_QUERY,
				query_buffer, strlen(query_buffer));

		/* generate the rd data */
		client_data_len = lwm2m_engine_get_rd_data(client_data,
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

		pending = zoap_pending_next_unused(pendings, NUM_PENDINGS);
		if (!pending) {
			SYS_LOG_ERR("Unable to find a free pending to track "
				    "retransmissions.");
			ret = -ENOMEM;
			goto cleanup;
		}

		ret = zoap_pending_init(pending, &request,
					&engine_info.server_ep.addr);
		if (ret < 0) {
			SYS_LOG_ERR("Unable to initialize a pending "
				    "retransmission (err:%d).", ret);
			goto cleanup;
		}

		/* log the registration attempt */
		SYS_LOG_DBG("Registering with [%s:%d] lwm2m endpoint '%s'",
			    sprint_ip_addr(&engine_info.server_ep.addr),
			    ntohs(NET_SIN_PORT(&engine_info.server_ep.addr)),
			    query_buffer);

		/* remember the last reg time */
		engine_info.last_update = k_uptime_get();
		SYS_LOG_DBG("last_update = %lld", engine_info.last_update);

		ret = net_context_sendto(pkt, &engine_info.server_ep.addr,
				       NET_SIN_SIZE,
				       NULL, 0, NULL, NULL);
		if (ret < 0) {
			SYS_LOG_ERR("Error sending LWM2M packet (err:%d).",
				    ret);
			goto cleanup;
		}

		zoap_pending_cycle(pending);
		k_delayed_work_submit(&retransmit_work, pending->timeout);
		set_sm_state(ENGINE_REGISTRATION_SENT);
	}

cleanup:
	if (pkt) {
		net_pkt_unref(pkt);
	}

	return ret;
}

static int sm_registration_done(void)
{
	struct zoap_packet request;
	struct net_pkt *pkt = NULL;
	struct zoap_pending *pending;
	u8_t *payload;
	u16_t client_data_len, len;
	int ret = 0;

	/* check for lifetime seconds - 1 so that we can update early */
	if (engine_info.registered &&
	    (engine_info.trigger_update ||
	     ((engine_info.lifetime - SECONDS_TO_UPDATE_EARLY) <=
	      (k_uptime_get() - engine_info.last_update) / 1000))) {
		/* remember the last registration time */
		engine_info.last_update = k_uptime_get();
		SYS_LOG_DBG("last_update = %lld", engine_info.last_update);

		ret = zoap_init_message(&request, &pkt, ZOAP_TYPE_CON,
					ZOAP_METHOD_POST, 0, NULL, 0,
					do_update_reply_cb);
		if (ret) {
			goto cleanup;
		}

		zoap_add_option(&request, ZOAP_OPTION_URI_PATH,
				LWM2M_RD_CLIENT_URI,
				strlen(LWM2M_RD_CLIENT_URI));

		zoap_add_option(&request, ZOAP_OPTION_URI_PATH,
				engine_info.assigned_ep,
				strlen(engine_info.assigned_ep));

		snprintf(query_buffer, sizeof(query_buffer) - 1,
			 "lt=%d", engine_info.lifetime);
		zoap_add_option(&request, ZOAP_OPTION_URI_QUERY,
				query_buffer, strlen(query_buffer));

		/* if UPDATE was triggered, re-send object support data */
		if (engine_info.trigger_update) {
			/* generate the client data */
			client_data_len = lwm2m_engine_get_rd_data(client_data,
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

		pending = zoap_pending_next_unused(pendings, NUM_PENDINGS);
		if (!pending) {
			SYS_LOG_ERR("Unable to find a free pending to track "
				    "retransmissions.");
			ret = -ENOMEM;
			goto cleanup;
		}

		ret = zoap_pending_init(pending, &request,
					&engine_info.server_ep.addr);
		if (ret < 0) {
			SYS_LOG_ERR("Unable to initialize a pending "
				    "retransmission (err:%d).", ret);
			goto cleanup;
		}

		SYS_LOG_INF("Send UPDATE to '%s': %s",
			    engine_info.assigned_ep, query_buffer);

		ret = net_context_sendto(pkt, &engine_info.server_ep.addr,
				       NET_SIN_SIZE,
				       NULL, 0, NULL, NULL);
		if (ret < 0) {
			SYS_LOG_ERR("Error sending LWM2M packet (err:%d).",
				    ret);
			goto cleanup;
		}

		zoap_pending_cycle(pending);
		k_delayed_work_submit(&retransmit_work, pending->timeout);
		set_sm_state(ENGINE_UPDATE_SENT);
	}

cleanup:
	/* clear trigger_update */
	engine_info.trigger_update = 0;
	if (pkt) {
		net_pkt_unref(pkt);
	}

	return ret;
}

static int sm_do_deregister(void)
{
	struct zoap_packet request;
	struct net_pkt *pkt = NULL;
	struct zoap_pending *pending;
	int ret;

	ret = zoap_init_message(&request, &pkt, ZOAP_TYPE_CON,
				ZOAP_METHOD_DELETE, 0, NULL, 0,
				do_deregister_reply_cb);
	if (ret) {
		goto cleanup;
	}

	zoap_add_option(&request, ZOAP_OPTION_URI_PATH,
			engine_info.assigned_ep,
			strlen(engine_info.assigned_ep));

	pending = zoap_pending_next_unused(pendings, NUM_PENDINGS);
	if (!pending) {
		SYS_LOG_ERR("Unable to find a free pending to track "
			    "retransmissions.");
		ret = -ENOMEM;
		goto cleanup;
	}

	ret = zoap_pending_init(pending, &request,
				&engine_info.server_ep.addr);
	if (ret < 0) {
		SYS_LOG_ERR("Unable to initialize a pending "
			    "retransmission (err:%d).", ret);
		goto cleanup;
	}

	SYS_LOG_INF("Deregister from '%s'", engine_info.assigned_ep);

	ret = net_context_sendto(pkt, &engine_info.server_ep.addr,
			       NET_SIN_SIZE,
			       NULL, 0, NULL, NULL);
	if (ret < 0) {
		SYS_LOG_ERR("Error sending LWM2M packet (err:%d).",
			    ret);
		goto cleanup;
	}

	zoap_pending_cycle(pending);
	k_delayed_work_submit(&retransmit_work, pending->timeout);
	set_sm_state(ENGINE_DEREGISTER_SENT);

cleanup:
	if (pkt) {
		net_pkt_unref(pkt);
	}

	return ret;
}

static int notify_message_reply_cb(const struct zoap_packet *response,
				   struct zoap_reply *reply,
				   const struct sockaddr *from)
{
	int ret = 0;
	u8_t type;
	u8_t code;

	type = zoap_header_get_type(response);
	code = zoap_header_get_code(response);
	SYS_LOG_DBG("NOTIFY ACK type:%u code:%d.%d reply_token:'%s'",
		type,
		ZOAP_RESPONSE_CODE_CLASS(code),
		ZOAP_RESPONSE_CODE_DETAIL(code),
		sprint_token(reply->token, reply->tkl));

	/* remove observer on ZOAP_TYPE_RESET */
	if (type == ZOAP_TYPE_RESET) {
		if (reply->tkl > 0) {
			ret = engine_remove_observer(reply->token, reply->tkl);
			if (ret) {
				SYS_LOG_ERR("remove obserer error: %d", ret);
			}
		} else {
			SYS_LOG_ERR("notify reply missing token -- ignored.");
		}
	}

	return 0;
}

static int generate_notify_message(struct observe_node *observer,
				   bool manual_trigger)
{
	struct net_pkt *pkt = NULL;
	struct zoap_pending *pending;
	int ret = 0;
	enum lwm2m_status success;
	struct zoap_packet request;
	struct lwm2m_engine_obj *obj;
	struct lwm2m_output_context out;
	struct lwm2m_engine_context context;

	/* setup engine context */
	context.out = &out;
	engine_clear_context(&context);
	/* dont clear the path */
	context.path = &observer->path;
	context.operation = LWM2M_OP_READ;
	out.out_zpkt = &request;

	SYS_LOG_DBG("[%s] NOTIFY MSG START: %u/%u/%u(%u) token:'%s' [%s] %lld",
		    manual_trigger ? "MANUAL" : "AUTO",
		    observer->path.obj_id,
		    observer->path.obj_inst_id,
		    observer->path.res_id,
		    observer->path.level,
		    sprint_token(observer->token, observer->tkl),
		    sprint_ip_addr(&observer->addr),
		    k_uptime_get());

	obj = get_engine_obj(observer->path.obj_id,
			     observer->path.obj_inst_id,
			     observer->path.level);
	if (!obj) {
		SYS_LOG_ERR("unable to get engine obj for %u/%u(%u)",
			    observer->path.obj_id,
			    observer->path.obj_inst_id,
			    observer->path.level);
		return -EINVAL;
	}

	ret = zoap_init_message(out.out_zpkt, &pkt, ZOAP_TYPE_CON,
				ZOAP_RESPONSE_CODE_CONTENT, 0,
				observer->token, observer->tkl,
				notify_message_reply_cb);
	if (ret) {
		goto cleanup;
	}

	/* each notification should increment the observer counter */
	observer->counter++;
	ret = zoap_add_option_int(out.out_zpkt, ZOAP_OPTION_OBSERVE,
				  observer->counter);
	if (ret) {
		SYS_LOG_ERR("OBSERVE option error: %d", ret);
		goto cleanup;
	}

	/* TODO: save the accept-format from original request */

	/* set the output writer */
	lwm2m_engine_select_writer(&out, LWM2M_TLV);

	/* set response content-format */
	ret = zoap_add_option_int(out.out_zpkt, ZOAP_OPTION_CONTENT_FORMAT,
				  LWM2M_TLV);
	if (ret > 0) {
		SYS_LOG_ERR("error setting content-format (err:%d)", ret);
		goto cleanup;
	}

	success = multi_read_op(obj, &context);
	if (success == LWM2M_STATUS_OK) {
		if (out.outlen > 0) {
			zoap_packet_set_used(out.out_zpkt, out.outlen);
		} else {
			SYS_LOG_DBG("no data in reply");
		}
	} else {
		SYS_LOG_ERR("error in multi-format read (err:%u)", success);
		ret = -EINVAL;
		goto cleanup;
	}

	pending = zoap_pending_next_unused(pendings, NUM_PENDINGS);
	if (!pending) {
		SYS_LOG_ERR("Unable to find a free pending to track "
			    "retransmissions.");
		ret = -ENOMEM;
		goto cleanup;
	}

	ret = zoap_pending_init(pending, out.out_zpkt, &observer->addr);
	if (ret < 0) {
		SYS_LOG_ERR("Unable to initialize a pending "
			    "retransmission (err:%d).", ret);
		goto cleanup;
	}

	ret = net_context_sendto(pkt, &observer->addr, NET_SIN_SIZE,
				 NULL, 0, NULL, NULL);
	if (ret < 0) {
		SYS_LOG_ERR("Error sending LWM2M packet (err:%d).", ret);
		goto cleanup;
	}
	SYS_LOG_DBG("NOTIFY MSG: SENT");

	zoap_pending_cycle(pending);
	k_delayed_work_submit(&retransmit_work, pending->timeout);

cleanup:
	if (pkt) {
		net_pkt_unref(pkt);
	}

	return ret;
}

/* TODO: this needs to be triggered via work_queue */
static void perform_notify_checks(void)
{
	struct observe_node *check_obj;
	s64_t timestamp = k_uptime_get();

	/*
	 * 1. scan the observer list
	 * 2. For each notify event found, scan the observer list
	 * 3. For each observer match, generate a NOTIFY message,
	 *    attaching the notify response handler
	 */
	SYS_SLIST_FOR_EACH_CONTAINER(&engine_observer_list,
				     check_obj, node) {

		/*
		 * manual notify requirements:
		 * - event_timestamp > last_timestamp
		 * - current timestamp > last_timestamp + min_period_sec
		 */
		if (check_obj->event_timestamp > check_obj->last_timestamp &&
		    timestamp > check_obj->last_timestamp +
			(check_obj->min_period_sec * MSEC_PER_SEC)) {
			check_obj->last_timestamp = k_uptime_get();
			generate_notify_message(check_obj, true);

		/*
		 * automatic time-based notify requirements:
		 * - current timestamp > last_timestamp + max_period_sec
		 */
		} else if (timestamp > check_obj->last_timestamp +
			(check_obj->max_period_sec * MSEC_PER_SEC)) {
			/* TODO: generate NOTIFY message */
			check_obj->last_timestamp = k_uptime_get();
			generate_notify_message(check_obj, false);
		}

	}
}

static void lwm2m_engine_service(void)
{
	while (true) {
		if (engine_info.registered) {
			perform_notify_checks();
		}

		k_sleep(K_MSEC(STATE_MACHINE_UPDATE_INTERVAL));


		switch (get_sm_state()) {

		case ENGINE_INIT:
			sm_do_init();
			break;

		case ENGINE_DO_BOOTSTRAP:
			sm_do_bootstrap();
			break;

		case ENGINE_BOOTSTRAP_SENT:
			/* wait for bootstrap to be done */
			break;

		case ENGINE_BOOTSTRAP_DONE:
			sm_bootstrap_done();
			break;

		case ENGINE_DO_REGISTRATION:
			sm_do_registration();
			break;

		case ENGINE_REGISTRATION_SENT:
			/* wait registration to be done */
			break;

		case ENGINE_REGISTRATION_DONE:
			sm_registration_done();
			break;

		case ENGINE_UPDATE_SENT:
			/* wait update to be done */
			break;

		case ENGINE_DEREGISTER:
			sm_do_deregister();
			break;

		case ENGINE_DEREGISTER_SENT:
			break;

		case ENGINE_DEREGISTER_FAILED:
			break;

		case ENGINE_DEREGISTERED:
			break;

		default:
			SYS_LOG_ERR("Unhandled state: %d", get_sm_state());

		}

		k_yield();
	}
}

int lwm2m_engine_init(const char *endpoint_name, struct sockaddr *local_addr,
		      const char *peer_ipaddr)
{
	int ret;

	/* Server Peer IP information */
	/* TODO: use server URI data from security */
	net_addr_pton(LWM2M_AF_INET, peer_ipaddr,
		      &NET_SIN_ADDR(&engine_info.server_ep.addr));
	NET_SIN_FAMILY(&engine_info.server_ep.addr) = LWM2M_AF_INET;
	NET_SIN_PORT(&engine_info.server_ep.addr) = htons(LWM2M_PEER_PORT);

	net_addr_pton(LWM2M_AF_INET, peer_ipaddr,
		      &NET_SIN_ADDR(&engine_info.bs_server_ep.addr));
	NET_SIN_FAMILY(&engine_info.bs_server_ep.addr) = LWM2M_AF_INET;
	NET_SIN_PORT(&engine_info.bs_server_ep.addr) =
			htons(LWM2M_BOOTSTRAP_PORT);

	ret = net_context_get(LWM2M_AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			    &engine_info.net_ctx);
	if (ret) {
		NET_ERR("Could not get an UDP context (err:%d)", ret);
		return ret;
	}

	ret = net_context_bind(engine_info.net_ctx, local_addr, NET_SIN_SIZE);
	if (ret) {
		NET_ERR("Could not bind the UDP context (err:%d)", ret);
		goto cleanup;
	}

	SYS_LOG_DBG("Attched to port: %d",
		    htons(net_sin_ptr(&engine_info.net_ctx->local)->sin_port));

	/* defaults */
	set_sm_state(ENGINE_INIT);

	/* start thread to handle OBSERVER / NOTIFY events */
	k_thread_create(&engine_thread_data,
			&engine_thread_stack[0],
			CONFIG_LWM2M_ENGINE_STACK_SIZE,
			(k_thread_entry_t) lwm2m_engine_service,
			NULL, NULL, NULL, K_PRIO_COOP(7), 0, K_NO_WAIT);

	strncpy(engine_info.ep, endpoint_name, sizeof(engine_info.ep)-1);
	SYS_LOG_INF("LWM2M Client: %s", engine_info.ep);

	k_delayed_work_init(&retransmit_work, retransmit_request);

	ret = net_context_recv(engine_info.net_ctx, udp_receive, 0, NULL);
	if (ret) {
		SYS_LOG_ERR("Could not set receive for net context (err:%d)",
			    ret);
		goto cleanup;
	}

	k_thread_create(&lwm2m_thread_data, &lwm2m_thread_stack[0],
			LWM2M_STACK_SIZE,
			(k_thread_entry_t) lwm2m_engine_service,
			NULL, NULL, NULL, K_PRIO_COOP(7), 0, K_NO_WAIT);

	return 0;

cleanup:
	net_context_put(engine_info.net_ctx);
	engine_info.net_ctx = NULL;
	return ret;
}
