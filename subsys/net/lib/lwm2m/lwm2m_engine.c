/*
 * Copyright (c) 2017 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Uses on some original concepts by:
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
 * - Handle WRITE_ATTRIBUTES (pmin=10&pmax=60)
 *
 * Re-write LWM2M Engine API:
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
#include <init.h>
#include <misc/printk.h>
#include <net/net_ip.h>
#include <net/net_pkt.h>
#include <net/zoap.h>
#include <net/lwm2m.h>

#include "lwm2m_object.h"
#include "lwm2m_engine.h"
#include "lwm2m_rw_plain_text.h"
#ifdef CONFIG_LWM2M_RW_JSON_SUPPORT
#include "lwm2m_rw_json.h"
#endif
#ifdef CONFIG_LWM2M_RW_OMA_TLV_SUPPORT
#include "lwm2m_rw_oma_tlv.h"
#endif
#ifdef CONFIG_LWM2M_RD_CLIENT_SUPPORT
#include "lwm2m_rd_client.h"
#endif

#define ENGINE_UPDATE_INTERVAL 500

/* LWM2M / CoAP Content-Formats */
#define LWM2M_FORMAT_PLAIN_TEXT		0
#define LWM2M_FORMAT_APP_LINK_FORMAT	40
#define LWM2M_FORMAT_APP_OCTET_STREAM	42
#define LWM2M_FORMAT_APP_EXI		47
#define LWM2M_FORMAT_APP_JSON		50
#define LWM2M_FORMAT_OMA_PLAIN_TEXT	1541
#define LWM2M_FORMAT_OMA_OLD_TLV	1542
#define LWM2M_FORMAT_OMA_OLD_JSON	1543
#define LWM2M_FORMAT_OMA_OLD_OPAQUE	1544
#define LWM2M_FORMAT_OMA_TLV		11542
#define LWM2M_FORMAT_OMA_JSON		11543

#define DISCOVER_PREFACE	"</.well-known/core>;ct=40"

struct observe_node {
	sys_snode_t node;
	bool used;
	struct net_context *net_ctx;
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

#define NUM_PENDINGS	CONFIG_LWM2M_ENGINE_MAX_PENDING
#define NUM_REPLIES	CONFIG_LWM2M_ENGINE_MAX_REPLIES

struct zoap_pending pendings[NUM_PENDINGS];
struct zoap_reply replies[NUM_REPLIES];
struct k_delayed_work retransmit_work;

static struct observe_node observe_node_data[CONFIG_LWM2M_ENGINE_MAX_OBSERVER];

static sys_slist_t engine_obj_list;
static sys_slist_t engine_obj_inst_list;
static sys_slist_t engine_observer_list;

/* periodic / notify / observe handling stack */
static char engine_thread_stack[CONFIG_LWM2M_ENGINE_STACK_SIZE];
static struct k_thread engine_thread_data;

/* for debugging: to print IP addresses */
char *sprint_ip_addr(const struct sockaddr *addr)
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

char *sprint_token(const u8_t *token, u8_t tkl)
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

/* observer functions */

int engine_notify_observer(u16_t obj_id, u16_t obj_inst_id, u16_t res_id)
{
	struct observe_node *obs;
	int ret = 0;

	/* look for observers which match our resource */
	SYS_SLIST_FOR_EACH_CONTAINER(&engine_observer_list, obs, node) {
		if (obs->path.obj_id == obj_id &&
		    obs->path.obj_inst_id == obj_inst_id &&
		    (obs->path.level < 3 ||
		     obs->path.res_id == res_id)) {
			/* update the event time for this observer */
			obs->event_timestamp = k_uptime_get();

			SYS_LOG_DBG("NOTIFY EVENT %u/%u/%u",
				    obj_id, obj_inst_id, res_id);

			ret++;
		}
	}

	return ret;
}

int engine_notify_observer_path(struct lwm2m_obj_path *path)
{
	return engine_notify_observer(path->obj_id, path->obj_inst_id,
				      path->res_id);
}

static int engine_add_observer(struct net_context *net_ctx,
			       struct sockaddr *addr,
			       const u8_t *token, u8_t tkl,
			       struct lwm2m_obj_path *path)
{
	struct observe_node *obs;
	int i;

	if (!addr) {
		SYS_LOG_ERR("sockaddr is required");
		return -EINVAL;
	}

	/* make sure this observer doesn't exist already */
	SYS_SLIST_FOR_EACH_CONTAINER(&engine_observer_list, obs, node) {
		if (memcmp(&obs->addr, addr, sizeof(addr)) == 0 &&
			memcmp(&obs->path, path, sizeof(*path)) == 0) {
			/* quietly update the token information */
			memcpy(obs->token, token, tkl);
			obs->tkl = tkl;

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
	observe_node_data[i].net_ctx = net_ctx;
	memcpy(&observe_node_data[i].addr, addr, sizeof(*addr));
	memcpy(&observe_node_data[i].path, path, sizeof(*path));
	memcpy(observe_node_data[i].token, token, tkl);
	observe_node_data[i].tkl = tkl;
	observe_node_data[i].last_timestamp = k_uptime_get();
	observe_node_data[i].event_timestamp =
			observe_node_data[i].last_timestamp;
	/* TODO: use server object instance or WRITE_ATTR values */
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

static int engine_remove_observer(const u8_t *token, u8_t tkl)
{
	struct observe_node *obs, *found_obj = NULL;

	if (!token || tkl == 0) {
		SYS_LOG_ERR("token(%p) and token length(%u) must be valid.",
			    token, tkl);
		return -EINVAL;
	}

	/* find the node index */
	SYS_SLIST_FOR_EACH_CONTAINER(&engine_observer_list, obs, node) {
		if (memcmp(obs->token, token, tkl) == 0) {
			found_obj = obs;
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

/* engine object */

void engine_register_obj(struct lwm2m_engine_obj *obj)
{
	sys_slist_append(&engine_obj_list, &obj->node);
}

void engine_unregister_obj(struct lwm2m_engine_obj *obj)
{
	/* TODO: remove all observer instances */
	sys_slist_remove(&engine_obj_list, NULL, &obj->node);
}

static struct lwm2m_engine_obj *get_engine_obj(int obj_id)
{
	struct lwm2m_engine_obj *obj;

	SYS_SLIST_FOR_EACH_CONTAINER(&engine_obj_list, obj, node) {
		if (obj->obj_id == obj_id) {
			return obj;
		}
	}

	return NULL;
}

struct lwm2m_engine_obj_field *
get_engine_obj_field(struct lwm2m_engine_obj *obj, int res_id)
{
	int i;

	if (obj && obj->fields && obj->field_count > 0) {
		for (i = 0; i < obj->field_count; i++) {
			if (obj->fields[i].res_id == res_id) {
				return &obj->fields[i];
			}
		}
	}

	return NULL;
}

/* engine object instance */

static void engine_register_obj_inst(struct lwm2m_engine_obj_inst *obj_inst)
{
	sys_slist_append(&engine_obj_inst_list, &obj_inst->node);
}

static void engine_unregister_obj_inst(struct lwm2m_engine_obj_inst *obj_inst)
{
	sys_slist_remove(&engine_obj_inst_list, NULL, &obj_inst->node);
}

static struct lwm2m_engine_obj_inst *get_engine_obj_inst(int obj_id,
							 int obj_inst_id)
{
	struct lwm2m_engine_obj_inst *obj_inst;

	SYS_SLIST_FOR_EACH_CONTAINER(&engine_obj_inst_list, obj_inst,
				     node) {
		if (obj_inst->obj->obj_id == obj_id &&
		    obj_inst->obj_inst_id == obj_inst_id) {
			return obj_inst;
		}
	}

	return NULL;
}

static struct lwm2m_engine_obj_inst *
next_engine_obj_inst(struct lwm2m_engine_obj_inst *last,
		     int obj_id, int obj_inst_id)
{
	while (last) {
		last = SYS_SLIST_PEEK_NEXT_CONTAINER(last, node);
		if (last && last->obj->obj_id == obj_id &&
		    last->obj_inst_id == obj_inst_id) {
			return last;
		}
	}

	return NULL;
}

int engine_create_obj_inst(u16_t obj_id, u16_t obj_inst_id,
			   struct lwm2m_engine_obj_inst *obj_inst)
{
	int i;
	struct lwm2m_engine_obj *obj;

	obj_inst = NULL;
	obj = get_engine_obj(obj_id);
	if (!obj) {
		SYS_LOG_ERR("unable to find obj: %u", obj_id);
		return -ENOENT;
	}

	if (!obj->create_cb) {
		SYS_LOG_ERR("obj %u has no create_cb", obj_id);
		return -EINVAL;
	}

	if (obj->instance_count + 1 > obj->max_instance_count) {
		SYS_LOG_ERR("no more instances available for obj %u", obj_id);
		return -ENOMEM;
	}

	obj_inst = obj->create_cb(obj_inst_id);
	if (!obj_inst) {
		SYS_LOG_ERR("unable to create obj %u instance %u",
			    obj_id, obj_inst_id);
		return -EINVAL;
	}

	obj->instance_count++;
	obj_inst->obj = obj;
	obj_inst->obj_inst_id = obj_inst_id;
	sprintf(obj_inst->path, "%u/%u", obj_id, obj_inst_id);
	for (i = 0; i < obj_inst->resource_count; i++) {
		sprintf(obj_inst->resources[i].path, "%u/%u/%u",
			obj_id, obj_inst_id, obj_inst->resources[i].res_id);
	}

	engine_register_obj_inst(obj_inst);
#ifdef CONFIG_LWM2M_RD_CLIENT_SUPPORT
	engine_trigger_update();
#endif
	return 0;
}

int engine_delete_obj_inst(u16_t obj_id, u16_t obj_inst_id)
{
	struct lwm2m_engine_obj *obj;
	struct lwm2m_engine_obj_inst *obj_inst;

	obj = get_engine_obj(obj_id);
	if (!obj) {
		return -ENOENT;
	}

	obj_inst = get_engine_obj_inst(obj_id, obj_inst_id);
	if (!obj_inst) {
		return -ENOENT;
	}

	engine_unregister_obj_inst(obj_inst);
	obj->instance_count--;
	if (obj->delete_cb) {
		return obj->delete_cb(obj_inst_id);
	}

	return 0;
}

/* utility functions */

static void engine_clear_context(struct lwm2m_engine_context *context)
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

static u16_t atou16(u8_t *buf, u16_t buflen, u16_t *len)
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

static void zoap_options_to_path(struct zoap_option *opt, int options_count,
				 struct lwm2m_obj_path *path)
{
	u16_t len;

	path->level = options_count;
	path->obj_id = atou16(opt[0].value, opt[0].len, &len);
	if (len == 0) {
		path->level = 0;
	}

	if (path->level > 1) {
		path->obj_inst_id = atou16(opt[1].value, opt[1].len, &len);
		if (len == 0) {
			path->level = 1;
		}
	}

	if (path->level > 2) {
		path->res_id = atou16(opt[2].value, opt[2].len, &len);
		if (len == 0) {
			path->level = 2;
		}
	}

	if (path->level > 3) {
		path->res_inst_id = atou16(opt[3].value, opt[3].len, &len);
		if (len == 0) {
			path->level = 3;
		}
	}
}

int zoap_init_message(struct net_context *net_ctx, struct zoap_packet *zpkt,
		      struct net_pkt **pkt, u8_t type, u8_t code, u16_t mid,
		      const u8_t *token, u8_t tkl, zoap_reply_t reply_cb)
{
	struct net_buf *frag;
	struct zoap_reply *reply = NULL;
	int r;

	*pkt = net_pkt_get_tx(net_ctx, K_FOREVER);
	if (!*pkt) {
		SYS_LOG_ERR("Unable to get TX packet, not enough memory.");
		return -ENOMEM;
	}

	frag = net_pkt_get_data(net_ctx, K_FOREVER);
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

u16_t lwm2m_engine_get_rd_data(u8_t *client_data, u16_t size)
{
	struct lwm2m_engine_obj_inst *obj_inst;
	u8_t temp[32];
	u16_t pos = 0;
	int len;

	SYS_SLIST_FOR_EACH_CONTAINER(&engine_obj_inst_list, obj_inst, node) {
		len = snprintf(temp, sizeof(temp), "%s</%s>",
			       (pos > 0) ? "," : "", obj_inst->path);
		/*
		 * TODO: iterate through resources once block transfer
		 * is handled correctly
		 */
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

/* input / output selection */

static u16_t select_writer(struct lwm2m_output_context *out, u16_t accept)
{
	switch (accept) {

	case LWM2M_FORMAT_PLAIN_TEXT:
	case LWM2M_FORMAT_OMA_PLAIN_TEXT:
		out->writer = &plain_text_writer;
		break;

#ifdef CONFIG_LWM2M_RW_JSON_SUPPORT
	case LWM2M_FORMAT_OMA_JSON:
	case LWM2M_FORMAT_OMA_OLD_JSON:
		out->writer = &json_writer;
		break;
#endif

#ifdef CONFIG_LWM2M_RW_OMA_TLV_SUPPORT
	case LWM2M_FORMAT_OMA_TLV:
	case LWM2M_FORMAT_OMA_OLD_TLV:
		out->writer = &oma_tlv_writer;
		break;
#endif

	default:
		SYS_LOG_ERR("Unknown Accept type %u, using LWM2M plain text",
			    accept);
		out->writer = &plain_text_writer;
		accept = LWM2M_FORMAT_OMA_PLAIN_TEXT;
		break;

	}

	return accept;
}

static u16_t select_reader(struct lwm2m_input_context *in, u16_t format)
{
	switch (format) {

	case LWM2M_FORMAT_OMA_PLAIN_TEXT:
		in->reader = &plain_text_reader;
		break;

#ifdef CONFIG_LWM2M_RW_OMA_TLV_SUPPORT
	case LWM2M_FORMAT_OMA_TLV:
	case LWM2M_FORMAT_OMA_OLD_TLV:
		in->reader = &oma_tlv_reader;
		break;
#endif

	default:
		SYS_LOG_ERR("Unknown content type %u, using LWM2M plain text",
			    format);
		in->reader = &plain_text_reader;
		format = LWM2M_FORMAT_OMA_PLAIN_TEXT;
		break;

	}

	return format;
}

/* check resource permission */
int check_perm(u16_t obj_id, u16_t res_id, u8_t perm)
{
	struct lwm2m_engine_obj *obj;
	struct lwm2m_engine_obj_field *obj_field;


	obj = get_engine_obj(obj_id);
	if (!obj) {
		return 0;
	}

	obj_field = get_engine_obj_field(obj, res_id);
	if (obj_field && ((obj_field->permissions & LWM2M_OP_BIT(perm)) ==
			  LWM2M_OP_BIT(perm))) {
		return 1;
	}

	return 0;
}

/* user data setter functions */

static int string_to_path(char *pathstr, struct lwm2m_obj_path *path,
			  char delim)
{
	u16_t value, len;
	int i, begin = -1, toklen;

	for (i = 0; i < strlen(pathstr); i++) {
		/* skip non-numeric */
		if (begin == -1 && pathstr[i] >= '0' && pathstr[i] <= '9') {
			begin = i;
		}

		/* match delim or end of string */
		if (begin >= 0 && (pathstr[i] == delim || i == (strlen(pathstr) - 1))) {
			if (pathstr[i] == delim) {
				toklen = i - begin;
			} else {
				toklen = i - begin + 1;
			}

			if (toklen > 0) {
				value = atou16(&pathstr[begin], toklen, &len);

				switch (path->level) {

				case 0:
					path->obj_id = value;
					break;

				case 1:
					path->obj_inst_id = value;
					break;

				case 2:
					path->res_id = value;
					break;

				case 3:
					path->res_inst_id = value;
					break;

				default:
					SYS_LOG_ERR("invalid level (%d)", path->level);
					return -EINVAL;

				}

				path->level++;
			}

			begin = -1;
		}
	}

	return 0;
}

static int lwm2m_engine_set(char *pathstr, void *value, u16_t len)
{
	int ret = 0, i;
	struct lwm2m_obj_path path;
	struct lwm2m_engine_obj_inst *obj_inst;
	struct lwm2m_engine_obj_field *obj_field;
	struct lwm2m_engine_res_inst *res = NULL;

	SYS_LOG_DBG("path:%s, value:%p, len:%d", pathstr, value, len);

	/* translate path -> path_obj */
	memset(&path, 0, sizeof(path));
	ret = string_to_path(pathstr, &path, '/');
	if (ret < 0) {
		return ret;
	}

	if (path.level < 3) {
		SYS_LOG_ERR("path must have 3 parts");
		return -EINVAL;
	}

	/* find obj_inst/res_id */
	obj_inst = get_engine_obj_inst(path.obj_id, path.obj_inst_id);
	if (!obj_inst) {
		SYS_LOG_ERR("obj instance %d/%d not found",
			    path.obj_id, path.obj_inst_id);
		return -ENOENT;
	}

	if (!obj_inst->resources || obj_inst->resource_count == 0) {
		SYS_LOG_ERR("obj instance has no resources");
		return -EINVAL;
	}

	obj_field = get_engine_obj_field(obj_inst->obj, path.res_id);
	if (!obj_field) {
		SYS_LOG_ERR("obj field %d not found", path.res_id);
		return -ENOENT;
	}

	for (i = 0; i < obj_inst->resource_count; i++) {
		if (obj_inst->resources[i].res_id == path.res_id) {
			res = &obj_inst->resources[i];
			break;
		}
	}

	if (!res) {
		SYS_LOG_ERR("res instance %d not found", path.res_id);
		return -ENOENT;
	}

	if (!res->data_ptr) {
		SYS_LOG_ERR("res data pointer is NULL");
		return -EINVAL;
	}

	/* check length (note: we add 1 to string length for NULL pad) */
	if (len > res->data_len -
		(obj_field->data_type == LWM2M_RES_TYPE_STRING ? 1 : 0)) {
		SYS_LOG_ERR("length %u is too long for resource %d data",
			    len, path.res_id);
		return -ENOMEM;
	}

	switch (obj_field->data_type) {

	case LWM2M_RES_TYPE_STRING:
		memcpy((u8_t *)res->data_ptr, value, len);
		((u8_t *)res->data_ptr)[len] = '\0';
		break;

	case LWM2M_RES_TYPE_U64:
		*((u64_t *)res->data_ptr) = *(u64_t *)value;
		break;

	case LWM2M_RES_TYPE_U32:
		*((u32_t *)res->data_ptr) = *(u32_t *)value;
		break;

	case LWM2M_RES_TYPE_U16:
		*((u16_t *)res->data_ptr) = *(u16_t *)value;
		break;

	case LWM2M_RES_TYPE_U8:
		*((u8_t *)res->data_ptr) = *(u8_t *)value;
		break;

	case LWM2M_RES_TYPE_S64:
		*((s64_t *)res->data_ptr) = *(s64_t *)value;
		break;

	case LWM2M_RES_TYPE_S32:
		*((s32_t *)res->data_ptr) = *(s32_t *)value;
		break;

	case LWM2M_RES_TYPE_S16:
		*((s16_t *)res->data_ptr) = *(s16_t *)value;
		break;

	case LWM2M_RES_TYPE_S8:
		*((s8_t *)res->data_ptr) = *(s8_t *)value;
		break;

	case LWM2M_RES_TYPE_BOOL:
		*((bool *)res->data_ptr) = *(bool *)value;
		break;

	case LWM2M_RES_TYPE_FLOAT32:
		/* TODO: */
		break;

	case LWM2M_RES_TYPE_TIME:
		break;

	}

	/* notify */

	return ret;
}

int lwm2m_engine_set_string(char *pathstr, char *data_ptr)
{
	return lwm2m_engine_set(pathstr, data_ptr, strlen(data_ptr));
}

int lwm2m_engine_set_u8(char *pathstr, u8_t value)
{
	return lwm2m_engine_set(pathstr, &value, 1);
}

int lwm2m_engine_set_u16(char *pathstr, u16_t value)
{
	return lwm2m_engine_set(pathstr, &value, 2);
}

int lwm2m_engine_set_u32(char *pathstr, u32_t value)
{
	return lwm2m_engine_set(pathstr, &value, 4);
}

int lwm2m_engine_set_u64(char *pathstr, u64_t value)
{
	return lwm2m_engine_set(pathstr, &value, 8);
}

int lwm2m_engine_set_s8(char *pathstr, s8_t value)
{
	return lwm2m_engine_set(pathstr, &value, 1);
}

int lwm2m_engine_set_s16(char *pathstr, s16_t value)
{
	return lwm2m_engine_set(pathstr, &value, 2);
}

int lwm2m_engine_set_s32(char *pathstr, s32_t value)
{
	return lwm2m_engine_set(pathstr, &value, 4);
}

int lwm2m_engine_set_s64(char *pathstr, s64_t value)
{
	return lwm2m_engine_set(pathstr, &value, 8);
}

int lwm2m_engine_set_bool(char *pathstr, bool value)
{
	u8_t temp = (value != 0);
	return lwm2m_engine_set(pathstr, &temp, 1);
}

/* user data getter functions */

static int lwm2m_engine_get(char *path, void *buf, u16_t buflen)
{
/* translate path -> path_obj */
/* find obj_inst/res_id */
	SYS_LOG_DBG("path:%s, buf:%p, buflen:%d", path, buf, buflen);
	return 0;
}

int lwm2m_engine_get_string(char *path, void *str, u16_t strlen)
{
	return lwm2m_engine_get(path, str, strlen);
}

u8_t lwm2m_engine_get_u8(char *path)
{
	u8_t value = 0;
	lwm2m_engine_get(path, &value, 1);
	return value;
}

u16_t lwm2m_engine_get_u16(char *path)
{
	u16_t value = 0;
	lwm2m_engine_get(path, &value, 2);
	return value;
}

u32_t lwm2m_engine_get_u32(char *path)
{
	u32_t value = 0;
	lwm2m_engine_get(path, &value, 4);
	return value;
}

u64_t lwm2m_engine_get_u64(char *path)
{
	u64_t value = 0;
	lwm2m_engine_get(path, &value, 8);
	return value;
}

s8_t lwm2m_engine_get_s8(char *path)
{
	s8_t value = 0;
	lwm2m_engine_get(path, &value, 1);
	return value;
}

s16_t lwm2m_engine_get_s16(char *path)
{
	s16_t value = 0;
	lwm2m_engine_get(path, &value, 2);
	return value;
}

s32_t lwm2m_engine_get_s32(char *path)
{
	s32_t value = 0;
	lwm2m_engine_get(path, &value, 4);
	return value;
}

s64_t lwm2m_engine_get_s64(char *path)
{
	s64_t value = 0;
	lwm2m_engine_get(path, &value, 8);
	return value;
}

bool lwm2m_engine_get_bool(char *path)
{
	return (lwm2m_engine_get_s8(path) != 0);
}

/* user callback functions */
static int engine_get_resource(struct lwm2m_obj_path *path,
			       struct lwm2m_engine_res_inst **res)
{
	int i;
	struct lwm2m_engine_obj_inst *obj_inst;

	if (!path) {
		return -EINVAL;
	}

	/* find obj_inst/res_id */
	obj_inst = get_engine_obj_inst(path->obj_id, path->obj_inst_id);
	if (!obj_inst) {
		SYS_LOG_ERR("obj instance %d/%d not found",
			    path->obj_id, path->obj_inst_id);
		return -ENOENT;
	}

	if (!obj_inst->resources || obj_inst->resource_count == 0) {
		SYS_LOG_ERR("obj instance has no resources");
		return -EINVAL;
	}

	for (i = 0; i < obj_inst->resource_count; i++) {
		if (obj_inst->resources[i].res_id == path->res_id) {
			*res = &obj_inst->resources[i];
			break;
		}
	}

	if (!*res) {
		SYS_LOG_ERR("res instance %d not found", path->res_id);
		return -ENOENT;
	}

	return 0;
}

static int engine_get_resource_from_pathstr(char *pathstr,
			       struct lwm2m_engine_res_inst **res)
{
	int ret;
	struct lwm2m_obj_path path;

	memset(&path, 0, sizeof(path));
	ret = string_to_path(pathstr, &path, '/');
	if (ret < 0) {
		return ret;
	}

	if (path.level < 3) {
		SYS_LOG_ERR("path must have 3 parts");
		return -EINVAL;
	}

	return engine_get_resource(&path, res);
}

int lwm2m_engine_register_read_callback(char *pathstr,
					lwm2m_engine_rw_cb_t cb)
{
	int ret;
	struct lwm2m_engine_res_inst *res = NULL;

	ret = engine_get_resource_from_pathstr(pathstr, &res);
	if (ret < 0) {
		return ret;
	}

	res->read_cb = cb;
	return 0;
}

int lwm2m_engine_register_write_callback(char *pathstr,
					 lwm2m_engine_rw_cb_t cb)
{
	int ret;
	struct lwm2m_engine_res_inst *res = NULL;

	ret = engine_get_resource_from_pathstr(pathstr, &res);
	if (ret < 0) {
		return ret;
	}

	res->write_cb = cb;
	return 0;
}

int lwm2m_engine_register_exec_callback(char *pathstr,
					lwm2m_engine_exec_cb_t cb)
{
	int ret;
	struct lwm2m_engine_res_inst *res = NULL;

	ret = engine_get_resource_from_pathstr(pathstr, &res);
	if (ret < 0) {
		return ret;
	}

	res->execute_cb = cb;
	return 0;
}

/* generic data handlers */

int engine_read_handler(struct lwm2m_engine_obj_inst *obj_inst,
			struct lwm2m_engine_res_inst *res,
			struct lwm2m_engine_obj_field *obj_field,
			struct lwm2m_engine_context *context)
{
	struct lwm2m_output_context *out = context->out;
	struct lwm2m_obj_path *path = context->path;
	int i, loop_max = 1;
	u16_t res_inst_id_tmp = 0;

	if (!obj_inst || !res || !obj_field || !context) {
		return -EINVAL;
	}

	SYS_LOG_DBG("<< READ [path:%s, id:%d]",
		res->path, res->res_id);

	if (res->read_cb &&
	    res->read_cb(obj_inst->obj_inst_id, res->data_ptr,
			 res->data_len, false, 0)) {
		return 0;
	}

	if (res->multi_count_var != NULL) {
		engine_put_begin_ri(out, path);
		loop_max = *res->multi_count_var;
		res_inst_id_tmp = path->res_inst_id;
	}

	for (i = 0; i < loop_max; i++) {
		if (res->multi_count_var != NULL) {
			path->res_inst_id = (u16_t) i;
		}

		switch (obj_field->data_type) {

		/* TODO: handle multi count for string? */
		case LWM2M_RES_TYPE_STRING:
			engine_put_string(out, path, (u8_t *)res->data_ptr,
					  strlen((u8_t *)res->data_ptr));
			break;

		case LWM2M_RES_TYPE_U64:
			engine_put_int64(out, path,
					 ((u64_t *)res->data_ptr)[i]);
			break;

		case LWM2M_RES_TYPE_U32:
			engine_put_int32(out, path,
					 ((u32_t *)res->data_ptr)[i]);
			break;

		case LWM2M_RES_TYPE_U16:
			engine_put_int32(out, path,
					 (s32_t)((u16_t *)res->data_ptr)[i]);
			break;

		case LWM2M_RES_TYPE_U8:
			engine_put_int32(out, path,
					 (s32_t)((u8_t *)res->data_ptr)[i]);
			break;

		case LWM2M_RES_TYPE_S64:
			engine_put_int64(out, path,
					 ((s64_t *)res->data_ptr)[i]);
			break;

		case LWM2M_RES_TYPE_S32:
			engine_put_int32(out, path,
					 ((s32_t *)res->data_ptr)[i]);
			break;

		case LWM2M_RES_TYPE_S16:
			engine_put_int32(out, path,
					 (s32_t)((s16_t *)res->data_ptr)[i]);
			break;

		case LWM2M_RES_TYPE_S8:
			engine_put_int32(out, path,
					 (s32_t)((s8_t *)res->data_ptr)[i]);
			break;

		case LWM2M_RES_TYPE_BOOL:
			engine_put_int32(out, path,
					 (s32_t)((bool *)res->data_ptr)[i]);
			break;

		case LWM2M_RES_TYPE_FLOAT32:
			/* TODO: */
			break;

		case LWM2M_RES_TYPE_TIME:
			engine_put_int32(out, path,
					 ((u32_t *)res->data_ptr)[i]);
			break;

		}
	}

	if (res->multi_count_var != NULL) {
		engine_put_end_ri(out, path);
		path->res_inst_id = res_inst_id_tmp;
	}

	return 0;
}

int engine_write_handler(struct lwm2m_engine_obj_inst *obj_inst,
			 struct lwm2m_engine_res_inst *res,
			 struct lwm2m_engine_obj_field *obj_field,
			 struct lwm2m_engine_context *context)
{
	struct lwm2m_input_context *in = context->in;
	struct lwm2m_obj_path *path = context->path;

	if (!obj_inst || !res || !obj_field || !context) {
		return -EINVAL;
	}

	SYS_LOG_DBG(">> WRITE [path:%s, id:%d]",
		res->path, res->res_id);

	if (res->write_cb &&
	    res->write_cb(obj_inst->obj_inst_id, res->data_ptr, res->data_len,
			  false, 0)) {
		return 0;
	}

	switch (obj_field->data_type) {

	case LWM2M_RES_TYPE_STRING:
//		engine_get_string(out, path, (u8_t *)res->data_ptr,
//				  strlen((u8_t *)res->data_ptr));
		break;

	}

	return 0;
}

int engine_write_attr_handler(struct lwm2m_engine_obj_inst *obj_inst,
			      struct lwm2m_engine_context *context)
{
	if (!obj_inst || !context) {
		return -EINVAL;
	}

	return 0;
}

int engine_exec_handler(struct lwm2m_engine_obj_inst *obj_inst,
			struct lwm2m_engine_context *context)
{
	struct lwm2m_obj_path *path = context->path;
	struct lwm2m_engine_res_inst *res = NULL;
	int ret;

	if (!obj_inst || !context) {
		return -EINVAL;
	}

	ret = engine_get_resource(path, &res);
	if (ret < 0) {
		return ret;
	}

	SYS_LOG_DBG(">> EXEC [path:%s, id:%d]",
		res->path, res->res_id);

	if (res->execute_cb) {
		res->execute_cb(obj_inst->obj_inst_id);
		return 0;
	}

	/* TODO: something else to handle for execute? */
	return -ENOENT;
}

int engine_create_handler(struct lwm2m_engine_obj *obj,
			  struct lwm2m_engine_context *context)
{
	if (!obj || !context) {
		return -EINVAL;
	}

	return 0;
}

int engine_delete_handler(struct lwm2m_engine_obj_inst *obj_inst,
			  struct lwm2m_engine_context *context)
{
	if (!obj_inst || !context) {
		return -EINVAL;
	}

	return 0;
}

#define MATCH_NONE	0
#define MATCH_ALL	1
#define MATCH_SINGLE	2

static int do_read_op(struct lwm2m_engine_obj_inst *obj_inst,
		      struct lwm2m_engine_context *context)
{
	struct lwm2m_output_context *out = context->out;
	struct lwm2m_obj_path *path = context->path;
	int pos = 0, index = 0;
	u8_t num_read = 0;
	u8_t initialized;
	int ret = 0, match_type;
	struct lwm2m_engine_res_inst *res;
	struct lwm2m_engine_obj_field *obj_field;
	u16_t temp_res_id;

	while (obj_inst) {
		initialized = 0;
		match_type = MATCH_NONE;

		/* check obj_inst path for at least partial match */
		if (path->obj_id == obj_inst->obj->obj_id &&
		    path->obj_inst_id == obj_inst->obj_inst_id) {
			if (path->level > 2) {
				match_type = MATCH_SINGLE;
			} else {
				match_type = MATCH_ALL;
			}
		}

		temp_res_id = path->res_id;

		/* if exact match on obj_inst path, then read all resources */
		/* if not then read only matching resources */

		if (match_type > MATCH_NONE && obj_inst->resources &&
				obj_inst->resource_count > 0) {
			while (index < obj_inst->resource_count) {
				res = &obj_inst->resources[index];
				if (match_type == MATCH_SINGLE &&
				    path->res_id != res->res_id) {
					index++;
					continue;
				}

				if (match_type == MATCH_ALL) {
					path->res_id = res->res_id;
				}

				obj_field = get_engine_obj_field(obj_inst->obj,
								 res->res_id);
				if (!obj_field) {
					ret = -ENOENT;
				} else if ((obj_field->permissions &
					    LWM2M_PERM_R) != LWM2M_PERM_R) {
					ret = -EPERM;
				} else {
					if (!initialized) {
						/*
						 * ZoAP API needs to create the
						 * net_pkt buffer in the correct
						 * order: we need to make sure
						 * out->outbuf has been
						 * initialized here.
						 */
						if (!out->outbuf) {
							out->outbuf =
							zoap_packet_get_payload(
								out->out_zpkt,
								&out->outsize);
						}

						engine_put_begin(out, path);
						initialized = 1;
					}

					ret = engine_read_handler(obj_inst, res,
								  obj_field,
								  context);
					if (ret < 0) {
						/* What to do here? */
						SYS_LOG_ERR("READ OP failed: "
							    "%d", ret);
					} else {
						num_read += 1;
						pos = out->outlen;
					}
				}

				/* on single read break if errors */
				if (ret < 0 && match_type == MATCH_SINGLE) {
					break;
				}

				/* reset return code */
				ret = 0;

				index++;
			}
		}

		path->res_id = temp_res_id;
		obj_inst = next_engine_obj_inst(obj_inst, path->obj_id,
						path->obj_inst_id);
		if (initialized) {
			engine_put_end(out, path);
			pos = out->outlen;
		}
	}

	/* did not read anything even if we should have - on single item */
	if (ret == 0 && num_read == 0 && path->level == 3) {
		return -ENOENT;
	}

	out->outlen = pos;
	return ret;
}

static int do_discover_op(struct lwm2m_engine_context *context)
{
	struct lwm2m_output_context *out = context->out;
	struct lwm2m_engine_obj_inst *obj_inst;
	int i = 0;

	/* set output content-format */
	zoap_add_option_int(out->out_zpkt,
			    ZOAP_OPTION_CONTENT_FORMAT,
			    LWM2M_FORMAT_APP_LINK_FORMAT);

	/* init the outbuffer */
	out->outbuf = zoap_packet_get_payload(out->out_zpkt,
					      &out->outsize);

	/* </.well-known/core>,**;ct=40 */
	memcpy(out->outbuf, DISCOVER_PREFACE, strlen(DISCOVER_PREFACE));
	out->outlen += strlen(DISCOVER_PREFACE);

	SYS_SLIST_FOR_EACH_CONTAINER(&engine_obj_inst_list, obj_inst, node) {
		/* avoid discovery for security and server objects */
		if (obj_inst->obj->obj_id <= LWM2M_OBJECT_SERVER_ID) {
			continue;
		}

		out->outlen += sprintf(&out->outbuf[out->outlen], ",</%u/%u>",
				       obj_inst->obj->obj_id,
				       obj_inst->obj_inst_id);

		for (i = 0; i < obj_inst->resource_count; i++) {
			out->outlen += sprintf(&out->outbuf[out->outlen],
					       ",</%u/%u/%u>",
					       obj_inst->obj->obj_id,
					       obj_inst->obj_inst_id,
					       obj_inst->resources[i].res_id);
		}
	}

	out->outbuf[out->outlen] = '\0';
	return 0;
}

int get_or_create_engine_obj(struct lwm2m_engine_context *context,
			     struct lwm2m_engine_obj_inst *obj_inst,
			     u8_t *created)
{
	struct lwm2m_obj_path *path = context->path;
	int ret = 0;

	if (created) {
		*created = 0;
	}

	obj_inst = get_engine_obj_inst(path->obj_id, path->obj_inst_id);
	if (!obj_inst) {
		ret = engine_create_obj_inst(path->obj_id, path->obj_inst_id,
					     obj_inst);
		if (ret < 0) {
			return ret;
		}

		zoap_header_set_code(context->in->in_zpkt,
				     ZOAP_RESPONSE_CODE_CREATED);
		/* set created flag to one */
		if (created) {
			*created = 1;
		}
	}

	return ret;
}

static int do_write_op(struct lwm2m_engine_obj_inst *obj_inst,
		       struct lwm2m_engine_context *context,
		       u16_t format)
{
	u8_t created = 0;
	int ret, i;
	struct lwm2m_engine_obj_field *obj_field;
	struct lwm2m_engine_res_inst *res = NULL;

	ret = get_or_create_engine_obj(context, obj_inst, &created);
	if (ret < 0) {
		return ret;
	}

	obj_field = get_engine_obj_field(obj_inst->obj,
					 context->path->res_id);
	if (!obj_field) {
		return -EINVAL;
	}

	if ((obj_field->permissions & LWM2M_OP_BIT(LWM2M_OP_WRITE)) !=
	    LWM2M_OP_BIT(LWM2M_OP_WRITE)) {
		return -EPERM;
	}

	if (!obj_inst->resources || obj_inst->resource_count == 0) {
		return -EINVAL;
	}

	for (i = 0; i < obj_inst->resource_count; i++) {
		if (obj_inst->resources[i].res_id == context->path->res_id) {
			res = &obj_inst->resources[i];
			break;
		}
	}

	if (!res) {
		return -ENOENT;
	}

	switch (format) {

	case LWM2M_FORMAT_PLAIN_TEXT:
	case LWM2M_FORMAT_OMA_PLAIN_TEXT:
		context->path->level = 3;
		context->in->inpos = 0;
		return engine_write_handler(obj_inst, res, obj_field, context);

#ifdef CONFIG_LWM2M_RW_JSON_SUPPORT
	case LWM2M_FORMAT_OMA_JSON:
	case LWM2M_FORMAT_OMA_OLD_JSON:
		return do_write_op_json(obj_inst, res, obj_field, context);
#endif

#ifdef CONFIG_LWM2M_RW_OMA_TLV_SUPPORT
	case LWM2M_FORMAT_OMA_TLV:
	case LWM2M_FORMAT_OMA_OLD_TLV:
		return do_write_op_tlv(obj_inst, context);
#endif

	default:
		SYS_LOG_ERR("Unsupported format: %u", format);
		return -EINVAL;

	}
}

static int get_observe_option(const struct zoap_packet *zpkt)
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

static int handle_request(struct zoap_packet *request,
			  struct zoap_packet *response,
			  struct sockaddr *from_addr)
{
	int r;
	u8_t code;
	struct zoap_option options[4];
	struct lwm2m_engine_obj *obj;
	struct lwm2m_engine_obj_inst *obj_inst = NULL;
	const u8_t *token;
	u8_t tkl = 0;
	u16_t format, accept;
	struct lwm2m_input_context in;
	struct lwm2m_output_context out;
	struct lwm2m_obj_path path;
	struct lwm2m_engine_context context;
	int observe = -1; /* default to -1, 0 = ENABLE, 1 = DISABLE */
	bool discover = false;

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
	r = zoap_find_options(in.in_zpkt, ZOAP_OPTION_URI_PATH, options, 4);
	if (r > 0) {
		/* check for .well-known/core URI query (DISCOVER) */
		if (r == 2 &&
		    (options[0].len == 11 &&
		     strncmp(options[0].value,".well-known", 11) == 0) &&
		    (options[1].len == 4 &&
		     strncmp(options[1].value,"core", 4) == 0)) {
			discover = true;
		} else {
			zoap_options_to_path(options, r, &path);
		}
	}

	/* read Content Format */
	r = zoap_find_options(in.in_zpkt, ZOAP_OPTION_CONTENT_FORMAT,
			      options, 1);
	if (r > 0) {
		format = zoap_option_value_to_int(&options[0]);
	} else {
		SYS_LOG_DBG("No content-format given. Assume text plain.");
		format = LWM2M_FORMAT_OMA_PLAIN_TEXT;
	}

	/* read Accept */
	r = zoap_find_options(in.in_zpkt, ZOAP_OPTION_ACCEPT, options, 1);
	if (r > 0) {
		accept = zoap_option_value_to_int(&options[0]);
	} else {
		SYS_LOG_DBG("No Accept header: use same as content-format(%d)",
			    format);
		accept = format;
	}

	/* TODO: Handle bootstrap deleted -- re-add when DTLS support ready */

	code = zoap_header_get_code(in.in_zpkt);

	/* find registered obj */
	obj = get_engine_obj(path.obj_id);
	if (!obj) {
		/* No matching object found - ignore request */
		return -ENOENT;
	}

	if (path.level > 1) {
		obj_inst = get_engine_obj_inst(path.obj_id, path.obj_inst_id);
	}

	format = select_reader(&in, format);
	accept = select_writer(&out, accept);

	/* set the operation */
	switch (code & ZOAP_REQUEST_MASK) {

	case ZOAP_METHOD_GET:
		if (discover || format == LWM2M_FORMAT_APP_LINK_FORMAT) {
			context.operation = LWM2M_OP_DISCOVER;
			accept = LWM2M_FORMAT_APP_LINK_FORMAT;
		} else {
			context.operation = LWM2M_OP_READ;
		}
		/* check for observe */
		observe = get_observe_option(in.in_zpkt);
		zoap_header_set_code(out.out_zpkt, ZOAP_RESPONSE_CODE_CONTENT);
		break;

	case ZOAP_METHOD_POST:
		if (path.level < 2) {
			/* write to a object instance */
			context.operation = LWM2M_OP_WRITE;
		} else {
			context.operation = LWM2M_OP_EXECUTE;
		}
		zoap_header_set_code(out.out_zpkt, ZOAP_RESPONSE_CODE_CHANGED);
		break;

	case ZOAP_METHOD_PUT:
		context.operation = LWM2M_OP_WRITE;
		zoap_header_set_code(out.out_zpkt, ZOAP_RESPONSE_CODE_CHANGED);
		break;

	case ZOAP_METHOD_DELETE:
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

	case LWM2M_OP_READ:
		if (observe == 0) {
			/* add new observer */
			if (token) {
				r = zoap_add_option_int(out.out_zpkt,
							ZOAP_OPTION_OBSERVE, 1);
				if (r) {
					SYS_LOG_ERR("OBSERVE option error: %d",
						    r);
				}

				r = engine_add_observer(
					net_pkt_context(in.in_zpkt->pkt),
					from_addr, token, tkl, &path);
				if (r < 0) {
					SYS_LOG_ERR("add OBSERVE error: %d", r);
				}
			} else {
				SYS_LOG_ERR("OBSERVE request missing token");
			}
		} else if (observe == 1) {
			/* use token from this request */
			token = zoap_header_get_token(in.in_zpkt, &tkl);
			/* remove observer */
			r = engine_remove_observer(token, tkl);
			if (r < 0) {
				SYS_LOG_ERR("remove obserer error: %d", r);
			}
		}

		/* set output content-format */
		r = zoap_add_option_int(out.out_zpkt,
					ZOAP_OPTION_CONTENT_FORMAT, accept);
		if (r > 0) {
			SYS_LOG_ERR("Error setting response content-format: %d",
				    r);
		}

		if (obj_inst) {
			r = do_read_op(obj_inst, &context);
		} else {
			r = -ENOENT;
		}
		break;

	case LWM2M_OP_DISCOVER:
		r = do_discover_op(&context);
		break;

	case LWM2M_OP_WRITE:
		if (obj_inst) {
			r = do_write_op(obj_inst, &context, format);
		} else {
			r = -ENOENT;
		}
		break;

	case LWM2M_OP_WRITE_ATTR:
		if (obj_inst) {
			r = engine_write_attr_handler(obj_inst, &context);
		} else {
			r = -ENOENT;
		}
		break;

	case LWM2M_OP_EXECUTE:
		if (obj_inst) {
			r = engine_exec_handler(obj_inst, &context);
		} else {
			r = -ENOENT;
		}
		break;

	case LWM2M_OP_CREATE:
		r = engine_create_handler(obj, &context);
		break;

	case LWM2M_OP_DELETE:
		if (obj_inst) {
			r = engine_delete_handler(obj_inst, &context);
		} else {
			r = -ENOENT;
		}
		break;

	default:
		SYS_LOG_ERR("Unknown operation: %u", context.operation);
		return -EINVAL;
	}

	if (r == 0) {
		/* TODO: Handle blockwise 1 */

		if (out.outlen > 0) {
			SYS_LOG_DBG("replying with %u bytes", out.outlen);
			zoap_packet_set_used(out.out_zpkt, out.outlen);
		} else {
			SYS_LOG_DBG("no data in reply");
		}
	} else {
		if (r == -ENOENT) {
			zoap_header_set_code(out.out_zpkt,
					     ZOAP_RESPONSE_CODE_NOT_FOUND);
			r = 0;
		} else if (r == -EPERM) {
			zoap_header_set_code(out.out_zpkt,
					     ZOAP_RESPONSE_CODE_NOT_ALLOWED);
			r = 0;
		} else {
			/* Failed to handle the request */
			zoap_header_set_code(out.out_zpkt,
					     ZOAP_RESPONSE_CODE_INTERNAL_ERROR);
			r = 0;
		}
	}

	return r;
}

static void udp_receive(struct net_context *ctx, struct net_pkt *pkt,
			int status, void *user_data)
{
	struct zoap_pending *pending;
	struct zoap_reply *reply;
	struct zoap_packet response;
	struct sockaddr from_addr;
	struct zoap_packet response2;
	struct net_pkt *pkt2;
	int header_len, r;
	const u8_t *token;
	u8_t tkl;

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
	pending = zoap_pending_received(&response, pendings, NUM_PENDINGS);
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
			r = zoap_init_message(ctx, &response2, &pkt2,
					      ZOAP_TYPE_ACK,
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
			r = handle_request(&response, &response2, &from_addr);
			if (r < 0) {
				SYS_LOG_ERR("Request handler error: %d", r);
			} else {
				r = net_context_sendto(pkt2, &from_addr,
						       NET_SOCKADDR_MAX_SIZE,
						       NULL, K_NO_WAIT, NULL,
						       NULL);
				if (r < 0) {
					SYS_LOG_ERR("Err sending response: %d",
						    r);
				}
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

static int notify_message_reply_cb(const struct zoap_packet *response,
				   struct zoap_reply *reply,
				   const struct sockaddr *from)
{
	int ret = 0;
	u8_t type, code;

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
	struct zoap_packet request;
	struct lwm2m_engine_obj_inst *obj_inst;
	struct lwm2m_output_context out;
	struct lwm2m_engine_context context;
	int ret = 0;

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

	obj_inst = get_engine_obj_inst(observer->path.obj_id,
				       observer->path.obj_inst_id);
	if (!obj_inst) {
		SYS_LOG_ERR("unable to get engine obj for %u/%u",
			    observer->path.obj_id,
			    observer->path.obj_inst_id);
		return -EINVAL;
	}

	ret = zoap_init_message(observer->net_ctx, out.out_zpkt, &pkt,
				ZOAP_TYPE_CON, ZOAP_RESPONSE_CODE_CONTENT,
				0, observer->token, observer->tkl,
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
	select_writer(&out, LWM2M_FORMAT_OMA_TLV);

	/* set response content-format */
	ret = zoap_add_option_int(out.out_zpkt, ZOAP_OPTION_CONTENT_FORMAT,
				  LWM2M_FORMAT_OMA_TLV);
	if (ret > 0) {
		SYS_LOG_ERR("error setting content-format (err:%d)", ret);
		goto cleanup;
	}

	ret = do_read_op(obj_inst, &context);
	if (ret == 0) {
		if (out.outlen > 0) {
			zoap_packet_set_used(out.out_zpkt, out.outlen);
		} else {
			SYS_LOG_DBG("no data in reply");
		}
	} else {
		SYS_LOG_ERR("error in multi-format read (err:%d)", ret);
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

	ret = net_context_sendto(pkt, &observer->addr, NET_SOCKADDR_MAX_SIZE,
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
static void lwm2m_engine_service(void)
{
	struct observe_node *obs;
	s64_t timestamp = k_uptime_get();

	while (true) {
		/*
		 * 1. scan the observer list
		 * 2. For each notify event found, scan the observer list
		 * 3. For each observer match, generate a NOTIFY message,
		 *    attaching the notify response handler
		 */
		SYS_SLIST_FOR_EACH_CONTAINER(&engine_observer_list, obs, node) {
			/*
			 * manual notify requirements:
			 * - event_timestamp > last_timestamp
			 * - current timestamp > last_timestamp + min_period_sec
			 */
			if (obs->event_timestamp > obs->last_timestamp &&
			    timestamp > obs->last_timestamp +
					(obs->min_period_sec * MSEC_PER_SEC)) {
				obs->last_timestamp = k_uptime_get();
				generate_notify_message(obs, true);

			/*
			 * automatic time-based notify requirements:
			 * - current timestamp > last_timestamp + max_period_sec
			 */
			} else if (timestamp > obs->last_timestamp +
					(obs->max_period_sec * MSEC_PER_SEC)) {
				obs->last_timestamp = k_uptime_get();
				generate_notify_message(obs, false);
			}

		}

		k_sleep(K_MSEC(ENGINE_UPDATE_INTERVAL));
	}
}

int lwm2m_engine_start(struct net_context *net_ctx)
{
	int ret = 0;

	/* set callback */
	ret = net_context_recv(net_ctx, udp_receive, 0, NULL);
	if (ret) {
		SYS_LOG_ERR("Could not set receive for net context (err:%d)",
			    ret);
	}

	return ret;
}

static int lwm2m_engine_init(struct device *dev)
{
	/* start thread to handle OBSERVER / NOTIFY events */
	k_thread_create(&engine_thread_data,
			&engine_thread_stack[0],
			CONFIG_LWM2M_ENGINE_STACK_SIZE,
			(k_thread_entry_t) lwm2m_engine_service,
			NULL, NULL, NULL, K_PRIO_COOP(7), 0, K_NO_WAIT);
	k_delayed_work_init(&retransmit_work, retransmit_request);
	SYS_LOG_DBG("LWM2M engine thread started");
	return 0;
}

SYS_INIT(lwm2m_engine_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
