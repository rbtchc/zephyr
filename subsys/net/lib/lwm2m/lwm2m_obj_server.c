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
 */

/*
 * TODO:
 * - Add getter / setter methods for client and engine use
 */

#define SYS_LOG_DOMAIN "lwm2m_obj_server"
#define SYS_LOG_LEVEL CONFIG_SYS_LOG_LWM2M_LEVEL
#include <logging/sys_log.h>
#include <stdint.h>
#include <init.h>
#include <net/lwm2m.h>

#include "lwm2m_object.h"
#include "lwm2m_engine.h"

/* Server resource IDs */
#define LWM2M_SERVER_SHORT_SERVER_ID		0
#define LWM2M_SERVER_LIFETIME_ID		1
#define LWM2M_SERVER_DEFAULT_MIN_PERIOD_ID	2
#define LWM2M_SERVER_DEFAULT_MAX_PERIOD_ID	3
#define LWM2M_SERVER_DISABLE_ID			4
#define LWM2M_SERVER_DISABLE_TIMEOUT_ID		5
#define LWM2M_SERVER_STORE_NOTIFY_ID		6
#define LWM2M_SERVER_TRANSPORT_BINDING_ID	7
#define LWM2M_SERVER_REG_UPDATE_TRIGGER_ID	8

/* Server flags */
#define SERVER_FLAG_DISABLED		1
#define SERVER_FLAG_STORE_NOTIFY	2

#define MAX_INSTANCE_COUNT		CONFIG_LWM2M_SERVER_INSTANCE_COUNT
#define TRANSPORT_BINDING_LEN		4

struct lwm2m_server_data {
	struct lwm2m_engine_obj eng_obj;
	u8_t  flags;
	u16_t server_id;
	u32_t lifetime;
	u32_t default_min_period;
	u32_t default_max_period;
	u32_t disabled_timeout;
	u8_t  transport_binding[TRANSPORT_BINDING_LEN];
};

static const u32_t resources[] = {
	RO(LWM2M_SERVER_SHORT_SERVER_ID),
	RW(LWM2M_SERVER_LIFETIME_ID),
	RW(LWM2M_SERVER_DEFAULT_MIN_PERIOD_ID),
	RW(LWM2M_SERVER_DEFAULT_MAX_PERIOD_ID),
	EX(LWM2M_SERVER_DISABLE_ID),
	RW(LWM2M_SERVER_DISABLE_TIMEOUT_ID),
	RW(LWM2M_SERVER_STORE_NOTIFY_ID),
	/* Mark Transport Binding RO as we only support UDP atm */
	RO(LWM2M_SERVER_TRANSPORT_BINDING_ID),
	EX(LWM2M_SERVER_REG_UPDATE_TRIGGER_ID)
};

static struct lwm2m_server_data instances[MAX_INSTANCE_COUNT];

static enum lwm2m_status
server_op_callback(struct lwm2m_engine_obj *obj,
		   struct lwm2m_engine_context *context);

static int server_create(u16_t obj_inst_id)
{
	int i;

	/* Check that there is no other instance with this ID */
	for (i = 0; i < MAX_INSTANCE_COUNT; i++) {
		if (instances[i].eng_obj.op_callback &&
		    instances[i].eng_obj.obj_inst_id == obj_inst_id) {
			SYS_LOG_ERR("Can not create instance - "
				    "already exists: %d", obj_inst_id);
			return 0;
		}
	}

	for (i = 0; i < MAX_INSTANCE_COUNT; i++) {
		/* Not used if OP callback is non-existend */
		if (!instances[i].eng_obj.op_callback) {
			instances[i].eng_obj.obj_id = LWM2M_OBJECT_SERVER_ID;
			instances[i].eng_obj.obj_inst_id = obj_inst_id;
			instances[i].eng_obj.rsc_ids = resources;
			instances[i].eng_obj.rsc_count =
				sizeof(resources) / sizeof(u32_t);
			instances[i].eng_obj.op_callback = server_op_callback;
			/* Set default values */
			instances[i].flags = 0;
			instances[i].server_id = i + 1;
			instances[i].lifetime =
					CONFIG_LWM2M_ENGINE_DEFAULT_LIFETIME;
			instances[i].default_min_period = 0;
			instances[i].default_max_period = 0;
			instances[i].disabled_timeout = 86400;
			strcpy(instances[i].transport_binding, "U");
			engine_add_object(
				(struct lwm2m_engine_obj *)&instances[i]);
			SYS_LOG_DBG("Create new server instance: %u",
				    obj_inst_id);
			return 1;
		}
	}

	return 0;
}

static enum lwm2m_status
server_op_callback(struct lwm2m_engine_obj *obj,
		   struct lwm2m_engine_context *context)
{
	struct lwm2m_input_context *in = context->in;
	struct lwm2m_output_context *out = context->out;
	struct lwm2m_obj_path *path = context->path;
	struct lwm2m_server_data *server;
	int temp;

	if (!path) {
		return LWM2M_STATUS_ERROR;
	}

	SYS_LOG_DBG("Got request at: %u/%u/%u lv:%u", path->obj_id,
		    path->obj_inst_id, path->res_id, path->level);
	server = (struct lwm2m_server_data *)obj;

	switch (context->operation) {

	case LWM2M_OP_READ:
		switch (path->res_id) {

		case LWM2M_SERVER_SHORT_SERVER_ID:
			engine_write_int32(out, path, server->server_id);
			break;

		case LWM2M_SERVER_LIFETIME_ID:
			engine_write_int32(out, path, server->lifetime);
			break;

		case LWM2M_SERVER_DEFAULT_MIN_PERIOD_ID:
			engine_write_int32(out, path,
					   server->default_min_period);
			break;

		case LWM2M_SERVER_DEFAULT_MAX_PERIOD_ID:
			engine_write_int32(out, path,
					   server->default_max_period);
			break;

		case LWM2M_SERVER_DISABLE_TIMEOUT_ID:
			engine_write_int32(out, path, server->disabled_timeout);
			break;

		case LWM2M_SERVER_STORE_NOTIFY_ID:
			engine_write_bool(out, path,
					  server->flags &
						SERVER_FLAG_STORE_NOTIFY);
			break;

		case LWM2M_SERVER_TRANSPORT_BINDING_ID:
			engine_write_string(out, path,
					    server->transport_binding,
					    strlen(server->transport_binding));
			break;

		default:
			SYS_LOG_WRN("OP_READ resource not found: %u",
				    path->res_id);
			return LWM2M_STATUS_NOT_FOUND;

		}

		break;

	case LWM2M_OP_WRITE:
		switch (path->res_id) {

		case LWM2M_SERVER_LIFETIME_ID:
			engine_read_int32(in, &server->lifetime);
			SYS_LOG_DBG("Read lifetime: %u", server->lifetime);
			NOTIFY_OBSERVER_PATH(path);
			break;

		case LWM2M_SERVER_DEFAULT_MIN_PERIOD_ID:
			engine_read_int32(in, &server->default_min_period);
			SYS_LOG_DBG("Read default min. period: %u",
				    server->default_min_period);
			NOTIFY_OBSERVER_PATH(path);
			break;

		case LWM2M_SERVER_DEFAULT_MAX_PERIOD_ID:
			engine_read_int32(in, &server->default_max_period);
			SYS_LOG_DBG("Read default max. period: %u",
				    server->default_max_period);
			NOTIFY_OBSERVER_PATH(path);
			break;

		case LWM2M_SERVER_DISABLE_TIMEOUT_ID:
			engine_read_int32(in, &server->disabled_timeout);
			SYS_LOG_DBG("Read disabled timeout(in seconds): %u",
				    server->disabled_timeout);
			NOTIFY_OBSERVER_PATH(path);
			break;

		case LWM2M_SERVER_STORE_NOTIFY_ID:
			engine_read_int32(in, &temp);
			if (temp) {
				server->flags |= SERVER_FLAG_STORE_NOTIFY;

			} else {
				SYS_LOG_DBG("Read disable timeout(in sec): %u",
				server->flags &= ~SERVER_FLAG_STORE_NOTIFY);
			}

			SYS_LOG_DBG("Read store notifications when offline: %s",
				    server->flags & SERVER_FLAG_STORE_NOTIFY ?
					"true" : "false");
			NOTIFY_OBSERVER_PATH(path);
			break;

		default:
			SYS_LOG_WRN("OP_WRITE resource not found: %u",
				    path->res_id);
			return LWM2M_STATUS_NOT_FOUND;

		}

		break;

	case LWM2M_OP_EXECUTE:
		switch (path->res_id) {

		case LWM2M_SERVER_DISABLE_ID:
			server->flags &= ~SERVER_FLAG_DISABLED;
			/*
			 * TODO: force de-registration if this is the 0xFFFF
			 * server.
			 */
			break;

		case LWM2M_SERVER_REG_UPDATE_TRIGGER_ID:
			engine_trigger_update();
			break;

		default:
			SYS_LOG_WRN("OP_EXECUTE resource not found: %u",
				    path->res_id);
			return LWM2M_STATUS_NOT_FOUND;

		}

		break;

	/*
	 * NOTE: the create operation will only create an instance and should
	 * avoid reading out data
	 */
	case LWM2M_OP_CREATE:
		if (server_create(path->obj_inst_id)) {
			return LWM2M_STATUS_OK;
		} else {
			return LWM2M_STATUS_ERROR;
		}

	default:
		SYS_LOG_ERR("Unknown resource operation: %d",
			    context->operation);
		return LWM2M_STATUS_ERROR;

	}


	return LWM2M_STATUS_OK;
}

static int lwm2m_server_init(struct device *dev)
{
	int ret;

	/* Register the first object */
	ret = server_create(0);
	if (ret) {
		SYS_LOG_DBG("Register default server instance");
	}

	return !ret;
}

SYS_INIT(lwm2m_server_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
