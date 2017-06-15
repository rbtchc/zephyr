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

#define SYS_LOG_DOMAIN "lwm2m_obj_security"
#define SYS_LOG_LEVEL CONFIG_SYS_LOG_LWM2M_LEVEL
#include <logging/sys_log.h>
#include <stdint.h>
#include <init.h>

#include "lwm2m_object.h"
#include "lwm2m_engine.h"
#include "lwm2m_obj_security.h"

/* Security resource IDs */
#define LWM2M_SECURITY_SERVER_URI_ID		0
#define LWM2M_SECURITY_BOOTSTRAP_FLAG_ID	1
#define LWM2M_SECURITY_MODE_ID			2
#define LWM2M_SECURITY_CLIENT_PKI_ID		3
#define LWM2M_SECURITY_SERVER_PKI_ID		4
#define LWM2M_SECURITY_KEY_ID			5
#define LWM2M_SECURITY_SHORT_SERVER_ID		10

#define MAX_INSTANCE_COUNT	CONFIG_LWM2M_SECURITY_INSTANCE_COUNT

static const u32_t resources[] = {
	RW(LWM2M_SECURITY_SERVER_URI_ID),
	WO(LWM2M_SECURITY_BOOTSTRAP_FLAG_ID),
	WO(LWM2M_SECURITY_MODE_ID),
	WO(LWM2M_SECURITY_CLIENT_PKI_ID),
	WO(LWM2M_SECURITY_SERVER_PKI_ID), /* TODO: Implement */
	WO(LWM2M_SECURITY_KEY_ID),
	WO(LWM2M_SECURITY_SHORT_SERVER_ID) /* TODO: Implement */
};

static struct lwm2m_security_data instances[MAX_INSTANCE_COUNT];

static enum lwm2m_status
security_op_callback(struct lwm2m_engine_obj *obj,
		     struct lwm2m_engine_context *context);

int lwm2m_security_instance_count(void)
{
	return MAX_INSTANCE_COUNT;
}

struct lwm2m_security_data *lwm2m_security_get_instance(int index)
{
	if (index < MAX_INSTANCE_COUNT &&
	    instances[index].eng_obj.op_callback) {
		return &instances[index];
	}

	return NULL;
}

static int security_create(u16_t obj_inst_id)
{
	int i;

	/* Check that there is no other instance with this ID */
	for (i = 0; i < MAX_INSTANCE_COUNT; i++) {
		if (instances[i].eng_obj.op_callback &&
		    instances[i].eng_obj.obj_inst_id == obj_inst_id) {
			SYS_LOG_ERR("Can not create instance - "
				    "already existing: %u", obj_inst_id);
			return 0;
		}
	}

	for (i = 0; i < MAX_INSTANCE_COUNT; i++) {
		/* Not used if OP callback is non-existend */
		if (!instances[i].eng_obj.op_callback) {
			instances[i].eng_obj.obj_id =
				LWM2M_OBJECT_SECURITY_ID;
			instances[i].eng_obj.obj_inst_id = obj_inst_id;
			instances[i].eng_obj.rsc_ids = resources;
			instances[i].eng_obj.rsc_count =
				sizeof(resources) / sizeof(u32_t);
			instances[i].eng_obj.op_callback = security_op_callback;
			/* TODO: Set default values */
			engine_add_object(
				(struct lwm2m_engine_obj *)&instances[i]);
			SYS_LOG_DBG("Create new security instance: %u",
				    obj_inst_id);
			return 1;
		}
	}

	return 0;
}

static enum lwm2m_status
security_op_callback(struct lwm2m_engine_obj *obj,
		     struct lwm2m_engine_context *context)
{
	struct lwm2m_input_context *in = context->in;
	struct lwm2m_output_context *out = context->out;
	struct lwm2m_obj_path *path = context->path;
	struct lwm2m_security_data *security;
	int value = 0;
	size_t value_len;

	if (!path) {
		return LWM2M_STATUS_ERROR;
	}

	SYS_LOG_DBG("Got request at: %u/%u/%u lv:%u", path->obj_id,
		    path->obj_inst_id, path->res_id, path->level);
	security = (struct lwm2m_security_data *)obj;

	switch (context->operation) {

	case LWM2M_OP_READ:
		switch (path->res_id) {

		case LWM2M_SECURITY_SERVER_URI_ID:
			engine_write_string(out, path,
					    security->server_uri,
					    security->server_uri_len);
			break;

		default:
			SYS_LOG_WRN("OP_READ resource not found: %u",
				    path->res_id);
			return LWM2M_STATUS_NOT_FOUND;

		}

		break;

	case LWM2M_OP_WRITE:
		switch (path->res_id) {

		case LWM2M_SECURITY_SERVER_URI_ID:
			engine_read_string(in, security->server_uri, URI_SIZE);
			security->server_uri_len = in->last_value_len;
			security->server_uri[security->server_uri_len] = '\0';
			SYS_LOG_DBG("Read security URI '%s'",
				    security->server_uri);
			break;

		case LWM2M_SECURITY_BOOTSTRAP_FLAG_ID:
			value_len = engine_read_bool(in, &value);
			if (value_len > 0) {
				security->bootstrap = (u8_t)value;
				SYS_LOG_DBG("Read bootstrap flag: %d", value);
			}

			break;

		case LWM2M_SECURITY_MODE_ID:
			engine_read_int32(in, &value);
			security->security_mode = value;
			SYS_LOG_DBG("Read security mode: %d", value);
			break;

		case LWM2M_SECURITY_CLIENT_PKI_ID:
			engine_read_string(in, security->public_key, KEY_SIZE);
			security->public_key_len = in->last_value_len;
			security->public_key[security->public_key_len] = '\0';
			SYS_LOG_DBG("Read client PKI: '%s'",
				    security->public_key);
			break;

		case LWM2M_SECURITY_KEY_ID:
			engine_read_string(in, security->secret_key, URI_SIZE);
			security->secret_key_len = in->last_value_len;
			security->secret_key[security->secret_key_len] = '\0';
			/* TODO: Probably don't want to print this here */
			SYS_LOG_DBG("Read secret key: '%s'",
				    security->secret_key);
			break;

		default:
			SYS_LOG_WRN("OP_WRITE resource not found: %u",
				    path->res_id);
			return LWM2M_STATUS_NOT_FOUND;

		}

		break;

	/*
	 * NOTE: the create operation will only create an instance and should
	 * avoid reading out data
	 */
	case LWM2M_OP_CREATE:
		if (security_create(path->obj_inst_id)) {
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

static int lwm2m_security_init(struct device *dev)
{
	int ret;

	/* Register the first object */
	ret = security_create(0);
	if (ret) {
		SYS_LOG_DBG("Register default securty instance");
	}

	return !ret;
}

SYS_INIT(lwm2m_security_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
