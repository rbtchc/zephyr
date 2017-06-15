/*
 * Copyright (c) 2016, SICS Swedish ICT AB
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
 * Support PULL transfer method (from server)
 */

#define SYS_LOG_DOMAIN "lwm2m_obj_firmware"
#define SYS_LOG_LEVEL CONFIG_SYS_LOG_LWM2M_LEVEL
#include <logging/sys_log.h>
#include <net/zoap.h>
#include <string.h>
#include <init.h>

#include "lwm2m_object.h"
#include "lwm2m_engine.h"

/* Firmware resource IDs */
#define LWM2M_FIRMWARE_PACKAGE_ID		0
#define LWM2M_FIRMWARE_PACKAGE_URI_ID		1 /* TODO */
#define LWM2M_FIRMWARE_UPDATE_ID		2
#define LWM2M_FIRMWARE_STATE_ID			3
#define LWM2M_FIRMWARE_UPDATE_RESULT_ID		5
#define LWM2M_FIRMWARE_PACKAGE_NAME_ID		6 /* TODO */
#define LWM2M_FIRMWARE_PACKAGE_VERSION_ID	7 /* TODO */
#define LWM2M_FIRMWARE_UPDATE_PROTO_SUPPORT_ID	8 /* TODO */
#define LWM2M_FIRMWARE_UPDATE_DELIV_METHOD_ID	9

#define DELIVERY_METHOD_PULL_ONLY	0
#define DELIVERY_METHOD_PUSH_ONLY	1
#define DELIVERY_METHOD_BOTH		2

#define PACKAGE_URI_LEN			255


static const u32_t resources[] = {
	WO(LWM2M_FIRMWARE_PACKAGE_ID),
	RW(LWM2M_FIRMWARE_PACKAGE_URI_ID),
	EX(LWM2M_FIRMWARE_UPDATE_ID),
	RO(LWM2M_FIRMWARE_STATE_ID),
	RO(LWM2M_FIRMWARE_UPDATE_RESULT_ID),
	RO(LWM2M_FIRMWARE_UPDATE_DELIV_METHOD_ID),
};

static struct lwm2m_engine_obj firmware;
static char package_uri[PACKAGE_URI_LEN];

/* private variables to enable notify */
static enum firmware_update_state  _update_state;
static enum firmware_update_result _update_result;
static lwm2m_block_received_cb_t _block_received_cb;
static lwm2m_generic_cb_t _update_cb;

extern int lwm2m_firmware_start_transfer(char *package_uri);

/* setter functions */

void lwm2m_firmware_set_update_state(enum firmware_update_state state)
{
	_update_state = state;
	NOTIFY_OBSERVER(LWM2M_OBJECT_FIRMWARE_ID, 0, LWM2M_FIRMWARE_STATE_ID);
}

void lwm2m_firmware_set_update_result(enum firmware_update_result result)
{
	_update_result = result;
	NOTIFY_OBSERVER(LWM2M_OBJECT_FIRMWARE_ID, 0,
			LWM2M_FIRMWARE_UPDATE_RESULT_ID);
}

void lwm2m_firmware_set_block_received_cb(int (*block_received_cb)(
	u8_t *data, u16_t data_len, bool last_block, size_t total_size))
{
	_block_received_cb = block_received_cb;
}

lwm2m_block_received_cb_t lwm2m_firmware_get_block_received_cb(void)
{
	return _block_received_cb;
}

void lwm2m_firmware_set_update_cb(lwm2m_generic_cb_t update_cb)
{
	_update_cb = update_cb;
}

/* OP Callback */

static enum lwm2m_status
firmware_op_callback(struct lwm2m_engine_obj *obj,
		     struct lwm2m_engine_context *context)
{
	struct lwm2m_input_context *in = context->in;
	struct lwm2m_output_context *out = context->out;
	struct lwm2m_obj_path *path = context->path;
	size_t value_len;

	if (!path || path->level < 3) {
		return LWM2M_STATUS_ERROR;
	}

	SYS_LOG_DBG("Got request at: %u/%u/%u lv:%u", path->obj_id,
		    path->obj_inst_id, path->res_id, path->level);

	switch (context->operation) {

	case LWM2M_OP_READ:
		switch (path->res_id) {

		/* TODO: implement alternate download method */
		case LWM2M_FIRMWARE_PACKAGE_URI_ID:
			if (strlen(package_uri) > 0) {
				SYS_LOG_DBG("PACKAGE URI: '%s'(%zd)",
					    package_uri, strlen(package_uri));
				engine_write_string(out, path,
						    package_uri,
						    strlen(package_uri));
			} else {
				return LWM2M_STATUS_NOT_FOUND;
			}
			break;

		case LWM2M_FIRMWARE_STATE_ID:
			engine_write_int32(out, path, _update_state);
			break;

		case LWM2M_FIRMWARE_UPDATE_RESULT_ID:
			engine_write_int32(out, path, _update_result);
			break;

		case LWM2M_FIRMWARE_UPDATE_DELIV_METHOD_ID:
#ifdef CONFIG_LWM2M_FIRMWARE_UPDATE_PULL_SUPPORT
			engine_write_int32(out, path, DELIVERY_METHOD_BOTH);
#else
			engine_write_int32(out, path,
					   DELIVERY_METHOD_PUSH_ONLY);
#endif
			break;

		default:
			SYS_LOG_WRN("OP_READ resource not found: %u",
				    path->res_id);
			return LWM2M_STATUS_NOT_FOUND;

		}

		break;

	case LWM2M_OP_WRITE:
		switch (path->res_id) {

		case LWM2M_FIRMWARE_PACKAGE_ID:
			/*
			 * TODO: Implement firmware download state machine and
			 * client callback for passing firmware data
			 */
			SYS_LOG_DBG("Write Firmware package: %d",
				    in->insize);
			/* Change response code to ZOAP_RESPONSE_CODE_CONTINUE */
			break;

		case LWM2M_FIRMWARE_PACKAGE_URI_ID:
			value_len = engine_read_string(in, package_uri,
						       PACKAGE_URI_LEN);
			package_uri[value_len] = '\0';
			SYS_LOG_DBG("Read Firmware URI: '%s'", package_uri);
			NOTIFY_OBSERVER_PATH(path);
			/* TODO: Start block transfer */
			/* HACK: currently only use IP addr */
			lwm2m_firmware_start_transfer(package_uri);
			break;

		default:
			SYS_LOG_WRN("OP_WRITE resource not found: %u",
				    path->res_id);
			return LWM2M_STATUS_NOT_FOUND;

		}

		break;

	case LWM2M_OP_EXECUTE:
		switch (path->res_id) {

		case LWM2M_FIRMWARE_UPDATE_ID:
			if (_update_state == STATE_DOWNLOADED) {
				if (_update_cb) {
					_update_cb();
				}

				return LWM2M_STATUS_OK;
			}

			/* Failure? */
			break;

		default:
			SYS_LOG_WRN("OP_EXECUTE resource not found: %u",
				    path->res_id);
			return LWM2M_STATUS_NOT_FOUND;

		}

		break;

	default:
		SYS_LOG_ERR("Unknown resource operation: %d",
			    context->operation);
		return LWM2M_STATUS_ERROR;

	}

	return LWM2M_STATUS_OK;
}

static int lwm2m_firmware_init(struct device *dev)
{
	firmware.obj_id = LWM2M_OBJECT_FIRMWARE_ID;
	firmware.obj_inst_id = 0;
	firmware.rsc_ids = resources;
	firmware.rsc_count = sizeof(resources) / sizeof(u32_t);
	firmware.op_callback = firmware_op_callback;

	/* Set default values */
	package_uri[0] = '\0';
	_update_state = STATE_IDLE;
	_update_result = RESULT_DEFAULT;
	_block_received_cb = NULL;

	engine_add_object(&firmware);
	SYS_LOG_DBG("Registered firmware instance");
	return 0;
}

SYS_INIT(lwm2m_firmware_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
