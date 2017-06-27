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

/* firmware block context for package push */
static struct zoap_block_context _fw_block_ctx;

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

#define GET_MORE(v) (!!((v) & 0x08))

static int get_block_option(const struct zoap_packet *zpkt, u16_t code)
{
	struct zoap_option option;
	unsigned int val;
	int count = 1;

	count = zoap_find_options(zpkt, code, &option, count);
	if (count <= 0) {
		return -ENOENT;
	}

	val = zoap_option_value_to_int(&option);

	return val;
}

static enum lwm2m_status handle_package_write(
	struct lwm2m_engine_context *context)
{
	struct lwm2m_input_context *in = context->in;
	struct lwm2m_output_context *out = context->out;

	lwm2m_block_received_cb_t callback;
	u16_t payload_len;
	u8_t *payload;
	int opt_block1;
	bool is_last_block = true;
	int ret;

	opt_block1 = get_block_option(in->in_zpkt, ZOAP_OPTION_BLOCK1);

	/* FIXME: Should take package uri into consideration */
	switch (_update_state) {
	case STATE_IDLE:
#if defined(NET_BLUETOOTH)
		zoap_block_transfer_init(&_fw_block_ctx, ZOAP_BLOCK_64, 0);
#else
		zoap_block_transfer_init(&_fw_block_ctx, ZOAP_BLOCK_256, 0);
#endif
		lwm2m_firmware_set_update_state(STATE_DOWNLOADING);
		lwm2m_firmware_set_update_result(RESULT_DEFAULT);
		break;

	case STATE_DOWNLOADING:
		break;

	case STATE_UPDATING:
		/* FIXME: not sure whether it's correct behavior or not */
		SYS_LOG_DBG("Package write request while uploading!");
		return LWM2M_STATUS_OP_NOT_ALLOWED;

	case STATE_DOWNLOADED:
		if (in->insize != 0) {
		    /* FIXME: not sure whether it's correct behavior or not */
		    return LWM2M_STATUS_OP_NOT_ALLOWED;
		}
		SYS_LOG_DBG("Rx empty string, switch to idle mode");
		lwm2m_firmware_set_update_state(STATE_IDLE);
		return LWM2M_STATUS_OK;

	default:
		SYS_LOG_ERR("Unhandled state: %d", _update_state);
		return LWM2M_STATUS_ERROR;

	}

	if (opt_block1 >= 0) {
		/* SIZE1 is not guranteed available */
		ret = zoap_update_from_block(in->in_zpkt, &_fw_block_ctx);
		if (ret < 0) {
			// TODO setup update_result, transit state?
			SYS_LOG_ERR("Error from block update: %d", ret);
			return LWM2M_STATUS_ERROR;
		}
		is_last_block = !GET_MORE(opt_block1);
	}

	/* Process incoming data */
	payload_len = 0;
	payload = zoap_packet_get_payload(in->in_zpkt, &payload_len);
	if (payload_len > 0) {
		SYS_LOG_DBG("total: %zd, current: %zd, payload len = %d",
			_fw_block_ctx.total_size,
			_fw_block_ctx.current,
			payload_len);

		/* Call callback */
		callback = lwm2m_firmware_get_block_received_cb();
		if (callback) {
			ret = callback(payload, payload_len,
				is_last_block,
				_fw_block_ctx.total_size);
			/* TODO: error handling */
			if (ret < 0) {
				// TODO setup update_result, transit state?
				SYS_LOG_ERR("firmware callback err: %d", ret);
				return LWM2M_STATUS_ERROR;
			}
		}
	}

	if (opt_block1 >= 0) {
		ret = zoap_add_block1_option(out->out_zpkt, &_fw_block_ctx);
		if (ret < 0) {
			SYS_LOG_ERR("Error on adding block1 response: %d", ret);
			return LWM2M_STATUS_ERROR;
		}
	}
	/* Change response code to ZOAP_RESPONSE_CODE_CONTINUE */
	if (is_last_block) {
		// Reset the firmware block context
		lwm2m_firmware_set_update_state(STATE_DOWNLOADED);
	} else {
		zoap_header_set_code(out->out_zpkt,
			ZOAP_RESPONSE_CODE_CONTINUE);
	}
	return LWM2M_STATUS_OK;
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

	enum lwm2m_status ret;

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
			SYS_LOG_DBG("Write Firmware package: %d",
				    in->insize);
			ret = handle_package_write(context);
			if (ret != LWM2M_STATUS_OK) {
				return ret;
			}
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

				lwm2m_firmware_set_update_state(STATE_IDLE);
				lwm2m_firmware_set_update_result(RESULT_SUCCESS);
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
