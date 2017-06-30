/*
 * Copyright (c) 2017 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * TODO:
 * Support PUSH transfer method (from server)
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
#define FIRMWARE_PACKAGE_ID			0
#define FIRMWARE_PACKAGE_URI_ID			1 /* TODO */
#define FIRMWARE_UPDATE_ID			2
#define FIRMWARE_STATE_ID			3
#define FIRMWARE_UPDATE_RESULT_ID		5
#define FIRMWARE_PACKAGE_NAME_ID		6 /* TODO */
#define FIRMWARE_PACKAGE_VERSION_ID		7 /* TODO */
#define FIRMWARE_UPDATE_PROTO_SUPPORT_ID	8 /* TODO */
#define FIRMWARE_UPDATE_DELIV_METHOD_ID		9

#define FIRMWARE_MAX_ID				10

#define DELIVERY_METHOD_PULL_ONLY		0
#define DELIVERY_METHOD_PUSH_ONLY		1
#define DELIVERY_METHOD_BOTH			2

#define PACKAGE_URI_LEN				255

/* resource state variables */
static u8_t update_state;
static u8_t update_result;
static u8_t delivery_method;
static char package_uri[PACKAGE_URI_LEN];

/* only 1 instance of firmware object exists */
static struct lwm2m_engine_obj firmware;
static struct lwm2m_engine_obj_field fields[] = {
	OBJ_FIELD(FIRMWARE_PACKAGE_ID, W, OPAQUE, 0),
	OBJ_FIELD(FIRMWARE_PACKAGE_URI_ID, RW, STRING, 0),
	OBJ_FIELD_EXECUTE(FIRMWARE_UPDATE_ID),
	OBJ_FIELD_DATA(FIRMWARE_STATE_ID, R, UINT),
	OBJ_FIELD_DATA(FIRMWARE_UPDATE_RESULT_ID, R, UINT),
	OBJ_FIELD_DATA(FIRMWARE_UPDATE_DELIV_METHOD_ID, R, UINT)
};

static struct lwm2m_engine_obj_inst inst;
static struct lwm2m_engine_res_inst res[FIRMWARE_MAX_ID];

static lwm2m_engine_rw_cb_t rw_cb;

#ifdef CONFIG_LWM2M_FIRMWARE_UPDATE_PULL_SUPPORT
extern int lwm2m_firmware_start_transfer(char *package_uri);
#endif

static int package_write_cb(u16_t obj_inst_id,
			    u8_t *data, u16_t data_len,
			    bool last_block, size_t total_size)
{
	SYS_LOG_DBG("PACKAGE WRITE");
	if (rw_cb) {
		return rw_cb(obj_inst_id, data, data_len,
			     last_block, total_size);
	}

	return 1;
}

static int package_uri_write_cb(u16_t obj_inst_id,
				u8_t *data, u16_t data_len,
				bool last_block, size_t total_size)
{
	SYS_LOG_DBG("PACKAGE_URI WRITE");
	lwm2m_firmware_start_transfer(data);
	return 1;
}

void lwm2m_firmware_set_rw_cb(lwm2m_engine_rw_cb_t cb)
{
	rw_cb = cb;
}

lwm2m_engine_rw_cb_t lwm2m_firmware_get_rw_cb(void)
{
	return rw_cb;
}

#if 0
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
#ifdef CONFIG_LWM2M_FIRMWARE_UPDATE_PULL_SUPPORT
			/* HACK: currently only use IP addr */
			lwm2m_firmware_start_transfer(package_uri);
#endif
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
#endif

static struct lwm2m_engine_obj_inst *firmware_create(u16_t obj_inst_id)
{
	int i = 0;

	/* initialize instance resource data */
	INIT_OBJ_RES(res, i, FIRMWARE_PACKAGE_ID, 0, NULL, 0,
		NULL, package_write_cb, NULL);
	INIT_OBJ_RES(res, i, FIRMWARE_PACKAGE_URI_ID, 0,
		package_uri, PACKAGE_URI_LEN,
		NULL, package_uri_write_cb, NULL);
	INIT_OBJ_RES_DUMMY(res, i, FIRMWARE_UPDATE_ID);
	INIT_OBJ_RES_DATA(res, i, FIRMWARE_STATE_ID,
		&update_state, sizeof(update_state));
	INIT_OBJ_RES_DATA(res, i, FIRMWARE_UPDATE_RESULT_ID,
		&update_result, sizeof(update_result));
	INIT_OBJ_RES_DATA(res, i, FIRMWARE_UPDATE_DELIV_METHOD_ID,
		&delivery_method, sizeof(delivery_method));

	inst.resources = res;
	inst.resource_count = i;
	SYS_LOG_DBG("Create LWM2M firmware instance: %d", obj_inst_id);
	return &inst;
}

static int lwm2m_firmware_init(struct device *dev)
{
	struct lwm2m_engine_obj_inst *obj_inst = NULL;
	int ret = 0;

	/* Set default values */
	package_uri[0] = '\0';
	update_state = STATE_IDLE;
	update_result = RESULT_DEFAULT;
#ifdef CONFIG_LWM2M_FIRMWARE_UPDATE_PULL_SUPPORT
	delivery_method = DELIVERY_METHOD_BOTH;
#else
	delivery_method = DELIVERY_METHOD_PUSH;
#endif

	firmware.obj_id = LWM2M_OBJECT_FIRMWARE_ID;
	firmware.fields = fields;
	firmware.field_count = sizeof(fields) / sizeof(*fields);
	firmware.max_instance_count = 1;
	firmware.create_cb = firmware_create;
	engine_register_obj(&firmware);

	/* auto create the only instance */
	ret = engine_create_obj_inst(LWM2M_OBJECT_FIRMWARE_ID, 0, obj_inst);
	if (ret < 0) {
		SYS_LOG_DBG("Create LWM2M instance 0 error: %d", ret);
	}

	return ret;
}

SYS_INIT(lwm2m_firmware_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
