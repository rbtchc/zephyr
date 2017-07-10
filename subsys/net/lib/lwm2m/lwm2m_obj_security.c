/*
 * Copyright (c) 2017 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define SYS_LOG_DOMAIN "lwm2m_obj_security"
#define SYS_LOG_LEVEL CONFIG_SYS_LOG_LWM2M_LEVEL
#include <logging/sys_log.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <init.h>

#include "lwm2m_object.h"
#include "lwm2m_engine.h"

/* Security resource IDs */
#define SECURITY_SERVER_URI_ID		0
#define SECURITY_BOOTSTRAP_FLAG_ID	1
#define SECURITY_MODE_ID		2
#define SECURITY_CLIENT_PK_ID		3
#define SECURITY_SERVER_PK_ID		4
#define SECURITY_SECRET_KEY_ID		5
#define SECURITY_SMS_SECURITY_MODE	6
#define SECURITY_SMS_BINDING_KEY_PARAMS	7
#define SECURITY_SMS_BINDING_KEYS	8
#define SECURITY_SERVER_SMS_NUMBER	9
#define SECURITY_SHORT_SERVER_ID	10

#define SECURITY_MAX_ID			11

#define MAX_INSTANCE_COUNT		CONFIG_LWM2M_SECURITY_INSTANCE_COUNT

#define SECURITY_URI_LEN		255

#define SECURITY_MODE_PSK		0
#define SECURITY_MODE_RAW		1
#define SECURITY_MODE_CERT		2
#define SECURITY_MODE_NO_SEC		3
#define SECURITY_MODE_CERT_WITH_EST	4

/* resource state variables */
static struct security_object security_res[MAX_INSTANCE_COUNT];

static struct lwm2m_engine_obj security;
static struct lwm2m_engine_obj_field fields[] = {
	OBJ_FIELD_DATA(SECURITY_SERVER_URI_ID, RW, STRING),
	OBJ_FIELD_DATA(SECURITY_BOOTSTRAP_FLAG_ID, W, BOOL),
	OBJ_FIELD_DATA(SECURITY_MODE_ID, W, U8),
	OBJ_FIELD_DATA(SECURITY_CLIENT_PK_ID, W, OPAQUE),	/* TODO */
	OBJ_FIELD_DATA(SECURITY_SERVER_PK_ID, W, OPAQUE),	/* TODO */
	OBJ_FIELD_DATA(SECURITY_SECRET_KEY_ID, W, OPAQUE),	/* TODO */
	OBJ_FIELD_DATA(SECURITY_SMS_SECURITY_MODE, W, U8),	/* TODO */
	OBJ_FIELD_DATA(SECURITY_SMS_BINDING_KEY_PARAMS, W, OPAQUE), /* TODO */
	OBJ_FIELD_DATA(SECURITY_SMS_BINDING_KEYS, W, OPAQUE),	/* TODO */
	OBJ_FIELD_DATA(SECURITY_SERVER_SMS_NUMBER, W, STRING),	/* TODO */
	OBJ_FIELD_DATA(SECURITY_SHORT_SERVER_ID, W, U16)	/* TODO */
};

static struct lwm2m_engine_obj_inst inst[MAX_INSTANCE_COUNT];
static struct lwm2m_engine_res_inst res[MAX_INSTANCE_COUNT][SECURITY_MAX_ID];

static int security_delete(u16_t obj_inst_id)
{
	int index;

	for (index = 0; index < MAX_INSTANCE_COUNT; index++) {
		if (inst[index].obj && inst[index].obj_inst_id == obj_inst_id) {
			memset(inst+index, 0, sizeof(*inst));
			return 0;
		}
	}
	return -ENOENT;
}

static struct lwm2m_engine_obj_inst *security_create(u16_t obj_inst_id)
{
	int index, i = 0;
	struct security_object *obj;

	/* Check that there is no other instance with this ID */
	for (index = 0; index < MAX_INSTANCE_COUNT; index++) {
		if (inst[index].obj && inst[index].obj_inst_id == obj_inst_id) {
			SYS_LOG_ERR("Can not create instance - "
				    "already existing: %u", obj_inst_id);
			return NULL;
		}
	}

	for (index = 0; index < MAX_INSTANCE_COUNT; index++) {
		if (!inst[index].obj) {
			break;
		}
	}

	if (index >= MAX_INSTANCE_COUNT) {
		SYS_LOG_ERR("Can not create instance - "
			    "no more room: %u", obj_inst_id);
		return NULL;
	}

	/* default values */
	obj = &security_res[index];
	obj->security_uri[0] = '\0';
	obj->bootstrap_flag = false;
	obj->security_mode = 0;
	obj->short_server_id = 0;

	/* initialize instance resource data */
	INIT_OBJ_RES_DATA(res[index], i, SECURITY_SERVER_URI_ID,
			  obj->security_uri,
			  SECURITY_URI_LEN);
	INIT_OBJ_RES_DATA(res[index], i, SECURITY_BOOTSTRAP_FLAG_ID,
			  &obj->bootstrap_flag, sizeof(obj->bootstrap_flag));
	INIT_OBJ_RES_DATA(res[index], i, SECURITY_MODE_ID,
			  &obj->security_mode, sizeof(obj->security_mode));
	/* TODO: */
	INIT_OBJ_RES_DUMMY(res[index], i, SECURITY_CLIENT_PK_ID);
	INIT_OBJ_RES_DUMMY(res[index], i, SECURITY_SERVER_PK_ID);
	INIT_OBJ_RES_DUMMY(res[index], i, SECURITY_SECRET_KEY_ID);
	INIT_OBJ_RES_DUMMY(res[index], i, SECURITY_SMS_SECURITY_MODE);
	INIT_OBJ_RES_DUMMY(res[index], i, SECURITY_SMS_BINDING_KEY_PARAMS);
	INIT_OBJ_RES_DUMMY(res[index], i, SECURITY_SMS_BINDING_KEYS);
	INIT_OBJ_RES_DUMMY(res[index], i, SECURITY_SERVER_SMS_NUMBER);
	INIT_OBJ_RES_DATA(res[index], i, SECURITY_SHORT_SERVER_ID,
			  &obj->short_server_id, sizeof(obj->short_server_id));

	inst[index].resources = res[index];
	inst[index].resource_count = i;
	SYS_LOG_DBG("Create LWM2M security instance: %d", obj_inst_id);
	return &inst[index];
}

int get_security_obj(u16_t ssid, bool bootstrap,
		     struct security_object **obj)
{
	int i;

	/* SSID 0 and 65535 are not used.
	 * When bootstrap = true is given, search for bootstrap server
	 * When SSID = 0 is given, search for first available non-bs server
	 */

	for (i = 0; i < MAX_INSTANCE_COUNT; i++) {
		/* Assuming only one bootstrap server */
		if (bootstrap == true) {
			if (security_res[i].bootstrap_flag) {
				*obj = &security_res[i];
				return 0;
			}
		} else {
			if (security_res[i].short_server_id > 0 &&
			    security_res[i].bootstrap_flag == false &&
			    (ssid == 0 ||
			     security_res[i].short_server_id == ssid)) {
				*obj = &security_res[i];
				return 0;
			}
		}
	}
	return -ENOENT;
}

int put_security_obj(const char *server_uri, bool bootstrap)
{
	struct lwm2m_engine_obj_inst *obj_inst;
	char buf[MAX_RESOURCE_LEN];
	int ret;
	int inst_id;
	int i;
	u16_t ssid = 0;

	/* Check server_uri length */
	if (sizeof(server_uri) >= SECURITY_URI_LEN) {
		return -EINVAL;
	}

	/* Only one bootstrap server is allowed */
	if (bootstrap) {
		for (i = 0; i < MAX_INSTANCE_COUNT; i++) {
			if (true == security_res[i].bootstrap_flag) {
				SYS_LOG_ERR("Bootstrap server exist");
				return -EEXIST;
			}
		}
	}

	/* Get smallest available instance ID */
	inst_id = 0;
	for (i = 0; i < MAX_INSTANCE_COUNT; i++) {
		if (inst[i].obj && inst[i].obj_inst_id == inst_id) {
			i = 0;
			inst_id++;
		}
	}

	if (!bootstrap) {
		/* Create server object if not bootstrap for SSID */
		ret = lwm2m_create_obj_inst(LWM2M_OBJECT_SERVER_ID,
					    inst_id, &obj_inst);
		if (ret < 0) {
			SYS_LOG_ERR("Create LWM2M server instance %d error: %d",
				    inst_id, ret);
			return ret;
		}
		SYS_LOG_DBG("Create server obj inst id = %d",
			    obj_inst->obj_inst_id);

		/* Get SERVER_SHORT_SERVER_ID from lwm2m_obj_server */
		sprintf(buf, "%u/%u/%u", LWM2M_OBJECT_SERVER_ID, inst_id, 0);
		ssid = lwm2m_engine_get_u16(buf);
	}

	/* Create security object instance */
	ret = lwm2m_create_obj_inst(LWM2M_OBJECT_SECURITY_ID,
			            inst_id, &obj_inst);
	if (ret < 0) {
		SYS_LOG_ERR("Create LWM2M security instance %d error: %d",
			    i, ret);
		goto cleanup;
	}

	/* Get corresponding security_res index */
	for (i = 0; i < MAX_INSTANCE_COUNT; i++) {
		if (inst[i].obj && inst[i].obj_inst_id == inst_id) {
			break;
		}
	}

	strncpy(security_res[i].security_uri, server_uri, SECURITY_URI_LEN);
	security_res[i].bootstrap_flag = bootstrap;

	/* TODO: if any security stuff passed in */
	security_res[i].security_mode = SECURITY_MODE_NO_SEC;
	security_res[i].short_server_id = ssid;

	return ssid;

cleanup:
	lwm2m_delete_obj_inst(LWM2M_OBJECT_SERVER_ID, inst_id);

	return ret;
}

static int lwm2m_security_init(struct device *dev)
{
	int ret = 0;

	/* Set default values */
	memset(inst, 0, sizeof(*inst) * MAX_INSTANCE_COUNT);
	memset(res, 0, sizeof(struct lwm2m_engine_res_inst) *
		       MAX_INSTANCE_COUNT * SECURITY_MAX_ID);
	memset(security_res, 0, sizeof(struct security_object) *
		                MAX_INSTANCE_COUNT);

	security.obj_id = LWM2M_OBJECT_SECURITY_ID;
	security.fields = fields;
	security.field_count = sizeof(fields) / sizeof(*fields);
	security.max_instance_count = MAX_INSTANCE_COUNT;
	security.create_cb = security_create;
	security.delete_cb = security_delete;
	lwm2m_register_obj(&security);

	return ret;
}

SYS_INIT(lwm2m_security_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
