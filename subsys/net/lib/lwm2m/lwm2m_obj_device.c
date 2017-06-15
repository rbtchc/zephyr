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
 * current_time updates
 */

#define SYS_LOG_DOMAIN "lwm2m_obj_device"
#define SYS_LOG_LEVEL CONFIG_SYS_LOG_LWM2M_LEVEL
#include <logging/sys_log.h>
#include <string.h>
#include <stdio.h>
#include <init.h>

#include "lwm2m_object.h"
#include "lwm2m_engine.h"

/* Device resource IDs */
#define LWM2M_DEVICE_MANUFACTURER_ID		0
#define LWM2M_DEVICE_MODEL_NUMBER_ID		1
#define LWM2M_DEVICE_SERIAL_NUMBER_ID		2
#define LWM2M_DEVICE_FIRMWARE_VERSION_ID	3
#define LWM2M_DEVICE_REBOOT_ID			4
#define LWM2M_DEVICE_FACTORY_DEFAULT_ID		5
#define LWM2M_DEVICE_AVAILABLE_POWER_SOURCES_ID	6
#define LWM2M_DEVICE_POWER_SOURCE_VOLTAGE_ID	7
#define LWM2M_DEVICE_POWER_SOURCE_CURRENT_ID	8
#define LWM2M_DEVICE_BATTERY_LEVEL_ID		9
#define LWM2M_DEVICE_MEMORY_FREE_ID		10
#define LWM2M_DEVICE_ERROR_CODE_ID		11
#define LWM2M_DEVICE_RESET_ERROR_CODE_ID	12
#define LWM2M_DEVICE_CURRENT_TIME_ID		13
#define LWM2M_DEVICE_UTC_OFFSET_ID		14
#define LWM2M_DEVICE_TIMEZONE_ID		15
#define LWM2M_DEVICE_SUPPORTED_BINDING_MODES_ID	16
#define LWM2M_DEVICE_TYPE_ID			17
#define LWM2M_DEVICE_HARDWARE_VERSION_ID	18
#define LWM2M_DEVICE_SOFTWARE_VERSION_ID	19
#define LWM2M_DEVICE_BATTERY_STATUS_ID		20
#define LWM2M_DEVICE_MEMORY_TOTAL_ID		21

#define LWM2M_DEVICE_MAX_ID			22

static const u32_t resources[] = {
	RO(LWM2M_DEVICE_MANUFACTURER_ID),
	RO(LWM2M_DEVICE_MODEL_NUMBER_ID),
	RO(LWM2M_DEVICE_SERIAL_NUMBER_ID),
	RO(LWM2M_DEVICE_FIRMWARE_VERSION_ID),
	EX(LWM2M_DEVICE_REBOOT_ID),
	EX(LWM2M_DEVICE_FACTORY_DEFAULT_ID),
	RO(LWM2M_DEVICE_AVAILABLE_POWER_SOURCES_ID),	/* Multi-resource */
	RO(LWM2M_DEVICE_POWER_SOURCE_VOLTAGE_ID),	/* Multi-resource */
	RO(LWM2M_DEVICE_POWER_SOURCE_CURRENT_ID),	/* Multi-resource */
	RO(LWM2M_DEVICE_BATTERY_LEVEL_ID),
	RO(LWM2M_DEVICE_MEMORY_FREE_ID),
	RO(LWM2M_DEVICE_ERROR_CODE_ID),			/* Multi-resource */
	EX(LWM2M_DEVICE_RESET_ERROR_CODE_ID),
	RW(LWM2M_DEVICE_CURRENT_TIME_ID),
	RW(LWM2M_DEVICE_UTC_OFFSET_ID),			/* TODO */
	RW(LWM2M_DEVICE_TIMEZONE_ID),			/* TODO */
	RO(LWM2M_DEVICE_SUPPORTED_BINDING_MODES_ID),
	RO(LWM2M_DEVICE_TYPE_ID),
	RO(LWM2M_DEVICE_HARDWARE_VERSION_ID),
	RO(LWM2M_DEVICE_SOFTWARE_VERSION_ID),		/* TODO */
	RO(LWM2M_DEVICE_BATTERY_STATUS_ID),
	RO(LWM2M_DEVICE_MEMORY_TOTAL_ID),
};

static s32_t time_offset;
static struct lwm2m_engine_obj device;

#ifdef CONFIG_LWM2M_DEVICE_ERROR_CODE_MAX
#define DEVICE_ERROR_CODE_MAX	CONFIG_LWM2M_DEVICE_ERROR_CODE_MAX
#else
#define DEVICE_ERROR_CODE_MAX	10
#endif

/* currently only support UDP binding mode (no SMS or Queue mode) */
#define SUPPORTED_BINDING_MODE	"U"

/* state variables */
static char *_manufacturer;
static char *_model_no;
static char *_serial_no;
static char *_firmware_version;
static char *_hardware_version;
static char *_device_type;
static int   _mem_total_kb;
static int   _mem_free_kb;
static int   _battery_level;
static lwm2m_generic_cb_t _reboot_cb;
static lwm2m_generic_cb_t _factory_default_cb;
static bool pwr_src_enabled[LWM2M_PWR_SRC_MAX];
static int  pwr_src_voltage_mv[LWM2M_PWR_SRC_MAX];
static int  pwr_src_current_ma[LWM2M_PWR_SRC_MAX];
static int  pwr_src_count;
static u8_t error_code_list[DEVICE_ERROR_CODE_MAX];
static int  error_code_count;
static enum lwm2m_device_battery_status _battery_status;

/* setter functions */

void lwm2m_device_set_manufacturer(char *manufacturer)
{
	_manufacturer = manufacturer;
	NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
			LWM2M_DEVICE_MANUFACTURER_ID);
}

void lwm2m_device_set_model_no(char *model_no)
{
	_model_no = model_no;
	NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
			LWM2M_DEVICE_MODEL_NUMBER_ID);
}

void lwm2m_device_set_serial_no(char *serial_no)
{
	_serial_no = serial_no;
	NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
			LWM2M_DEVICE_SERIAL_NUMBER_ID);
}

void lwm2m_device_set_firmware_version(char *firmware_version)
{
	_firmware_version = firmware_version;
	NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
			LWM2M_DEVICE_FIRMWARE_VERSION_ID);
}

void lwm2m_device_set_hardware_version(char *hardware_version)
{
	_hardware_version = hardware_version;
	NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
			LWM2M_DEVICE_HARDWARE_VERSION_ID);
}

void lwm2m_device_set_type(char *device_type)
{
	_device_type = device_type;
	NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
			LWM2M_DEVICE_TYPE_ID);
}

void lwm2m_device_set_mem_total_kb(int mem_total_kb)
{
	_mem_total_kb = mem_total_kb;
	NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
			LWM2M_DEVICE_MEMORY_TOTAL_ID);
}

void lwm2m_device_set_mem_free_kb(int mem_free_kb)
{
	_mem_free_kb = mem_free_kb;
	NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
			LWM2M_DEVICE_MEMORY_FREE_ID);
}

void lwm2m_device_set_battery_level(int battery_level)
{
	if (pwr_src_enabled[LWM2M_PWR_SRC_BATTERY_INTERNAL]) {
		_battery_level = battery_level;
		NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
				LWM2M_DEVICE_BATTERY_LEVEL_ID);
	} else {
		SYS_LOG_ERR("Can't set battery level without registering "
			    "an internal battery!");
	}
}

void lwm2m_device_set_battery_status(enum lwm2m_device_battery_status
						battery_status)
{
	if (pwr_src_enabled[LWM2M_PWR_SRC_BATTERY_INTERNAL]) {
		_battery_status = battery_status;
		NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
				LWM2M_DEVICE_BATTERY_STATUS_ID);
	} else {
		SYS_LOG_ERR("Can't set battery status without registering "
			    "an internal battery!");
	}
}

void lwm2m_device_set_reboot_cb(lwm2m_generic_cb_t reboot_cb)
{
	_reboot_cb = reboot_cb;
}

void lwm2m_device_set_factory_default_cb(lwm2m_generic_cb_t factory_default_cb)
{
	_factory_default_cb = factory_default_cb;
}

void lwm2m_device_set_pwr_src_voltage_mv(enum lwm2m_pwr_src_type pwr_src_type,
					 int voltage_mv)
{
	if (pwr_src_enabled[pwr_src_type]) {
		pwr_src_voltage_mv[pwr_src_type] = voltage_mv;
		NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
				LWM2M_DEVICE_POWER_SOURCE_VOLTAGE_ID);
	} else {
		SYS_LOG_ERR("Can't set power source id %d voltage without "
			    "registering it first!", pwr_src_type);
	}
}

void lwm2m_device_set_pwr_src_current_ma(enum lwm2m_pwr_src_type pwr_src_type,
					 int current_ma)
{
	if (pwr_src_enabled[pwr_src_type]) {
		pwr_src_current_ma[pwr_src_type] = current_ma;
		NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
				LWM2M_DEVICE_POWER_SOURCE_CURRENT_ID);
	} else {
		SYS_LOG_ERR("Can't set power source id %d current without "
			    "registering it first!", pwr_src_type);
	}
}

/* error code function */

int lwm2m_device_add_err(enum lwm2m_device_error error_code)
{
	if (error_code_count < DEVICE_ERROR_CODE_MAX) {
		error_code_list[error_code_count] = error_code;
		error_code_count++;
		return 0;
	}

	return -ENOMEM;
}

/* power source registration */

int lwm2m_device_enable_pwr_src(enum lwm2m_pwr_src_type pwr_src_type,
				int voltage_mv, int current_ma)
{
	if (pwr_src_type < LWM2M_PWR_SRC_DC_POWER &&
	    pwr_src_type >= LWM2M_PWR_SRC_MAX) {
		SYS_LOG_ERR("power source id %d doesn't exist",
			    pwr_src_type);
		return -EINVAL;
	}

	if (pwr_src_enabled[pwr_src_type]) {
		SYS_LOG_ERR("power source id %d already registered",
			    pwr_src_type);
		return -EINVAL;
	}

	pwr_src_enabled[pwr_src_type] = true;
	pwr_src_voltage_mv[pwr_src_type] = voltage_mv;
	pwr_src_current_ma[pwr_src_type] = current_ma;
	pwr_src_count++;
	NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
			LWM2M_DEVICE_AVAILABLE_POWER_SOURCES_ID);
	return 0;
}

int lwm2m_device_disable_pwr_src(enum lwm2m_pwr_src_type pwr_src_type)
{
	if (!pwr_src_enabled[pwr_src_type]) {
		SYS_LOG_ERR("power source id %d wasn't enabled!", pwr_src_type);
		return -EINVAL;
	}

	pwr_src_enabled[pwr_src_type] = false;
	pwr_src_voltage_mv[pwr_src_type] = 0;
	pwr_src_current_ma[pwr_src_type] = 0;
	pwr_src_count--;
	NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
			LWM2M_DEVICE_AVAILABLE_POWER_SOURCES_ID);
	return 0;
}

/* callbacks */

static int device_dim_callback(struct lwm2m_engine_obj *obj,
			       u16_t res_id)
{
	switch (res_id) {

	case LWM2M_DEVICE_AVAILABLE_POWER_SOURCES_ID:
	case LWM2M_DEVICE_POWER_SOURCE_VOLTAGE_ID:
	case LWM2M_DEVICE_POWER_SOURCE_CURRENT_ID:
		return pwr_src_count;

	}

	return 0;
}

static char *device_get_resource_string(u16_t res_id)
{
	char *str = NULL;

	switch (res_id) {

	case LWM2M_DEVICE_MANUFACTURER_ID:
		str = _manufacturer;
		break;

	case LWM2M_DEVICE_MODEL_NUMBER_ID:
		str = _model_no;
		break;

	case LWM2M_DEVICE_SERIAL_NUMBER_ID:
		str = _serial_no;
		break;

	case LWM2M_DEVICE_FIRMWARE_VERSION_ID:
		str = _firmware_version;
		break;

	case LWM2M_DEVICE_TYPE_ID:
		str = _device_type;
		break;

	case LWM2M_DEVICE_HARDWARE_VERSION_ID:
		str = _hardware_version;
		break;

	case LWM2M_DEVICE_SUPPORTED_BINDING_MODES_ID:
		str = SUPPORTED_BINDING_MODE;
		break;

	}

	return str;
}

static enum lwm2m_status
device_op_callback(struct lwm2m_engine_obj *obj,
		   struct lwm2m_engine_context *context)
{
	struct lwm2m_input_context *in = context->in;
	struct lwm2m_output_context *out = context->out;
	struct lwm2m_obj_path *path = context->path;
	int count, i = 0;
	char *str = NULL;
	s32_t lw_time;
	size_t len;

	if (!path || path->level < 3) {
		return LWM2M_STATUS_ERROR;
	}

	SYS_LOG_DBG("Got request at: %u/%u/%u lv:%u", path->obj_id,
		    path->obj_inst_id, path->res_id, path->level);

	switch (context->operation) {

	case LWM2M_OP_READ:
		switch (path->res_id) {

		case LWM2M_DEVICE_MANUFACTURER_ID:
		case LWM2M_DEVICE_MODEL_NUMBER_ID:
		case LWM2M_DEVICE_SERIAL_NUMBER_ID:
		case LWM2M_DEVICE_FIRMWARE_VERSION_ID:
		case LWM2M_DEVICE_TYPE_ID:
		case LWM2M_DEVICE_HARDWARE_VERSION_ID:
		case LWM2M_DEVICE_SUPPORTED_BINDING_MODES_ID:
			str = device_get_resource_string(path->res_id);
			break;

		case LWM2M_DEVICE_CURRENT_TIME_ID:
			SYS_LOG_DBG("Reading time: %lld",
			       (time_offset + (k_uptime_get() / 1000)));
			engine_write_int64(out, path,
					   time_offset +
						(k_uptime_get() / 1000));
			break;

		/* Power Multi-resource case - just use array index as ID */
		case LWM2M_DEVICE_AVAILABLE_POWER_SOURCES_ID:
			engine_write_begin_ri(out, path);
			count = 0;
			for (i = LWM2M_PWR_SRC_DC_POWER;
			     i < LWM2M_PWR_SRC_MAX; i++) {
				if (pwr_src_enabled[i]) {
					count++;
					path->res_inst_id = count;
					engine_write_int32(out, path, i);
				}
			}
			engine_write_end_ri(out, path);
			break;

		case LWM2M_DEVICE_POWER_SOURCE_VOLTAGE_ID:
			engine_write_begin_ri(out, path);
			count = 0;
			for (i = LWM2M_PWR_SRC_DC_POWER;
			     i < LWM2M_PWR_SRC_MAX; i++) {
				if (pwr_src_enabled[i]) {
					count++;
					path->res_inst_id = count;
					engine_write_int32(out, path,
							pwr_src_voltage_mv[i]);
				}
			}
			engine_write_end_ri(out, path);
			break;

		case LWM2M_DEVICE_POWER_SOURCE_CURRENT_ID:
			engine_write_begin_ri(out, path);
			count = 0;
			for (i = LWM2M_PWR_SRC_DC_POWER;
			     i < LWM2M_PWR_SRC_MAX; i++) {
				if (pwr_src_enabled[i]) {
					count++;
					path->res_inst_id = count;
					engine_write_int32(out, path,
							pwr_src_current_ma[i]);
				}
			}
			engine_write_end_ri(out, path);
			break;

		case LWM2M_DEVICE_BATTERY_LEVEL_ID:
			if (pwr_src_enabled[LWM2M_PWR_SRC_BATTERY_INTERNAL]) {
				engine_write_int32(out, path, _battery_level);
			}
			break;

		case LWM2M_DEVICE_MEMORY_FREE_ID:
			if (_mem_free_kb > -1) {
				engine_write_int32(out, path, _mem_free_kb);
			}
			break;

		case LWM2M_DEVICE_ERROR_CODE_ID:
			engine_write_begin_ri(out, path);
			if (error_code_count > 0) {
				for (i = 0; i < error_code_count; i++) {
					path->res_inst_id = i + 1;
					engine_write_int32(out, path,
							   error_code_list[i]);
				}
			} else {
				path->res_inst_id = 1;
				engine_write_int32(out, path, 0);
			}
			engine_write_end_ri(out, path);
			break;

		case LWM2M_DEVICE_BATTERY_STATUS_ID:
			if (pwr_src_enabled[LWM2M_PWR_SRC_BATTERY_INTERNAL]) {
				engine_write_int32(out, path, _battery_status);
			}
			break;

		case LWM2M_DEVICE_MEMORY_TOTAL_ID:
			if (_mem_total_kb > 0) {
				engine_write_int32(out, path, _mem_total_kb);
			}
			break;

		default:
			SYS_LOG_WRN("OP_READ resource not found: %u",
				    path->res_id);
			return LWM2M_STATUS_NOT_FOUND;

		}

		if (str) {
			engine_write_string(out, path, str, strlen(str));
		}

		break;

	case LWM2M_OP_WRITE:
		switch (path->res_id) {

		case LWM2M_DEVICE_CURRENT_TIME_ID:
			/* assume that this only read one TLV value */
			len = engine_read_int32(in, &lw_time);
			if (len == 0) {
				SYS_LOG_ERR("FAIL: could not read time");
			} else {
				SYS_LOG_DBG("Got: time: %d", lw_time);
				time_offset = lw_time -
					      (s32_t)(k_uptime_get() / 1000);
				SYS_LOG_DBG("Write time...%d => offset = %d",
					    lw_time, time_offset);
			}

			/* don't need to update the hash, updates every sec */

			break;

		default:
			SYS_LOG_WRN("OP_WRITE resource not found: %u",
				    path->res_id);
			return LWM2M_STATUS_NOT_FOUND;

		}

		break;

	case LWM2M_OP_EXECUTE:
		switch (path->res_id) {

		case LWM2M_DEVICE_REBOOT_ID:
			if (_reboot_cb) {
				_reboot_cb();
			}
			break;

		case LWM2M_DEVICE_FACTORY_DEFAULT_ID:
			if (_factory_default_cb) {
				_factory_default_cb();
			}
			break;

		case LWM2M_DEVICE_RESET_ERROR_CODE_ID:
			error_code_count = 0;
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

#if 0
static void device_periodic_thread(void)
{
	while (true) {
		/* TODO: make this delay configurable */
		k_sleep(K_SECONDS(1));
		NOTIFY_OBSERVER(LWM2M_OBJECT_DEVICE_ID, 0,
				LWM2M_DEVICE_CURRENT_TIME_ID);
		k_yield();
	}
}
#endif

static int lwm2m_device_init(struct device *dev)
{
	device.obj_id = LWM2M_OBJECT_DEVICE_ID;
	device.obj_inst_id = 0;
	device.rsc_ids = resources;
	device.rsc_count = sizeof(resources) / sizeof(u32_t);
	device.rsc_dim_callback = device_dim_callback;
	device.op_callback = device_op_callback;

	/* Set default values / hashcodes */
	time_offset = 0;
	_mem_total_kb = 0;
	_mem_free_kb = -1;
	pwr_src_count = 0;
	error_code_count = 0;
	_reboot_cb = NULL;
	_factory_default_cb = NULL;

	/* TODO: start current time notification thread (every second) */

	engine_add_object(&device);
	SYS_LOG_DBG("Register device instance");
	return 0;
}

SYS_INIT(lwm2m_device_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
