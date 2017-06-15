/*
 * Copyright (c) 2017 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __LWM2M_H__
#define __LWM2M_H__

#include <net/net_context.h>

/* LWM2M Objects defined by OMA */

#define LWM2M_OBJECT_SECURITY_ID		0
#define LWM2M_OBJECT_SERVER_ID			1
#define LWM2M_OBJECT_ACCESS_CONTROL_ID		2
#define LWM2M_OBJECT_DEVICE_ID			3
#define LWM2M_OBJECT_CONNECTIVITY_MONITORING_ID	4
#define LWM2M_OBJECT_FIRMWARE_ID		5
#define LWM2M_OBJECT_LOCATION_ID		6
#define LWM2M_OBJECT_CONNECTIVITY_STATISTICS_ID	7

/* LWM2M Device Object */

enum lwm2m_pwr_src_type {
	LWM2M_PWR_SRC_DC_POWER,
	LWM2M_PWR_SRC_BATTERY_INTERNAL,
	LWM2M_PWR_SRC_BATTERY_EXTERNAL,
	LWM2M_PWR_SRC_UNUSED,
	LWM2M_PWR_SRC_POWER_OVER_ETHERNET,
	LWM2M_PWR_SRC_USB,
	LWM2M_PWR_SRC_AC_POWER,
	LWM2M_PWR_SRC_SOLAR,
	LWM2M_PWR_SRC_MAX,
};

enum lwm2m_device_error {
	LWM2M_DEVICE_ERROR_NONE,
	LWM2M_DEVICE_ERROR_LOW_POWER,
	LWM2M_DEVICE_ERROR_EXT_POWER_SUPPLY_OFF,
	LWM2M_DEVICE_ERROR_GPS_FAILURE,
	LWM2M_DEVICE_ERROR_LOW_SIGNAL_STRENGTH,
	LWM2M_DEVICE_ERROR_OUT_OF_MEMORY,
	LWM2M_DEVICE_ERROR_SMS_FAILURE,
	LWM2M_DEVICE_ERROR_NETWORK_FAILURE,
	LWM2M_DEVICE_ERROR_PERIPHERAL_FAILURE,
};

enum lwm2m_device_battery_status {
	LWM2M_DEVICE_BATTERY_NORMAL,
	LWM2M_DEVICE_BATTERY_CHARGING,
	LWM2M_DEVICE_BATTERY_CHARGE_COMPLETE,
	LWM2M_DEVICE_BATTERY_DAMAGED,
	LWM2M_DEVICE_BATTERY_LOW,
	LWM2M_DEVICE_BATTERY_NOT_INSTALLED,
	LWM2M_DEVICE_BATTERY_UNKNOWN,
};

typedef void (*lwm2m_generic_cb_t)(void);

void lwm2m_device_set_manufacturer(char *manufacturer);
void lwm2m_device_set_model_no(char *model_no);
void lwm2m_device_set_serial_no(char *serial_no);
void lwm2m_device_set_firmware_version(char *firmware_version);
void lwm2m_device_set_hardware_version(char *hardware_version);
void lwm2m_device_set_type(char *device_type);
void lwm2m_device_set_mem_total_kb(int mem_total_kb);
void lwm2m_device_set_mem_free_kb(int mem_free_kb);
void lwm2m_device_set_battery_level(int batter_level);
void lwm2m_device_set_battery_status(enum lwm2m_device_battery_status
						batter_status);
void lwm2m_device_set_reboot_cb(lwm2m_generic_cb_t reboot_cb);
void lwm2m_device_set_factory_default_cb(
		lwm2m_generic_cb_t factory_default_cb);
int  lwm2m_device_add_err(enum lwm2m_device_error error_code);
int  lwm2m_device_enable_pwr_src(enum lwm2m_pwr_src_type pwr_src_type,
				 int voltage_mv, int current_ma);
int  lwm2m_device_disable_pwr_src(enum lwm2m_pwr_src_type pwr_src_type);
void lwm2m_device_set_pwr_src_voltage_mv(enum lwm2m_pwr_src_type pwr_src_type,
					 int voltage_mv);
void lwm2m_device_set_pwr_src_current_ma(enum lwm2m_pwr_src_type pwr_src_type,
					 int current_ma);

/* LWM2M Firemware Update Object */

enum firmware_update_state {
	STATE_IDLE,
	STATE_DOWNLOADING,
	STATE_DOWNLOADED,
	STATE_UPDATING
};

enum firmware_update_result {
	RESULT_DEFAULT,
	RESULT_SUCCESS,
	RESULT_NO_STORAGE,
	RESULT_OUT_OF_MEM,
	RESULT_CONNECTION_LOST,
	RESULT_INTEGRITY_FAILED,
	RESULT_UNSUP_FW,
	RESULT_INVALID_URI,
	RESULT_UPDATE_FAILED,
	RESULT_UNSUP_PROTO
};

typedef int (*lwm2m_block_received_cb_t)(u8_t *data, u16_t data_len,
					 bool last_block, size_t total_size);

void lwm2m_firmware_set_update_state(enum firmware_update_state state);
void lwm2m_firmware_set_update_result(enum firmware_update_result result);
void lwm2m_firmware_set_block_received_cb(
	lwm2m_block_received_cb_t block_received_cb);
lwm2m_block_received_cb_t lwm2m_firmware_get_block_received_cb(void);
void lwm2m_firmware_set_update_cb(lwm2m_generic_cb_t update_cb);

/* LWM2M Engine */

int  lwm2m_engine_init(const char *endpoint_name, struct sockaddr *local_addr,
		       const char *peer_ipaddr);

#endif	/* __LWM2M_H__ */
