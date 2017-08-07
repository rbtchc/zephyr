/*
 * Copyright (c) 2017 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define SYS_LOG_DOMAIN "lwm2m-client"
#define NET_SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#define NET_LOG_ENABLED 1

#include <board.h>
#include <stdio.h>
#include <zephyr.h>
#include <net/lwm2m.h>

#if defined(CONFIG_NET_L2_BT)
#include <bluetooth/bluetooth.h>
#include <gatt/ipss.h>
#endif

#define APP_BANNER "Run LWM2M client"

#define CLIENT_MANUFACTURER	"Zephyr"
#define CLIENT_MODEL_NUMBER	"OMA-LWM2M Sample Client"
#define CLIENT_SERIAL_NUMBER	"345000123"
#define CLIENT_FIRMWARE_VER	"1.0"
#define CLIENT_DEVICE_TYPE	"OMA-LWM2M Client"
#define CLIENT_HW_VER		"1.0.1"

#define ENDPOINT_LEN		32
#define URI_LEN			255

static int pwrsrc_bat;
static int pwrsrc_usb;
static int battery_voltage = 3800;
static int battery_current = 125;
static int usb_voltage = 5000;
static int usb_current = 900;

static struct k_sem quit_lock;

static int device_reboot_cb(u16_t obj_inst_id)
{
	SYS_LOG_INF("DEVICE: REBOOT");
	/* Add an error for testing */
	lwm2m_device_add_err(LWM2M_DEVICE_ERROR_LOW_POWER);
	/* Change the battery voltage for testing */
	lwm2m_device_set_pwrsrc_voltage_mv(pwrsrc_bat, --battery_voltage);

	return 1;
}

static int device_factory_default_cb(u16_t obj_inst_id)
{
	SYS_LOG_INF("DEVICE: FACTORY DEFAULT");
	/* Add an error for testing */
	lwm2m_device_add_err(LWM2M_DEVICE_ERROR_GPS_FAILURE);
	/* Change the USB current for testing */
	lwm2m_device_set_pwrsrc_current_ma(pwrsrc_usb, --usb_current);

	return 1;
}

static int firmware_update_cb(u16_t obj_inst_id)
{
	SYS_LOG_DBG("UPDATE");

	/* TODO: kick off update process */

	/* If success, set the update result as RESULT_SUCCESS.
	 * In reality, it should be set at function lwm2m_setup()
	 */
	lwm2m_engine_set_u8("5/0/3", STATE_IDLE);
	lwm2m_engine_set_u8("5/0/5", RESULT_SUCCESS);
	return 1;
}

static int firmware_block_received_cb(u16_t obj_inst_id,
				      u8_t *data, u16_t data_len,
				      bool last_block, size_t total_size)
{
	SYS_LOG_INF("FIRMWARE: BLOCK RECEIVED: len:%u last_block:%d",
		    data_len, last_block);
	return 1;
}

static int set_endpoint_name(char *ep_name, const char *proto)
{
	int ret;
	ret = snprintk(ep_name, ENDPOINT_LEN, "%s-%s", //-%u",
		       CONFIG_BOARD, proto
//		       ,sys_rand32_get()
		      );
	if (ret < 0 || ret >= ENDPOINT_LEN) {
		SYS_LOG_ERR("Can't fill name buffer");
		return -EINVAL;
	}

	return 0;
}

static int lwm2m_setup(void)
{
	struct float32_value float_value;

	/* setup SECURITY object */

	/* setup SERVER object */

	/* setup DEVICE object */

	lwm2m_engine_set_string("3/0/0", CLIENT_MANUFACTURER);
	lwm2m_engine_set_string("3/0/1", CLIENT_MODEL_NUMBER);
	lwm2m_engine_set_string("3/0/2", CLIENT_SERIAL_NUMBER);
	lwm2m_engine_set_string("3/0/3", CLIENT_FIRMWARE_VER);
	lwm2m_engine_register_exec_callback("3/0/4", device_reboot_cb);
	lwm2m_engine_register_exec_callback("3/0/5", device_factory_default_cb);
	lwm2m_engine_set_u8("3/0/9", 95); /* battery level */
	lwm2m_engine_set_u32("3/0/10", 15); /* mem free */
	lwm2m_engine_set_string("3/0/17", CLIENT_DEVICE_TYPE);
	lwm2m_engine_set_string("3/0/18", CLIENT_HW_VER);
	lwm2m_engine_set_u8("3/0/20", LWM2M_DEVICE_BATTERY_STATUS_CHARGING);
	lwm2m_engine_set_u32("3/0/21", 25); /* mem total */

	pwrsrc_bat = lwm2m_device_add_pwrsrc(LWM2M_DEVICE_PWR_SRC_TYPE_BAT_INT);
	if (pwrsrc_bat < 0) {
		SYS_LOG_ERR("LWM2M battery power source enable error (err:%d)",
			pwrsrc_bat);
		return pwrsrc_bat;
	}
	lwm2m_device_set_pwrsrc_voltage_mv(pwrsrc_bat, battery_voltage);
	lwm2m_device_set_pwrsrc_current_ma(pwrsrc_bat, battery_current);

	pwrsrc_usb = lwm2m_device_add_pwrsrc(LWM2M_DEVICE_PWR_SRC_TYPE_USB);
	if (pwrsrc_usb < 0) {
		SYS_LOG_ERR("LWM2M usb power source enable error (err:%d)",
			pwrsrc_usb);
		return pwrsrc_usb;
	}
	lwm2m_device_set_pwrsrc_voltage_mv(pwrsrc_usb, usb_voltage);
	lwm2m_device_set_pwrsrc_current_ma(pwrsrc_usb, usb_current);

	/* setup FIRMWARE object */

	lwm2m_firmware_set_write_cb(firmware_block_received_cb);
	lwm2m_firmware_set_update_cb(firmware_update_cb);

	/* setup TEMP SENSOR object */

	lwm2m_engine_create_obj_inst("3303/0");
	/* dummy temp data in C*/
	float_value.val1 = 25;
	float_value.val2 = 0;
	lwm2m_engine_set_float32("3303/0/5700", &float_value);

	return 0;
}

void main(void)
{
	int ret;
	char ep_name[ENDPOINT_LEN];
	char uri[URI_LEN];

	SYS_LOG_INF(APP_BANNER);

	k_sem_init(&quit_lock, 0, UINT_MAX);

#if defined(CONFIG_NET_L2_BT)
	if (bt_enable(NULL)) {
		SYS_LOG_ERR("Bluetooth init failed");
		return;
	}
	ipss_init();
	ipss_advertise();
#endif

	ret = lwm2m_setup();
	if (ret < 0) {
		SYS_LOG_ERR("Cannot setup LWM2M fields (%d)", ret);
		return;
	}

#if defined(CONFIG_NET_IPV6)
	ret = set_endpoint_name(ep_name, "ipv6");
	if (ret < 0) {
		SYS_LOG_ERR("Cannot set IPv6 endpoint name (%d)", ret);
		return;
	}

#if defined(CONFIG_LWM2M_BOOTSTRAP_SERVER)
	snprintf(uri, URI_LEN-1, "coap://[%s]:%u",
		 CONFIG_NET_APP_PEER_IPV6_ADDR, LWM2M_BOOTSTRAP_PORT);
	ret = lwm2m_rd_client_start(uri, true, ep_name);
#else
	snprintf(uri, URI_LEN-1, "coap://[%s]:%u",
		 CONFIG_NET_APP_PEER_IPV6_ADDR, CONFIG_LWM2M_PEER_PORT);
	ret = lwm2m_rd_client_start(uri, false, ep_name);
#endif
	if (ret < 0) {
		SYS_LOG_ERR("LWM2M init LWM2M IPv6 RD client error (%d)",
			ret);
		return;
	}

	SYS_LOG_INF("IPv6 setup complete.");
#endif

#if defined(CONFIG_NET_IPV4)
	ret = set_endpoint_name(ep_name, "ipv4");
	if (ret < 0) {
		SYS_LOG_ERR("Cannot set IPv4 endpoint name (%d)", ret);
		return;
	}

#if defined(CONFIG_LWM2M_BOOTSTRAP_SERVER)
	snprintf(uri, URI_LEN-1, "coap://%s:%u",
		 CONFIG_NET_APP_PEER_IPV4_ADDR, CONFIG_LWM2M_BOOTSTRAP_PORT);
	ret = lwm2m_rd_client_start(uri, true, ep_name);
#else
	snprintf(uri, URI_LEN-1, "coap://%s:%u",
		 CONFIG_NET_APP_PEER_IPV4_ADDR, CONFIG_LWM2M_PEER_PORT);
	ret = lwm2m_rd_client_start(uri, false, ep_name);
#endif
	if (ret < 0) {
		SYS_LOG_ERR("LWM2M init LWM2M IPv4 RD client error (%d)",
			ret);
		return;
	}

	SYS_LOG_INF("IPv4 setup complete.");
#endif
	k_sem_take(&quit_lock, K_FOREVER);
}
