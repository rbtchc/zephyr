/*
 * Copyright (c) 2017 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <board.h>
#include <zephyr.h>
#include <net/net_core.h>
#include <net/net_pkt.h>
#include <net/net_mgmt.h>
#include <net/lwm2m.h>

#if defined(CONFIG_NET_L2_BLUETOOTH)
#include <bluetooth/bluetooth.h>
#include <gatt/ipss.h>
#endif

#if defined(CONFIG_NET_IPV6)
#define LWM2M_AF_INET		AF_INET6
#define NET_SIN_FAMILY(s)	net_sin6(s)->sin6_family
#define NET_SIN_ADDR(s)		net_sin6(s)->sin6_addr
#define NET_SIN_SIZE		sizeof(struct sockaddr_in6)
#define LOCAL_IPADDR		CONFIG_NET_APP_MY_IPV6_ADDR
#define PEER_IPADDR		CONFIG_NET_APP_PEER_IPV6_ADDR
#elif defined(CONFIG_NET_IPV4)
#define LWM2M_AF_INET		AF_INET
#define NET_SIN_FAMILY(s)	net_sin(s)->sin_family
#define NET_SIN_ADDR(s)		net_sin(s)->sin_addr
#define NET_SIN_SIZE		sizeof(struct sockaddr_in)
#define LOCAL_IPADDR		CONFIG_NET_APP_MY_IPV4_ADDR
#define PEER_IPADDR		CONFIG_NET_APP_PEER_IPV4_ADDR
#endif

#define LWM2M_DEVICE_MANUFACTURER	"Zephyr"
#define LWM2M_DEVICE_MODEL_NUMBER	"OMA-LWM2M Sample Client"
#define LWM2M_DEVICE_SERIAL_NUMBER	"345000123"
#define LWM2M_DEVICE_FIRMWARE_VER	"1.0"
#define LWM2M_DEVICE_HW_VER		"1.0.1"
#define LWM2M_DEVICE_TYPE		"OMA-LWM2M Client"


static struct sockaddr client_addr;

#if defined(CONFIG_NET_MGMT_EVENT)
static struct net_mgmt_event_callback cb;
#endif

static int battery_voltage = 3800;
static int battery_current = 125;
static int usb_voltage = 5000;
static int usb_current = 900;

static void device_reboot_cb(void)
{
	NET_INFO("DEVICE: REBOOT");
	/* Add an error for testing */
	lwm2m_device_add_err(LWM2M_DEVICE_ERROR_LOW_POWER);
	/* Change the battery voltage for testing */
	lwm2m_device_set_pwr_src_voltage_mv(LWM2M_PWR_SRC_BATTERY_INTERNAL,
					    --battery_voltage);
}

static void device_factory_default_cb(void)
{
	NET_INFO("DEVICE: FACTORY DEFAULT");
	/* Add an error for testing */
	lwm2m_device_add_err(LWM2M_DEVICE_ERROR_GPS_FAILURE);
	/* Change the USB current for testing */
	lwm2m_device_set_pwr_src_current_ma(LWM2M_PWR_SRC_USB, --usb_current);
}

static int firmware_block_received_cb(
	u8_t *data, u16_t data_len, bool last_block, size_t total_size)
{
	NET_INFO("FIRMWARE: BLOCK RECEIVED");
	return 0;
}

static int lwm2m_start(void)
{
	int r;
	char endpoint_name[32];

	r = snprintk(endpoint_name, sizeof(endpoint_name), "%s-%u",
		     CONFIG_BOARD, sys_rand32_get());
	if (r < 0 || r >= sizeof(endpoint_name)) {
		NET_ERR("Can't fill name buffer");
		return -EINVAL;
	}

	/* setup SECURITY values */
	/* setup SERVER values */

	/* setup DEVICE values / callbacks */
	lwm2m_device_set_manufacturer(LWM2M_DEVICE_MANUFACTURER);
	lwm2m_device_set_model_no(LWM2M_DEVICE_MODEL_NUMBER);
	lwm2m_device_set_serial_no(LWM2M_DEVICE_SERIAL_NUMBER);
	lwm2m_device_set_firmware_version(LWM2M_DEVICE_FIRMWARE_VER);
	lwm2m_device_set_hardware_version(LWM2M_DEVICE_HW_VER);
	lwm2m_device_set_type(LWM2M_DEVICE_TYPE);
	lwm2m_device_set_mem_total_kb(25);
	lwm2m_device_set_mem_free_kb(15);
	lwm2m_device_set_reboot_cb(device_reboot_cb);
	lwm2m_device_set_factory_default_cb(device_factory_default_cb);
	r = lwm2m_device_enable_pwr_src(LWM2M_PWR_SRC_BATTERY_INTERNAL,
					battery_voltage, battery_current);
	if (r) {
		NET_ERR("LWM2M battery power source enable error (err:%d)", r);
		return r;
	}

	r = lwm2m_device_enable_pwr_src(LWM2M_PWR_SRC_USB, usb_voltage,
					usb_current);
	if (r) {
		NET_ERR("LWM2M usb power source enable error (err:%d)", r);
		return r;
	}

	/* set the battery information after enabling BATTERY_INTERNAL */
	lwm2m_device_set_battery_level(95);
	lwm2m_device_set_battery_status(LWM2M_DEVICE_BATTERY_CHARGING);


	/* setup FIRMWARE callback */
	lwm2m_firmware_set_block_received_cb(firmware_block_received_cb);


	/* start LWM2M engine */
	r = lwm2m_engine_init(endpoint_name, &client_addr, PEER_IPADDR);
	if (r) {
		NET_ERR("LWM2M client error (err:%d)", r);
		return r;
	}

	return r;
}

static void event_iface_up(struct net_mgmt_event_callback *cb,
			   u32_t mgmt_event, struct net_if *iface)
{
	int r;

	if (!iface) {
		SYS_LOG_ERR("No network interface specified!");
		return;
	}

	/* Client IP information */
#if defined(CONFIG_NET_IPV6)
	net_addr_pton(LWM2M_AF_INET, LOCAL_IPADDR, &NET_SIN_ADDR(&client_addr));
	net_if_ipv6_addr_add(iface,
			     &NET_SIN_ADDR(&client_addr),
			     NET_ADDR_MANUAL, 0);
/*
 * For IPv6 via ethernet, Zephyr does not support an autoconfiguration
 * method such as DHCPv6.  Use IPv4 until it's implemented if this is
 * required.
 */
#elif defined(CONFIG_NET_IPV4)
#if defined(CONFIG_NET_DHCPV4)
	net_dhcpv4_start(iface);

	/* Add delays so DHCP can assign IP */
	/* TODO: add a timeout/retry */
	SYS_LOG_INF("Waiting for DHCP");
	do {
		k_sleep(K_SECONDS(1));
	} while (net_is_ipv4_addr_unspecified(&iface->dhcpv4.requested_ip));
	SYS_LOG_INF("Done!");

	/* TODO: add a timeout */
	SYS_LOG_INF("Waiting for IP assignment");
	do {
		k_sleep(K_SECONDS(1));
	} while (!net_is_my_ipv4_addr(&iface->dhcpv4.requested_ip));
	SYS_LOG_INF("Done!");

	net_ipaddr_copy(&NET_SIN_ADDR(&client_addr),
			&iface->dhcpv4.requested_ip);
#else
	net_addr_pton(LWM2M_AF_INET, LOCAL_IPADDR, &NET_SIN_ADDR(&client_addr));
	net_if_ipv4_addr_add(iface,
			     &NET_SIN_ADDR(&client_addr),
			     NET_ADDR_MANUAL, 0);
#endif
#endif
	NET_SIN_FAMILY(&client_addr) = LWM2M_AF_INET;

	r = lwm2m_start();
	if (r) {
		NET_ERR("Problems starting LWM2M (err:%d)", r);
	}

	return;
}

void main(void)
{
	struct net_if *iface = net_if_get_default();

	/* HACK: let some network interfaces init */
	k_sleep(K_SECONDS(5));

#if defined(CONFIG_NET_L2_BLUETOOTH)
	if (bt_enable(NULL)) {
		NET_ERR("Bluetooth init failed\n");
		return;
	}
#endif

#if defined(CONFIG_NET_MGMT_EVENT)
	/* Subscribe to NET_IF_UP if interface is not ready */
	if (!atomic_test_bit(iface->flags, NET_IF_UP)) {
		net_mgmt_init_event_callback(&cb, event_iface_up,
					     NET_EVENT_IF_UP);
		net_mgmt_add_event_callback(&cb);
		return;
	}
#endif

	event_iface_up(NULL, NET_EVENT_IF_UP, iface);
}
