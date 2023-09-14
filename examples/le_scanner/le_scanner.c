/**
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include "btstack.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"
#include <inttypes.h>

#include "wizchip_conf.h"
#include "w5x00_spi.h"
#include "dhcp.h"
#include "timer.h"
#include "mqtt_transport_interface.h"
#include "ssl_transport_interface.h"
#include "timer_interface.h"
#include "mqtt_certificate.h"
#include "pico/binary_info.h"
#include "pico/critical_section.h"
#include "pico/multicore.h"
#include "pico/util/datetime.h"
#include "hardware/spi.h"
#include "hardware/dma.h"
#include "hardware/clocks.h"
#include "hardware/rtc.h"
#include "core1_main.h"
#include "sntp.h"

#if 1
#define DEBUG_LOG(...) printf(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

#define TIMER1_PERIOD 1000

/* Clock */
#define PLL_SYS_KHZ (133 * 1000)

/* Buffer */
#define ETHERNET_BUF_MAX_SIZE (1024 * 2)

/* Socket */
#define SOCKET_MQTT 0
#define SOCKET_DHCP 1
#define SOCKET_SNTP 2
// socket number 3 is used in dns interface

/* Port */
#define TARGET_PORT 8883

/* AWS IoT */
#define MQTT_DOMAIN "account-specific-prefix-ats.iot.ap-northeast-2.amazonaws.com"
#define MQTT_PUB_TOPIC "$aws/things/my_rp2040_thing/shadow/update"
#define MQTT_SUB_TOPIC "$aws/things/my_rp2040_thing/shadow/update/accepted"
#define MQTT_USERNAME NULL
#define MQTT_PASSWORD NULL
#define MQTT_CLIENT_ID "my_rp2040_thing"

#define TIMEZONE 40 // Korea

static btstack_packet_callback_registration_t hci_event_callback_registration;

static bd_addr_t server_addr;
static btstack_timer_source_t timer_1;

static uint8_t json_buf[2048];
datetime_t rtc_time;
datetime sntp_time;

/* Network */
wiz_NetInfo g_net_info =
    {
        .mac = {0x00, 0x08, 0xDC, 0x12, 0x34, 0x56}, // MAC address
        .ip = {192, 168, 11, 2},                     // IP address
        .sn = {255, 255, 255, 0},                    // Subnet Mask
        .gw = {192, 168, 11, 1},                     // Gateway
        .dns = {8, 8, 8, 8},                         // DNS server
        .dhcp = NETINFO_DHCP                         // DHCP
};
static uint8_t g_ethernet_buf[ETHERNET_BUF_MAX_SIZE];
static uint8_t g_mqtt_buf[MQTT_BUF_MAX_SIZE];
uint8_t g_mqtt_pub_msg_buf[MQTT_BUF_MAX_SIZE];
tlsContext_t g_mqtt_tls_context;
static uint8_t g_sntp_server_ip[4] = {216, 239, 35, 0};

static void set_clock_khz(void);
static void wizchip_dhcp_init(void);
static void wizchip_dhcp_assign(void);
static void wizchip_dhcp_conflict(void);


static void client_start(void){
    DEBUG_LOG("Start scanning!\n");
    //gap_set_scan_parameters(0,0x0030, 0x0030);
    gap_set_scan_parameters(0,0x0C80, 0x0030);
    gap_start_scan();
}

static void hci_event_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size) {
    UNUSED(size);
    UNUSED(channel);
    bd_addr_t local_addr;
    uint8_t data_str[128];
    uint32_t json_buf_len;

    if (packet_type != HCI_EVENT_PACKET) return;

    uint8_t event_type = hci_event_packet_get_type(packet);
    switch(event_type){
        case BTSTACK_EVENT_STATE:
            if (btstack_event_state_get_state(packet) == HCI_STATE_WORKING) {
                gap_local_bd_addr(local_addr);
                printf("BTstack up and running on %s.\n", bd_addr_to_str(local_addr));
                client_start();
            }
            break;
        case GAP_EVENT_ADVERTISING_REPORT:
            gap_event_advertising_report_get_address(packet, server_addr);
            uint8_t event_type = gap_event_advertising_report_get_advertising_event_type(packet);
            uint8_t address_type = gap_event_advertising_report_get_address_type(packet);
            int8_t rssi = gap_event_advertising_report_get_rssi(packet);
            uint8_t length = gap_event_advertising_report_get_data_length(packet);
            const uint8_t * data = gap_event_advertising_report_get_data(packet);

            if (rssi < -60) return;

            sprintf(data_str, "0x");
            for(uint32_t i=0; i<length; i++)
                sprintf(data_str+2+(i*2),"%02X", data[i]);
            
            rtc_get_datetime(&rtc_time);

            //printf("get RTC time = %04d%02d%02d%02d%02d%02d\r\n", rtc_time.year, rtc_time.month, rtc_time.day, rtc_time.hour, rtc_time.min, rtc_time.sec);
            printf("get RTC time = %04d-%02d-%02d %02d:%02d:%02d\r\n", rtc_time.year, rtc_time.month, rtc_time.day, rtc_time.hour, rtc_time.min, rtc_time.sec);

            json_buf_len = sprintf(json_buf, "{\r\n\"addr-type\":\"%u\",\"addr\":\"%s\",\"evt-type\":\"%u\",\"rssi\":\"%d\",\"data\":\"%s\",\"data_len\":\"%u\",\"date\":\"%04d-%02d-%02d %02d:%02d:%02d\"\r\n}", \
                    address_type, bd_addr_to_str(server_addr), event_type, rssi, data_str, length, rtc_time.year, rtc_time.month, rtc_time.day, rtc_time.hour, rtc_time.min, rtc_time.sec);

            printf("%s\r\n",json_buf);

            mqtt_transport_publish(MQTT_PUB_TOPIC, json_buf, json_buf_len, 0);
            
            break;
    }
}

static void heartbeat_handler(struct btstack_timer_source *ts) {
    // Invert the led
    static bool quick_flash;
    static bool led_on = true;

    led_on = !led_on;
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, led_on);
    
    // Restart timer
    //btstack_run_loop_set_timer(ts, (led_on || quick_flash) ? LED_QUICK_FLASH_DELAY_MS : LED_SLOW_FLASH_DELAY_MS);
    btstack_run_loop_set_timer(ts, TIMER1_PERIOD);
    btstack_run_loop_add_timer(ts);
}

/**
 * ----------------------------------------------------------------------------------------------------
 * Functions
 * ----------------------------------------------------------------------------------------------------
 */
/* Clock */
static void set_clock_khz(void)
{
    // set a system clock frequency in khz
    set_sys_clock_khz(PLL_SYS_KHZ, true);

    // configure the specified clock
    clock_configure(
        clk_peri,
        0,                                                // No glitchless mux
        CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLKSRC_PLL_SYS, // System PLL on AUX mux
        PLL_SYS_KHZ * 1000,                               // Input frequency
        PLL_SYS_KHZ * 1000                                // Output (must be same as no divider)
    );
}

/* DHCP */
static void wizchip_dhcp_init(void)
{
    printf(" DHCP client running\n");
    DHCP_init(SOCKET_DHCP, g_ethernet_buf);
    reg_dhcp_cbfunc(wizchip_dhcp_assign, wizchip_dhcp_assign, wizchip_dhcp_conflict);
}

static void wizchip_dhcp_assign(void)
{
    getIPfromDHCP(g_net_info.ip);
    getGWfromDHCP(g_net_info.gw);
    getSNfromDHCP(g_net_info.sn);
    getDNSfromDHCP(g_net_info.dns);

    g_net_info.dhcp = NETINFO_DHCP;

    /* Network initialize */
    network_initialize(g_net_info); // apply from DHCP

    print_network_information(g_net_info);
    printf(" DHCP leased time : %ld seconds\n", getDHCPLeasetime());
}

static void wizchip_dhcp_conflict(void)
{
    printf(" Conflict IP from DHCP\n");
    while (1);
}


int main() {
    int retval = 0;

    set_clock_khz();
    stdio_init_all();
    sleep_ms(300);

    wizchip_spi_initialize();
    wizchip_cris_initialize();

    wizchip_reset();
    wizchip_initialize();
    wizchip_check();
    wizchip_1ms_timer_initialize(repeating_timer_callback);

    if (g_net_info.dhcp == NETINFO_DHCP) // DHCP
    {
        wizchip_dhcp_init();
        while (1)
        {
            retval = DHCP_run();
            if (retval == DHCP_IP_LEASED)
                break;
            sleep_ms(1000);
        }
    }
    else // static
    {
        network_initialize(g_net_info);
        print_network_information(g_net_info);
    }

    SNTP_init(SOCKET_SNTP, g_sntp_server_ip, TIMEZONE, g_ethernet_buf);
    while(1)
    {
        retval = SNTP_run(&sntp_time);
        if (retval == 1)
        {
            printf(" %d-%d-%d, %d:%d:%d\n", sntp_time.yy, sntp_time.mo, sntp_time.dd, sntp_time.hh, sntp_time.mm, sntp_time.ss);
            break;
        }
    }

    rtc_init();
    rtc_time.year = sntp_time.yy;
    rtc_time.month = sntp_time.mo;
    rtc_time.day = sntp_time.dd;
    rtc_time.hour = sntp_time.hh;
    rtc_time.min = sntp_time.mm;
    rtc_time.sec = sntp_time.ss;
    rtc_set_datetime(&rtc_time);

    /* Setup certificate */
    g_mqtt_tls_context.rootca_option = MBEDTLS_SSL_VERIFY_REQUIRED; // use Root CA verify
    g_mqtt_tls_context.clica_option = 1;                            // use client certificate
    g_mqtt_tls_context.root_ca = mqtt_root_ca;
    g_mqtt_tls_context.client_cert = mqtt_client_cert;
    g_mqtt_tls_context.private_key = mqtt_private_key;

    retval = mqtt_transport_init(true, MQTT_CLIENT_ID, NULL, NULL, MQTT_DEFAULT_KEEP_ALIVE);

    if (retval != 0)
    {
        printf(" Failed, mqtt_transport_init returned %d\n", retval);
        while (1);
    }

    retval = mqtt_transport_connect(SOCKET_MQTT, 1, g_mqtt_buf, MQTT_BUF_MAX_SIZE, MQTT_DOMAIN, TARGET_PORT, &g_mqtt_tls_context);
    if (retval != 0)
    {
        printf(" Failed, mqtt_transport_connect returned %d\n", retval);
        while (1);
    }
    retval = mqtt_transport_subscribe(0, MQTT_SUB_TOPIC);
    if (retval != 0)
    {
        printf(" Failed, mqtt_transport_subscribe returned %d\n", retval);
        while (1);
    }

    multicore_launch_core1(core1_main);

    // initialize CYW43 driver architecture (will enable BT if/because CYW43_ENABLE_BLUETOOTH == 1)
    if (cyw43_arch_init()) {
        printf("failed to initialise cyw43_arch\n");
        return -1;
    }

    l2cap_init();
    sm_init();
    sm_set_io_capabilities(IO_CAPABILITY_NO_INPUT_NO_OUTPUT);

    // setup empty ATT server - only needed if LE Peripheral does ATT queries on its own, e.g. Android and iOS
    att_server_init(NULL, NULL, NULL);
    gatt_client_init();

    hci_event_callback_registration.callback = &hci_event_handler;
    hci_add_event_handler(&hci_event_callback_registration);

    // set one-shot btstack timer
    timer_1.process = &heartbeat_handler;
    btstack_run_loop_set_timer(&timer_1, TIMER1_PERIOD);
    btstack_run_loop_add_timer(&timer_1);

    // turn on!
    hci_power_control(HCI_POWER_ON);


    // btstack_run_loop_execute is only required when using the 'polling' method (e.g. using pico_cyw43_arch_poll library).
    // This example uses the 'threadsafe background` method, where BT work is handled in a low priority IRQ, so it
    // is fine to call bt_stack_run_loop_execute() but equally you can continue executing user code.

#if 1 // this is only necessary when using polling (which we aren't, but we're showing it is still safe to call in this case)
    btstack_run_loop_execute();
#else
    // this core is free to do it's own stuff except when using 'polling' method (in which case you should use 
    // btstacK_run_loop_ methods to add work to the run loop.

    // this is a forever loop in place of where user code would go.
    while(true) {      
        sleep_ms(1000);
    }
#endif
    return 0;
}
