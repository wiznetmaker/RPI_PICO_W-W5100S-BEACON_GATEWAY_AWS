/**
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include "pico/stdlib.h"

#include "wizchip_conf.h"
#include "w5x00_spi.h"
#include "dhcp.h"
#include "timer.h"
#include "mqtt_transport_interface.h"
#include "ssl_transport_interface.h"
#include "timer_interface.h"
#include "sntp.h"
#include "hardware/rtc.h"

#define RTC_UPDATE_PERIOD 86400000 //24 hours

extern wiz_NetInfo g_net_info;
extern datetime_t rtc_time;
extern datetime sntp_time;


void core1_main(void)
{
    int retval = 0;
    uint32_t start_time, end_time;

    start_time = millis();
    while(1)
    {
        if (g_net_info.dhcp == NETINFO_DHCP)
            DHCP_run();
        retval = mqtt_transport_yield(MQTT_DEFAULT_YIELD_TIMEOUT);
        if (retval != 0)
        {
            printf(" Failed, mqtt_transport_yield returned %d\n", retval);
            while (1);
        }
        end_time = millis();
        if((end_time - start_time) > RTC_UPDATE_PERIOD)
        {
            while(1)
            {
                retval = SNTP_run(&sntp_time);
                if (retval == 1)
                {
                    printf(" %d-%d-%d, %d:%d:%d\n", sntp_time.yy, sntp_time.mo, sntp_time.dd, sntp_time.hh, sntp_time.mm, sntp_time.ss);
                    rtc_time.year = sntp_time.yy;
                    rtc_time.month = sntp_time.mo;
                    rtc_time.day = sntp_time.dd;
                    rtc_time.hour = sntp_time.hh;
                    rtc_time.min = sntp_time.mm;
                    rtc_time.sec = sntp_time.ss;
                    rtc_set_datetime(&rtc_time);
                    break;
                }
            }
        }
    }
}