# Standalone example that connects to picow_ble_temp_sensor and reads the temperature 
# Flahes once quickly each second when it's running but not connected to another device
# Flashes twice quickly each second when connected to another device and reading it's temperature
add_executable(le_scanner
    le_scanner.c
    core1_main.c
    )
target_link_libraries(le_scanner
    pico_stdlib
    pico_btstack_ble
    pico_btstack_cyw43
    pico_cyw43_arch_none
    pico_multicore
    hardware_spi
    hardware_dma
    hardware_rtc
    ETHERNET_FILES
    IOLIBRARY_FILES
    DHCP_FILES
    DNS_FILES
    AWS_SDK_PORT_FILES
    SNTP_FILES
    TIMER_FILES
    mbedcrypto
    mbedx509
    mbedtls
    )
target_include_directories(le_scanner PRIVATE
    ${CMAKE_CURRENT_LIST_DIR} # For btstack config
    )
target_compile_definitions(le_scanner PRIVATE
    RUNNING_AS_CLIENT=1
)

pico_enable_stdio_usb(le_scanner 1)
#pico_enable_stdio_uart(le_scanner 1)
pico_add_extra_outputs(le_scanner)
#example_auto_set_url(le_scanner)
