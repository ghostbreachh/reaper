idf_component_register(SRCS "main.c"
                       "led_indicator.c"
                       "wifi_sniffer.c"
                       "ble_scanner.c"
                       "storage_sd.c"
                       "deauth_engine.c"
                       "arp_poison.c"
                       "handshake_crack.c"
                       "pcap_ring.c"
                       "cli_module.c"
                       "cred_sniffer.c"
                       "beacon_spam.c"
                       "extra_offense.c"
                       INCLUDE_DIRS "."
                       REQUIRES led_strip freertos esp_wifi nvs_flash spi_flash esp_event esp_netif bt esp_driver_spi esp_driver_uart esp_driver_gpio esp_http_server lwip fatfs sdmmc mbedtls)
          


target_link_options(${COMPONENT_LIB} PRIVATE "-Wl,--wrap=ieee80211_raw_frame_sanity_check")