# Main application component.
#
# For now this remains a single large component.
# Long term, many of these subsystems should become separate components:
#   transport/
#   wifi/
#   ble/
#   ai/
#   storage/
#   offensive/
#   platform/
#
# But this explicit source list is still better than GLOB.

set(reaper_srcs
    # ------------------------------------------------------------------
    # Core
    # ------------------------------------------------------------------
    main.c

    # ------------------------------------------------------------------
    # Platform
    # ------------------------------------------------------------------
    platform_antitamper.c
    platform_config.c
    platform_factory_test.c
    platform_fleet.c
    platform_plugins.c
    platform_secure_boot.c

    # ------------------------------------------------------------------
    # System health / logging / watchdog
    # ------------------------------------------------------------------
    health_ai_monitor.c
    health_telemetry.c
    structured_log.c
    watchdog.c

    # ------------------------------------------------------------------
    # Control / transport / RPC
    # ------------------------------------------------------------------
    cli_flipper.c
    cli_module.c
    cli_transport.c
    jsonrpc.c
    jsonrpc_schema.c
    ota_http.c           # <-- ADDED: Was missing from build
    port_detect.c
    usb_cdc.c

    # ------------------------------------------------------------------
    # Storage / export
    # ------------------------------------------------------------------
    export.c
    nvs_persist.c
    storage_sd.c
    storage_spiffs.c
    wordlist_manager.c

    # ------------------------------------------------------------------
    # Wi-Fi core
    # ------------------------------------------------------------------
    channel_hopper.c
    coex.c
    pcap_ring.c
    wifi_rrm.c
    wifi_sniffer.c
    # wifi_tx_fix.c      # <-- ADD THIS if you have a .c file for it

    # ------------------------------------------------------------------
    # Wi-Fi security / field modules
    # ------------------------------------------------------------------
    arp_poison.c
    attack_planner.c
    beacon_spam.c
    btm.c
    cred_sniffer.c
    deauth_engine.c
    dragonfly_sim.c
    eap_capture.c
    extra_offense.c
    ft_roam.c
    handshake_crack.c
    neighbor_report.c
    offensive.c
    pmkid.c
    reaction_rules.c
    sae_sidechannel.c
    scheduler.c
    stealth.c
    tx_bypass.c
    wardrive.c
    wps_pixiedust.c

    # ------------------------------------------------------------------
    # BLE
    # ------------------------------------------------------------------
    ble_ext_adv.c
    ble_findmy.c
    ble_gatt_client.c
    ble_gatt_enumerator.c
    ble_iso.c
    ble_mitm.c
    ble_periodic.c
    ble_phy.c
    ble_privacy.c
    ble_rpa_bypass.c
    ble_scanner.c
    ble_smarttag.c

    # ------------------------------------------------------------------
    # AI
    # ------------------------------------------------------------------
    ai_anomaly.c
    ai_ble_profiler.c
    ai_channel_predictor.c
    ai_classifier.c
    ai_deauth_predictor.c
    ai_fingerprint.c
    ai_handshake_quality.c
    ai_model.c
    ai_rogue_detector.c
    ai_training.c

    # ------------------------------------------------------------------
    # Misc radios / hardware / stubs
    # ------------------------------------------------------------------
    gps.c
    led_indicator.c
    matter_commissioner.c
    thread_border_router.c
    zigbee_sniffer.c
)

set(priv_reqs
    app_update
    bt
    console
    driver
    esp_event
    esp_http_client
    esp_http_server
    esp_https_ota
    esp_netif
    esp_ota_ops
    esp_system
    esp_timer
    esp_wifi
    fatfs
    freertos
    hal
    heap
    json
    led_strip
    log
    lwip
    mbedtls
    nvs_flash
    sdmmc
    soc
    spi_flash
    spiffs
    vfs
)

# ----------------------------------------------------------------------
# USB device support
# ----------------------------------------------------------------------
if(EXISTS "${IDF_PATH}/components/tinyusb")
    list(APPEND priv_reqs tinyusb)
endif()

# ----------------------------------------------------------------------
# ESP-IDF 5.3+ split driver components
# ----------------------------------------------------------------------
foreach(opt_drv
        esp_driver_gpio
        esp_driver_uart
        esp_driver_spi
        esp_driver_usb_serial_jtag)
    if(EXISTS "${IDF_PATH}/components/${opt_drv}")
        list(APPEND priv_reqs ${opt_drv})
    endif()
endforeach()

idf_component_register(
    SRCS ${reaper_srcs}
    INCLUDE_DIRS "."
    PRIV_REQUIRES ${priv_reqs}
)

# ----------------------------------------------------------------------
# Compiler warnings
# ----------------------------------------------------------------------
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
)

# ----------------------------------------------------------------------
# Raw 802.11 frame sanity-check override
# ----------------------------------------------------------------------
target_link_options(${COMPONENT_LIB} INTERFACE
    "-Wl,--wrap=ieee80211_raw_frame_sanity_check"
)
