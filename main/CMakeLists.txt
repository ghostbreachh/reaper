# ============================================================================
#  REAPER — main application component
#  Target: ESP32-S3-N16R8
# ============================================================================

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
    ota_http.c
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

# ----------------------------------------------------------------------
# Stable requirements (present in IDF 5.x and 6.x)
#
# NOTE: esp_ota_ops is intentionally NOT listed.
#       The OTA API is provided by app_update.
# ----------------------------------------------------------------------
set(priv_reqs
    app_update
    bt
    console
    esp_event
    esp_http_client
    esp_http_server
    esp_https_ota
    esp_netif
    esp_system
    esp_timer
    esp_wifi
    fatfs
    freertos
    hal
    heap
    log
    lwip
    mbedtls
    nvs_flash
    sdmmc
    soc
    spi_flash
    vfs
)

# ----------------------------------------------------------------------
# Version-sensitive requirements
#
# IDF 5.3+ split `driver` into granular components, and some subsystems
# moved between releases. Resolve these by actual presence in the SDK
# rather than hard-coding a version-specific name.
# ----------------------------------------------------------------------
set(idf_optional_reqs
    driver
    json
    spiffs
    led_strip
    efuse
    bootloader_support
    esp_security
    esp_app_format
    esp_coex
    esp_partition
    esp_psram
    esp_hw_support
    esp_driver_gpio
    esp_driver_uart
    esp_driver_spi
    esp_driver_rmt
    esp_driver_tsens
    esp_driver_sdspi
    esp_driver_usb_serial_jtag
    esp_ota_ops
    usb
    tinyusb
)

foreach(req IN LISTS idf_optional_reqs)
    if(EXISTS "${IDF_PATH}/components/${req}")
        list(APPEND priv_reqs "${req}")
        message(STATUS "reaper: using IDF component '${req}'")
    endif()
endforeach()

# ----------------------------------------------------------------------
# led_strip is a managed component (espressif/led_strip).
# It is resolved via idf_component.yml and made available to this build.
# ----------------------------------------------------------------------

idf_component_register(
    SRCS ${reaper_srcs}
    INCLUDE_DIRS "."
    PRIV_REQUIRES ${priv_reqs}
)

# ----------------------------------------------------------------------
# Compiler warnings
# ----------------------------------------------------------------------
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Os
    -Wall
    -Wextra
    -Wno-unused-parameter
    -Wno-error=format
    -Wno-error=format-truncation
    -Wno-error=stringop-truncation
    -Wno-error=deprecated-declarations
)

# ----------------------------------------------------------------------
# Raw 802.11 TX sanity-check override
#
# tx_bypass.c must define:
#   int __wrap_ieee80211_raw_frame_sanity_check(int32_t, int32_t, int32_t);
#
# Without this wrap, esp_wifi_80211_tx() silently drops injected frames.
# ----------------------------------------------------------------------
target_link_options(${COMPONENT_LIB} INTERFACE
    "-Wl,--wrap=ieee80211_raw_frame_sanity_check"
)
