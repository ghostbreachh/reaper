#include "ai_ble_profiler.h"
#include "ai_model.h"
#include "common_types.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* ============================================================================
 *  BLE DEVICE PROFILER (classify beacons as tag/phone/sensor/tracker)
 * ============================================================================
 *
 *  Branch A — Full BLE stack introspection before classification
 *    Decision: REJECTED. Scanner already parses adv data; profiler should
 *              consume the existing ble_info_t, not duplicate parsing.
 *  Branch B — Lightweight feature extractor from ble_info_t + model inference
 *    Decision: ACCEPTED. Reads MAC, flags, AD types, tx_power, adv_mode
 *              from existing scanner state; calls ai_model_zoo_infer().
 *  Branch C — OUI database only
 *    Decision: REJECTED. BLE classification needs behavior signals too:
 *              connectable vs non-connectable, TX power, scan response.
 */

static const char *TAG = "ai_ble";

static char            g_model_name[64] = {0};
static bool            g_init_done      = false;
static uint32_t        g_profile_count  = 0;
static uint32_t        g_heuristic_count= 0;

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

/**
 * @brief Build 8-byte feature tensor from BLE advertisement metadata.
 *
 * Layout:
 *   [0] OUI byte 0
 *   [1] OUI byte 1
 *   [2] OUI byte 2
 *   [3] flags: bit0=has_scan_rsp, bit1=non_conn, bit2=coded_s8, bit3=periodic
 *   [4] tx_power clamped 0..255
 *   [5] adv_mode (0=legacy, 1=non-conn, 2=scan)
 *   [6] reserved
 *   [7] reserved
 */
static void build_ble_tensor(const uint8_t *mac, const ble_info_t *info,
                             uint8_t *tensor, size_t tensor_sz)
{
    memset(tensor, 0, tensor_sz);
    if (tensor_sz < 8 || mac == NULL || info == NULL) return;

    tensor[0] = mac[0];
    tensor[1] = mac[1];
    tensor[2] = mac[2];

    uint8_t flags = 0;
    if (info->has_scan_rsp)     flags |= 0x01;
    if (info->adv_mode == 1)    flags |= 0x02; /* non-connectable */
    if (info->phy_coded_s8)     flags |= 0x04;
    if (info->periodic_adv_seen) flags |= 0x08;
    tensor[3] = flags;

    tensor[4] = (uint8_t)((int32_t)(info->tx_power != 0 ? info->tx_power : -100) + 100);
    tensor[5] = info->adv_mode;
}

esp_err_t ai_ble_profiler_init(void)
{
    if (g_init_done) return ESP_OK;

    memset(g_model_name, 0, sizeof(g_model_name));
    g_init_done = true;
    g_profile_count = 0;
    g_heuristic_count = 0;
    ESP_LOGI(TAG, "BLE profiler init");
    return ESP_OK;
}

esp_err_t ai_ble_profiler_set_model(const char *model_name)
{
    if (model_name == NULL) return ESP_ERR_INVALID_ARG;
    snprintf(g_model_name, sizeof(g_model_name), "%s", model_name);
    ESP_LOGI(TAG, "BLE profiler model set: '%s'", g_model_name);
    return ESP_OK;
}

esp_err_t ai_ble_profiler_classify(const uint8_t *mac,
                                   const uint8_t *adv_data, size_t adv_len,
                                   ai_ble_profile_t *out)
{
    if (mac == NULL || out == NULL || !g_init_done) return ESP_ERR_INVALID_STATE;

    memset(out, 0, sizeof(*out));
    memcpy(out->oui, mac, 3);

    /* Find ble_info_t for this MAC */
    extern ble_info_t *g_ble_list;
    extern uint32_t    g_ble_count;

    const ble_info_t *info = NULL;
    for (uint32_t i = 0; i < g_ble_count; i++) {
        if (memcmp(g_ble_list[i].mac, mac, 6) == 0) {
            info = &g_ble_list[i];
            break;
        }
    }

    /* Fallback stub info if not found yet */
    ble_info_t stub;
    memset(&stub, 0, sizeof(stub));
    if (info == NULL) info = &stub;

    uint8_t tensor[8];
    build_ble_tensor(mac, info, tensor, sizeof(tensor));

    /* Try model inference */
    if (g_model_name[0] != '\0') {
        uint8_t model_out[4];
        size_t out_len = 0;
        uint64_t t0 = esp_timer_get_time();
        esp_err_t rc = ai_model_zoo_infer(g_model_name,
                                          tensor, sizeof(tensor),
                                          model_out, sizeof(model_out),
                                          &out_len);
        uint64_t dt = esp_timer_get_time() - t0;
        out->inference_us = (uint32_t)dt;

        if (rc == ESP_OK && out_len >= 4) {
            uint8_t cls = model_out[0];
            if (cls <= AI_BLE_BEACON) {
                out->cls = (ai_ble_class_t)cls;
            } else {
                out->cls = AI_BLE_UNKNOWN;
            }
            snprintf(out->label, sizeof(out->label), "%s", ble_class_name(out->cls));
            out->adv_type = info->adv_mode;
            out->flags = model_out[1];
            out->model_loaded = true;
            g_profile_count++;
            return ESP_OK;
        }
    }

    /* Heuristic fallback */
    g_heuristic_count++;

    ai_ble_class_t cls = AI_BLE_UNKNOWN;

    /* Heuristic rules based on advertisement behavior */
    if (info->periodic_adv_seen && info->adv_mode == 1) {
        cls = AI_BLE_BEACON;
    } else if (info->has_scan_rsp && info->adv_mode == 1) {
        cls = AI_BLE_TRACKER;
    } else if (info->phy_coded_s8 && info->tx_power < -50) {
        cls = AI_BLE_SENSOR;
    } else if (info->adv_mode == 1 && !info->has_scan_rsp) {
        cls = AI_BLE_TAG;
    } else if (info->rpa_seen && info->has_scan_rsp) {
        cls = AI_BLE_PHONE;
    } else {
        cls = AI_BLE_UNKNOWN;
    }

    out->cls = cls;
    snprintf(out->label, sizeof(out->label), "%s", ble_class_name(cls));
    out->adv_type = info->adv_mode;
    out->flags = 0;
    out->model_loaded = false;
    out->inference_us = 0;
    return ESP_OK;
}

esp_err_t ai_ble_profiler_json(char *buf, size_t bufsz)
{
    int w = snprintf(buf, bufsz,
        "{\"total\":%lu,\"heuristic\":%lu,\"model\":\"%s\"}",
        (unsigned long)g_profile_count,
        (unsigned long)g_heuristic_count,
        g_model_name);
    if (w < 0 || (size_t)w >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

void ai_ble_profiler_deinit(void)
{
    memset(g_model_name, 0, sizeof(g_model_name));
    g_init_done = false;
    g_profile_count = 0;
    g_heuristic_count = 0;
    ESP_LOGI(TAG, "BLE profiler deinit");
}
