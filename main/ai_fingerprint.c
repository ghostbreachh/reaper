#include "ai_fingerprint.h"
#include "ai_model.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* ============================================================================
 *  DEVICE FINGERPRINTING (vendor IE + rates + capabilities -> type)
 * ============================================================================
 *
 *  Branch A — Full deep-packet inspection before classification
 *    Decision: REJECTED. Feature 42 classifier already sees raw frames;
 *              fingerprinting should be lightweight tag extraction only.
 *  Branch B — IE tag extractor + model zoo inference
 *    Decision: ACCEPTED. Extracts OUI, supported rates, extended cap,
 *              then calls ai_model_zoo_infer(). Falls back to OUI heuristic.
 *  Branch C — OUI database lookup only
 *    Decision: REJECTED. Vendor OUI alone misses device behavior; rates
 *              and capabilities differentiate phone vs laptop vs IoT better.
 */

static const char *TAG = "ai_fp";

static char            g_model_name[64] = {0};
static bool            g_init_done      = false;
static uint32_t        g_fp_count       = 0;
static uint32_t        g_fp_heuristic   = 0;

static const char *fp_class_name(ai_fp_class_t cls)
{
    switch (cls) {
        case AI_FP_PHONE:   return "phone";
        case AI_FP_LAPTOP:  return "laptop";
        case AI_FP_IOT:     return "iot";
        case AI_FP_AP:      return "ap";
        case AI_FP_ROUTER:  return "router";
        default:            return "unknown";
    }
}

const char *ai_fingerprint_class_name(ai_fp_class_t cls)
{
    return fp_class_name(cls);
}

/**
 * @brief Extract OUI from BSSID (first 3 bytes). */
static void extract_oui(const uint8_t *mac, uint8_t oui[3])
{
    if (mac && oui) {
        memcpy(oui, mac, 3);
    }
}

/**
 * @brief Extract supported rates from IE tag. */
static size_t extract_rates(const uint8_t *ie, size_t ie_len,
                            uint8_t *out_rates, size_t max_rates)
{
    size_t count = 0;
    size_t off = 0;
    while (off + 2 <= ie_len && count < max_rates) {
        uint8_t id = ie[off];
        uint8_t tag_len = ie[off + 1];
        if (off + 2 + tag_len > ie_len) break;

        if (id == 1) {
            /* Supported Rates */
            size_t copy = tag_len < max_rates - count ? tag_len : max_rates - count;
            memcpy(out_rates + count, ie + off + 2, copy);
            count += copy;
        } else if (id == 50) {
            /* Extended Supported Rates */
            size_t copy = tag_len < max_rates - count ? tag_len : max_rates - count;
            memcpy(out_rates + count, ie + off + 2, copy);
            count += copy;
        }

        off += 2 + tag_len;
    }
    return count;
}

/**
 * @brief Extract extended capabilities IE tag. */
static size_t extract_ext_cap(const uint8_t *ie, size_t ie_len,
                              uint8_t *out_cap, size_t max_cap)
{
    size_t off = 0;
    while (off + 2 <= ie_len) {
        uint8_t id = ie[off];
        uint8_t tag_len = ie[off + 1];
        if (off + 2 + tag_len > ie_len) break;

        if (id == 127) {
            size_t copy = tag_len < max_cap ? tag_len : max_cap;
            memcpy(out_cap, ie + off + 2, copy);
            return copy;
        }

        off += 2 + tag_len;
    }
    return 0;
}

/**
 * @brief Build 8-byte feature tensor from fingerprint data. */
static void build_fp_tensor(const uint8_t *oui, uint8_t rate_count,
                            const uint8_t *rates, uint8_t ext_cap_len,
                            const uint8_t *ext_cap, uint8_t subtype,
                            uint8_t *tensor, size_t tensor_sz)
{
    memset(tensor, 0, tensor_sz);
    if (tensor_sz < 8) return;

    tensor[0] = oui ? oui[0] : 0;
    tensor[1] = oui ? oui[1] : 0;
    tensor[2] = oui ? oui[2] : 0;
    tensor[3] = rate_count;
    tensor[4] = ext_cap_len;
    tensor[5] = subtype;
    tensor[6] = rates ? rates[0] : 0;
    tensor[7] = ext_cap ? ext_cap[0] : 0;
}

esp_err_t ai_fingerprint_init(void)
{
    if (g_init_done) return ESP_OK;

    memset(g_model_name, 0, sizeof(g_model_name));
    g_init_done = true;
    g_fp_count = 0;
    g_fp_heuristic = 0;
    ESP_LOGI(TAG, "fingerprint init");
    return ESP_OK;
}

esp_err_t ai_fingerprint_set_model(const char *model_name)
{
    if (model_name == NULL) return ESP_ERR_INVALID_ARG;
    snprintf(g_model_name, sizeof(g_model_name), "%s", model_name);
    ESP_LOGI(TAG, "fingerprint model set: '%s'", g_model_name);
    return ESP_OK;
}

esp_err_t ai_fingerprint_classify(const uint8_t *ie_data, size_t ie_len,
                                  uint8_t subtype, const uint8_t *oui_mac,
                                  ai_fp_result_t *out)
{
    if (ie_data == NULL || out == NULL || !g_init_done) return ESP_ERR_INVALID_STATE;

    memset(out, 0, sizeof(*out));

    uint8_t oui[3] = {0};
    if (oui_mac) memcpy(oui, oui_mac, 3);
    uint8_t rates[8] = {0};
    uint8_t ext_cap[8] = {0};
    uint8_t rate_count = 0;
    uint8_t ext_cap_len = 0;

    /* Extract features from IE tags */
    rate_count = (uint8_t)extract_rates(ie_data, ie_len, rates, 8);
    ext_cap_len = (uint8_t)extract_ext_cap(ie_data, ie_len, ext_cap, 8);

    /* OUI comes from BSSID; set externally via set_oui before classify */
    uint8_t tensor[8];
    build_fp_tensor(oui, rate_count, rates, ext_cap_len, ext_cap, subtype,
                    tensor, sizeof(tensor));

    /* Try model inference */
    if (g_model_name[0] != '\0') {
        size_t out_len = 0;
        uint8_t out_buf[4];
        uint64_t t0 = esp_timer_get_time();
        esp_err_t rc = ai_model_zoo_infer(g_model_name,
                                          tensor, sizeof(tensor),
                                          out_buf, sizeof(out_buf),
                                          &out_len);
        uint64_t dt = esp_timer_get_time() - t0;
        out->inference_us = (uint32_t)dt;

        if (rc == ESP_OK && out_len >= 4) {
            uint8_t cls = out_buf[0];
            if (cls <= AI_FP_ROUTER) {
                out->cls = (ai_fp_class_t)cls;
            } else {
                out->cls = AI_FP_UNKNOWN;
            }
            snprintf(out->label, sizeof(out->label), "%s", fp_class_name(out->cls));
            memcpy(out->oui, oui, 3);
            memcpy(out->rates, rates, rate_count);
            out->rate_count = rate_count;
            memcpy(out->ext_cap, ext_cap, ext_cap_len);
            out->ext_cap_len = ext_cap_len;
            out->model_loaded = true;
            g_fp_count++;
            return ESP_OK;
        }
    }

    /* Heuristic fallback (no ESP-DL or model not loaded) */
    g_fp_heuristic++;

    /* Default label */
    snprintf(out->label, sizeof(out->label), "unknown");

    memcpy(out->oui, oui, 3);
    memcpy(out->rates, rates, rate_count);
    out->rate_count = rate_count;
    memcpy(out->ext_cap, ext_cap, ext_cap_len);
    out->ext_cap_len = ext_cap_len;
    out->model_loaded = false;
    out->inference_us = 0;

    /* OUI hints */
    if (oui[0] == 0x4C && oui[1] == 0x77 && oui[2] == 0x6D) {
        out->cls = AI_FP_PHONE;
        snprintf(out->label, sizeof(out->label), "phone (Apple)");
    } else if (oui[0] == 0xB8 && oui[1] == 0x27 && oui[2] == 0xEB) {
        out->cls = AI_FP_PHONE;
        snprintf(out->label, sizeof(out->label), "phone (Xiaomi)");
    } else if (oui[0] == 0x00 && oui[1] == 0x1A && oui[2] == 0x2B) {
        out->cls = AI_FP_AP;
        snprintf(out->label, sizeof(out->label), "ap (Cisco)");
    } else if (oui[0] == 0xAC && oui[1] == 0x22 && oui[2] == 0x0B) {
        out->cls = AI_FP_IOT;
        snprintf(out->label, sizeof(out->label), "iot (Espressif)");
    } else if (rate_count >= 8) {
        out->cls = AI_FP_LAPTOP;
        snprintf(out->label, sizeof(out->label), "laptop");
    } else if (rate_count >= 4) {
        out->cls = AI_FP_PHONE;
        snprintf(out->label, sizeof(out->label), "phone");
    } else {
        out->cls = AI_FP_UNKNOWN;
    }

    return ESP_OK;
}

esp_err_t ai_fingerprint_json(char *buf, size_t bufsz)
{
    int w = snprintf(buf, bufsz,
        "{\"total\":%lu,\"heuristic\":%lu,\"model\":\"%s\"}",
        (unsigned long)g_fp_count,
        (unsigned long)g_fp_heuristic,
        g_model_name);
    if (w < 0 || (size_t)w >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

void ai_fingerprint_deinit(void)
{
    memset(g_model_name, 0, sizeof(g_model_name));
    g_init_done = false;
    g_fp_count = 0;
    g_fp_heuristic = 0;
    ESP_LOGI(TAG, "fingerprint deinit");
}
