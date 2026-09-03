#include "ai_deauth_predictor.h"
#include "ai_model.h"
#include "deauth_engine.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* ============================================================================
 *  DEAUTH EFFECTIVENESS PREDICTOR
 * ============================================================================
 *
 *  Branch A — Full deauth simulation model
 *    Decision: REJECTED. Predicting RF behavior from static features is
 *              enough; simulation adds no real value on-device.
 *  Branch B — Per-target feature extraction + model inference + heuristic
 *    Decision: ACCEPTED. Reads deauth target list, builds tensor from
 *              PMF/WPA3 flags, client count, fallback level, RSSI.
 *  Branch C — Static probability table only
 *    Decision: REJECTED. Doesn't adapt to target state; model+heuristic
 *              is more accurate.
 */

static const char *TAG = "ai_deauth";

static char            g_model_name[64] = {0};
static bool            g_init_done      = false;
static uint32_t        g_predict_count  = 0;
static uint32_t        g_heuristic_count= 0;
static ai_deauth_prediction_t g_last[8];

esp_err_t ai_deauth_predictor_init(void)
{
    if (g_init_done) return ESP_OK;

    memset(g_model_name, 0, sizeof(g_model_name));
    memset(g_last, 0, sizeof(g_last));
    g_init_done = true;
    g_predict_count = 0;
    g_heuristic_count = 0;
    ESP_LOGI(TAG, "deauth predictor init");
    return ESP_OK;
}

esp_err_t ai_deauth_predictor_set_model(const char *model_name)
{
    if (model_name == NULL) return ESP_ERR_INVALID_ARG;
    snprintf(g_model_name, sizeof(g_model_name), "%s", model_name);
    ESP_LOGI(TAG, "deauth predictor model set: '%s'", g_model_name);
    return ESP_OK;
}

/**
 * @brief Build 8-byte feature tensor for a target.
 *
 * Layout:
 *   [0] flags: bit0=pmf, bit1=wpa3, bit2=client_active, bit3=fallback_active
 *   [1] RSSI clamped 0..255
 *   [2] target count (active targets)
 *   [3] fallback level
 *   [4] mode (from deauth_mode_t)
 *   [5..7] reserved
 */
static void build_deauth_tensor(uint8_t target_index, uint8_t *tensor)
{
    memset(tensor, 0, 8);
    if (target_index >= (uint8_t)g_deauth_target_count) return;

    const deauth_target_t *t = &g_deauth_targets[target_index];
    bool pmf = false, wpa3 = false;
    wifi_sniffer_get_security(t->bssid, &pmf, &wpa3);

    uint8_t flags = 0;
    if (pmf) flags |= 0x01;
    if (wpa3) flags |= 0x02;
    if (t->client_mac[0] || t->client_mac[1] || t->client_mac[2] ||
        t->client_mac[3] || t->client_mac[4] || t->client_mac[5]) flags |= 0x04;
    if (t->fallback_level != DEAUTH_FALLBACK_NONE) flags |= 0x08;

    int8_t rssi = -100;
    wifi_sniffer_get_rssi(t->bssid, &rssi);
    tensor[0] = flags;
    tensor[1] = (uint8_t)((int32_t)(rssi != 0 ? rssi : -100) + 100);
    tensor[2] = (uint8_t)(g_deauth_target_count > 255 ? 255 : g_deauth_target_count);
    tensor[3] = (uint8_t)(t->fallback_level > 255 ? 255 : t->fallback_level);
    tensor[4] = (uint8_t)(t->mode > 255 ? 255 : t->mode);
}

esp_err_t ai_deauth_predictor_predict(uint8_t target_index,
                                       ai_deauth_prediction_t *out)
{
    if (out == NULL || !g_init_done) return ESP_ERR_INVALID_STATE;
    if (target_index >= (uint8_t)g_deauth_target_count) return ESP_ERR_INVALID_ARG;

    memset(out, 0, sizeof(*out));
    out->target_index = target_index;

    const deauth_target_t *t = &g_deauth_targets[target_index];
    out->target_index = target_index;

    uint8_t tensor[8];
    build_deauth_tensor(target_index, tensor);

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
            out->probability = (float)model_out[0] / 255.0f;
            out->flags = model_out[1];
            out->model_loaded = true;
            g_predict_count++;
            g_last[target_index] = *out;
            return ESP_OK;
        }
    }

    /* Heuristic fallback */
    g_heuristic_count++;

    bool pmf = false, wpa3 = false;
    wifi_sniffer_get_security(t->bssid, &pmf, &wpa3);

    float prob = 0.5f;
    uint8_t flags = 0;
    if (!pmf && !wpa3) {
        prob += 0.4f;
        flags |= 0x01;
    }
    if (rssi > -60) {
        prob += 0.1f;
        flags |= 0x02;
    }
    if (t->client_mac[0] || t->client_mac[1]) {
        prob += 0.1f;
        flags |= 0x04;
    }
    if (t->fallback_level == DEAUTH_FALLBACK_NONE) {
        prob += 0.05f;
        flags |= 0x08;
    }

    if (prob > 1.0f) prob = 1.0f;
    out->probability = prob;
    out->flags = flags;
    out->model_loaded = false;
    out->inference_us = 0;
    g_last[target_index] = *out;
    return ESP_OK;
}

esp_err_t ai_deauth_predictor_predict_all(void)
{
    for (int i = 0; i < g_deauth_target_count && i < 8; i++) {
        ai_deauth_predictor_predict((uint8_t)i, &g_last[i]);
    }
    return ESP_OK;
}

esp_err_t ai_deauth_predictor_json(char *buf, size_t bufsz)
{
    int w = snprintf(buf, bufsz, "[");
    if (w < 0 || (size_t)w >= bufsz) return ESP_ERR_NO_MEM;

    for (int i = 0; i < g_deauth_target_count && i < 8 && (size_t)w < bufsz; i++) {
        int n = snprintf(buf + w, bufsz - w,
            "%s{\"idx\":%d,\"prob\":%.2f,\"flags\":%d,"
            "\"model\":%s,\"infer_us\":%lu}",
            i == 0 ? "" : ",",
            i,
            (double)g_last[i].probability,
            g_last[i].flags,
            g_last[i].model_loaded ? "true" : "false",
            (unsigned long)g_last[i].inference_us);
        if (n < 0 || (size_t)n >= bufsz - w) break;
        w += n;
    }

    if ((size_t)w + 1 >= bufsz) return ESP_ERR_NO_MEM;
    buf[w++] = ']';
    buf[w] = '\0';
    return ESP_OK;
}

void ai_deauth_predictor_deinit(void)
{
    memset(g_model_name, 0, sizeof(g_model_name));
    memset(g_last, 0, sizeof(g_last));
    g_init_done = false;
    g_predict_count = 0;
    g_heuristic_count = 0;
    ESP_LOGI(TAG, "deauth predictor deinit");
}
