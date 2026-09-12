#include "ai_deauth_predictor.h"
#include "ai_model.h"
#include "deauth_engine.h"
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

static const char *TAG = "ai_deauth";

static char g_model_name[64] = {0};

static bool g_init_done = false;

static uint32_t g_model_count = 0;
static uint32_t g_heuristic_count = 0;
static uint32_t g_last_infer_us = 0;

static ai_deauth_prediction_t g_last[AI_DEAUTH_PREDICTOR_MAX_TARGETS];
static uint8_t g_last_count = 0;

static SemaphoreHandle_t g_lock = NULL;
static SemaphoreHandle_t g_infer_lock = NULL;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

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

static bool mac_is_zero(const uint8_t *mac)
{
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0) {
            return false;
        }
    }

    return true;
}

static bool mac_is_broadcast(const uint8_t *mac)
{
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0xFF) {
            return false;
        }
    }

    return true;
}

static bool mac_is_unicast_target(const uint8_t *mac)
{
    if (mac == NULL) {
        return false;
    }

    if (mac_is_zero(mac)) {
        return false;
    }

    if (mac_is_broadcast(mac)) {
        return false;
    }

    /* Multicast bit set means not a normal unicast client. */
    if ((mac[0] & 0x01) != 0) {
        return false;
    }

    return true;
}

static uint8_t normalize_rssi_feature(int8_t rssi)
{
    int32_t v = (int32_t)rssi;

    if (v < -100) {
        v = -100;
    }

    if (v > -10) {
        v = -10;
    }

    /*
     * Map roughly -100..-10 to 0..255.
     */
    int32_t normalized = ((v + 100) * 255) / 90;

    if (normalized < 0) {
        normalized = 0;
    }

    if (normalized > 255) {
        normalized = 255;
    }

    return (uint8_t)normalized;
}

static void store_prediction_locked(uint8_t index, const ai_deauth_prediction_t *pred)
{
    if (index >= AI_DEAUTH_PREDICTOR_MAX_TARGETS || pred == NULL) {
        return;
    }

    g_last[index] = *pred;

    if (index >= g_last_count) {
        g_last_count = (uint8_t)(index + 1);
    }
}

/* -------------------------------------------------------------------------
 *  Feature extraction
 * ----------------------------------------------------------------------- */

static void build_deauth_tensor(const deauth_target_t *target,
                                uint8_t active_target_count,
                                bool pmf_required,
                                bool wpa3,
                                int8_t rssi,
                                uint8_t tensor[8])
{
    memset(tensor, 0, 8);

    uint8_t flags = 0;

    if (pmf_required) {
        flags |= AI_DEAUTH_FLAG_PMF_REQUIRED;
    }

    if (wpa3) {
        flags |= AI_DEAUTH_FLAG_WPA3;
    }

    if (!pmf_required && !wpa3) {
        flags |= AI_DEAUTH_FLAG_UNPROTECTED;
    }

    if (mac_is_unicast_target(target->client_mac)) {
        flags |= AI_DEAUTH_FLAG_UNICAST_TARGET;
    }

    if (target->fallback_level == DEAUTH_FALLBACK_NONE) {
        flags |= AI_DEAUTH_FLAG_NO_FALLBACK;
    }

    if (target->active) {
        flags |= 0x40;
    }

    tensor[0] = flags;
    tensor[1] = normalize_rssi_feature(rssi);
    tensor[2] = active_target_count;
    tensor[3] = (uint8_t)target->fallback_level;
    tensor[4] = (uint8_t)target->mode;

    /*
     * Reserved bytes.
     */
    tensor[5] = 0;
    tensor[6] = 0;
    tensor[7] = 0;
}

/* -------------------------------------------------------------------------
 *  Heuristic fallback
 * ----------------------------------------------------------------------- */

static void heuristic_predict(const deauth_target_t *target,
                              bool pmf_required,
                              bool wpa3,
                              int8_t rssi,
                              float *out_probability,
                              uint8_t *out_flags)
{
    float prob = 0.5f;
    uint8_t flags = 0;

    bool unicast_target = mac_is_unicast_target(target->client_mac);

    if (pmf_required) {
        flags |= AI_DEAUTH_FLAG_PMF_REQUIRED;
        prob = 0.05f;
    }

    if (wpa3) {
        flags |= AI_DEAUTH_FLAG_WPA3;

        if (!pmf_required) {
            prob = 0.20f;
        }
    }

    if (!pmf_required && !wpa3) {
        flags |= AI_DEAUTH_FLAG_UNPROTECTED;
        prob += 0.30f;
    }

    if (rssi >= -60) {
        flags |= AI_DEAUTH_FLAG_STRONG_SIGNAL;
        prob += 0.10f;
    } else if (rssi <= -85) {
        prob -= 0.20f;
    }

    if (unicast_target) {
        flags |= AI_DEAUTH_FLAG_UNICAST_TARGET;
        prob += 0.10f;
    } else {
        /* Broadcast deauth is usually less precise and more likely to be ignored. */
        prob -= 0.10f;
    }

    if (target->fallback_level == DEAUTH_FALLBACK_NONE) {
        flags |= AI_DEAUTH_FLAG_NO_FALLBACK;
        prob += 0.05f;
    }

    /*
     * Protected networks should stay low even if other features look good.
     */
    if (pmf_required && prob > 0.10f) {
        prob = 0.10f;
    }

    if (wpa3 && prob > 0.35f) {
        prob = 0.35f;
    }

    if (prob < 0.0f) {
        prob = 0.0f;
    }

    if (prob > 1.0f) {
        prob = 1.0f;
    }

    *out_probability = prob;
    *out_flags = flags;
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t ai_deauth_predictor_init(void)
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
    memset(g_last, 0, sizeof(g_last));

    g_model_count = 0;
    g_heuristic_count = 0;
    g_last_infer_us = 0;
    g_last_count = 0;

    g_init_done = true;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Deauth predictor initialized");
    return ESP_OK;
}

void ai_deauth_predictor_deinit(void)
{
    if (g_lock == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_model_name, 0, sizeof(g_model_name));
    memset(g_last, 0, sizeof(g_last));

    g_model_count = 0;
    g_heuristic_count = 0;
    g_last_infer_us = 0;
    g_last_count = 0;

    g_init_done = false;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Deauth predictor deinitialized");
}

/* -------------------------------------------------------------------------
 *  Configuration
 * ----------------------------------------------------------------------- */

esp_err_t ai_deauth_predictor_set_model(const char *model_name)
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

    ESP_LOGI(TAG, "Deauth predictor model set: '%s'", g_model_name);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Prediction
 * ----------------------------------------------------------------------- */

esp_err_t ai_deauth_predictor_predict(uint8_t target_index,
                                      ai_deauth_prediction_t *out)
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    if (target_index >= AI_DEAUTH_PREDICTOR_MAX_TARGETS) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t target_count = deauth_get_target_count();

    if (target_index >= target_count) {
        return ESP_ERR_INVALID_ARG;
    }

    deauth_target_t target;
    esp_err_t rc = deauth_get_target(target_index, &target);
    if (rc != ESP_OK) {
        return rc;
    }

    memset(out, 0, sizeof(*out));
    out->target_index = target_index;

    if (!target.active) {
        out->probability = 0.0f;
        out->flags = 0;
        out->model_loaded = false;
        out->inference_us = 0;

        xSemaphoreTake(g_lock, portMAX_DELAY);
        store_prediction_locked(target_index, out);
        xSemaphoreGive(g_lock);

        return ESP_OK;
    }

    bool pmf_required = false;
    bool wpa3 = false;
    wifi_sniffer_get_security(target.bssid, &pmf_required, &wpa3);

    int8_t rssi = -100;
    wifi_sniffer_get_rssi(target.bssid, &rssi);

    uint8_t tensor[8];
    build_deauth_tensor(&target, target_count, pmf_required, wpa3, rssi, tensor);

    char model_local[sizeof(g_model_name)] = {0};
    bool model_enabled = false;

    xSemaphoreTake(g_lock, portMAX_DELAY);
    model_enabled = (g_model_name[0] != '\0');
    if (model_enabled) {
        snprintf(model_local, sizeof(model_local), "%s", g_model_name);
    }
    xSemaphoreGive(g_lock);

    if (model_enabled) {
        uint8_t model_out[4] = {0};
        size_t out_len = 0;

        uint64_t t0 = esp_timer_get_time();

        if (g_infer_lock != NULL) {
            xSemaphoreTake(g_infer_lock, portMAX_DELAY);
        }

        rc = ai_model_zoo_infer(
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

        if (rc == ESP_OK && out_len >= 1) {
            float probability = (float)model_out[0] / 255.0f;
            uint8_t flags = (out_len >= 2) ? model_out[1] : 0;

            xSemaphoreTake(g_lock, portMAX_DELAY);

            g_model_count++;
            g_last_infer_us = (uint32_t)dt;

            out->probability = probability;
            out->flags = flags;
            out->model_loaded = true;
            out->inference_us = g_last_infer_us;

            store_prediction_locked(target_index, out);

            xSemaphoreGive(g_lock);

            return ESP_OK;
        }

        ESP_LOGD(TAG, "Model inference failed or returned invalid data; using heuristic");
    }

    float probability = 0.0f;
    uint8_t flags = 0;

    heuristic_predict(&target, pmf_required, wpa3, rssi, &probability, &flags);

    xSemaphoreTake(g_lock, portMAX_DELAY);

    g_heuristic_count++;

    out->probability = probability;
    out->flags = flags;
    out->model_loaded = false;
    out->inference_us = 0;

    store_prediction_locked(target_index, out);

    xSemaphoreGive(g_lock);

    return ESP_OK;
}

esp_err_t ai_deauth_predictor_predict_all(void)
{
    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t target_count = deauth_get_target_count();

    if (target_count > AI_DEAUTH_PREDICTOR_MAX_TARGETS) {
        target_count = AI_DEAUTH_PREDICTOR_MAX_TARGETS;
    }

    for (uint8_t i = 0; i < target_count; i++) {
        ai_deauth_prediction_t result;
        ai_deauth_predictor_predict(i, &result);
    }

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

esp_err_t ai_deauth_predictor_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    ai_deauth_prediction_t snapshot[AI_DEAUTH_PREDICTOR_MAX_TARGETS];
    uint8_t count = 0;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    count = g_last_count;

    if (count > AI_DEAUTH_PREDICTOR_MAX_TARGETS) {
        count = AI_DEAUTH_PREDICTOR_MAX_TARGETS;
    }

    memcpy(snapshot, g_last, sizeof(ai_deauth_prediction_t) * count);

    xSemaphoreGive(g_lock);

    size_t off = 0;

    if (!json_append(buf, bufsz, &off, "[")) {
        return ESP_ERR_INVALID_SIZE;
    }

    for (uint8_t i = 0; i < count; i++) {
        if (i > 0) {
            if (!json_append(buf, bufsz, &off, ",")) {
                return ESP_ERR_INVALID_SIZE;
            }
        }

        if (!json_append(buf, bufsz, &off,
                         "{\"idx\":%u,\"prob\":%.2f,\"flags\":%u,"
                         "\"model\":%s,\"infer_us\":%" PRIu32 "}",
                         (unsigned)snapshot[i].target_index,
                         (double)snapshot[i].probability,
                         (unsigned)snapshot[i].flags,
                         snapshot[i].model_loaded ? "true" : "false",
                         snapshot[i].inference_us)) {
            return ESP_ERR_INVALID_SIZE;
        }
    }

    if (!json_append(buf, bufsz, &off, "]")) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}
