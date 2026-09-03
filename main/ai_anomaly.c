#include "ai_anomaly.h"
#include "ai_model.h"
#include <string.h>
#include <stdio.h>
#include <math.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* ============================================================================
 *  ANOMALY DETECTOR (autoencoder on timing/RSSI/size)
 * ============================================================================
 *
 *  Branch A — External anomaly library
 *    Decision: REJECTED. Keep it self-contained; reuse model zoo.
 *  Branch B — Sliding-window feature extractor + autoencoder inference
 *    Decision: ACCEPTED. Feeds windowed stats through model zoo; soft-falls
 *              back to z-score if ESP-DL not linked.
 *  Branch C — Central limit theorem only, no inference
 *    Decision: REJECTED. Autoencoder captures nonlinear patterns; simple
 *              Gaussian z-score misses coordinated bursts and fuzzing.
 */

static const char *TAG = "ai_anom";

typedef struct {
    int8_t   rssi;
    uint16_t frame_len;
    uint64_t timestamp_us;
} ai_anom_pkt_t;

static ai_anom_pkt_t   g_window[AI_ANOMALY_WINDOW];
static uint32_t        g_widx      = 0;
static uint32_t        g_wcount    = 0;
static uint32_t        g_pkt_total = 0;
static uint32_t        g_anom_total= 0;
static char            g_model_name[64] = {0};
static float           g_threshold = 0.5f;
static bool            g_init_done = false;
static float           g_last_score = 0.0f;
static bool            g_last_anomaly = false;

static float rolling_mean(const uint32_t *values, uint32_t count, uint32_t len)
{
    if (count == 0) return 0.0f;
    double sum = 0.0;
    for (uint32_t i = 0; i < count && i < len; i++) sum += (double)values[i];
    return (float)(sum / (double)count);
}

static float rolling_std(const uint32_t *values, uint32_t count, uint32_t len, float mean)
{
    if (count < 2) return 0.0f;
    double var = 0.0;
    uint32_t n = count < len ? count : len;
    for (uint32_t i = 0; i < n; i++) {
        double d = (double)values[i] - mean;
        var += d * d;
    }
    return (float)sqrt(var / (double)n);
}

/**
 * @brief Fallback anomaly detection: z-score of RSSI and frame_len.
 *
 * Returns reconstruction-error proxy: max(|z_rssi|, |z_len|) / 10.0f.
 */
static float detect_zscore(int8_t rssi, uint16_t frame_len)
{
    uint32_t rssi_buf[AI_ANOMALY_WINDOW];
    uint32_t len_buf[AI_ANOMALY_WINDOW];
    uint32_t n = g_wcount < AI_ANOMALY_WINDOW ? g_wcount : AI_ANOMALY_WINDOW;

    for (uint32_t i = 0; i < n; i++) {
        rssi_buf[i] = (uint32_t)(int32_t)(g_window[i].rssi + 128);
        len_buf[i]  = g_window[i].frame_len;
    }

    float r_mean = rolling_mean(rssi_buf, n, AI_ANOMALY_WINDOW);
    float r_std  = rolling_std(rssi_buf, n, AI_ANOMALY_WINDOW, r_mean);
    float l_mean = rolling_mean(len_buf, n, AI_ANOMALY_WINDOW);
    float l_std  = rolling_std(len_buf, n, AI_ANOMALY_WINDOW, l_mean);

    float z_rssi = (r_std > 0.001f)
        ? (float)fabs((double)((int32_t)(rssi + 128)) - (double)r_mean) / (double)r_std
        : 0.0f;
    float z_len  = (l_std > 0.001f)
        ? (float)fabs((double)frame_len - (double)l_mean) / (double)l_std
        : 0.0f;

    return (z_rssi > z_len ? z_rssi : z_len) / 10.0f;
}

esp_err_t ai_anomaly_init(void)
{
    if (g_init_done) return ESP_OK;

    memset(g_window, 0, sizeof(g_window));
    g_widx = g_wcount = g_pkt_total = g_anom_total = 0;
    g_last_score = 0.0f;
    g_last_anomaly = false;
    g_init_done = true;
    ESP_LOGI(TAG, "anomaly detector init (window=%d)", AI_ANOMALY_WINDOW);
    return ESP_OK;
}

esp_err_t ai_anomaly_set_model(const char *model_name)
{
    if (model_name == NULL) return ESP_ERR_INVALID_ARG;
    snprintf(g_model_name, sizeof(g_model_name), "%s", model_name);
    ESP_LOGI(TAG, "anomaly model set: '%s'", g_model_name);
    return ESP_OK;
}

esp_err_t ai_anomaly_set_threshold(float threshold)
{
    if (threshold < 0.0f || threshold > 1.0f) return ESP_ERR_INVALID_ARG;
    g_threshold = threshold;
    ESP_LOGI(TAG, "anomaly threshold set: %.3f", threshold);
    return ESP_OK;
}

esp_err_t ai_anomaly_feed(int8_t rssi, uint16_t frame_len, uint64_t timestamp_us)
{
    if (!g_init_done) return ESP_ERR_INVALID_STATE;

    /* Compute inter-arrival delta */
    float delta_us = 0.0f;
    if (g_wcount > 0) {
        uint32_t idx = (g_widx == 0) ? (AI_ANOMALY_WINDOW - 1) : (g_widx - 1);
        if (timestamp_us > g_window[idx].timestamp_us) {
            delta_us = (float)((double)timestamp_us - (double)g_window[idx].timestamp_us);
        }
    }

    /* Store in circular buffer */
    g_window[g_widx].rssi = rssi;
    g_window[g_widx].frame_len = frame_len;
    g_window[g_widx].timestamp_us = timestamp_us;
    g_widx = (g_widx + 1) % AI_ANOMALY_WINDOW;
    if (g_wcount < AI_ANOMALY_WINDOW) g_wcount++;
    g_pkt_total++;

    /* Need minimum 4 samples for meaningful stats */
    if (g_wcount < 4) {
        g_last_score = 0.0f;
        g_last_anomaly = false;
        return ESP_OK;
    }

    /* Try model inference if model name set */
    if (g_model_name[0] != '\0') {
        uint8_t tensor[AI_ANOMALY_FEAT_SZ];
        memset(tensor, 0, sizeof(tensor));
        tensor[0] = (uint8_t)((int32_t)rssi + 128);
        tensor[1] = frame_len & 0xFF;
        tensor[2] = (frame_len >> 8) & 0xFF;
        tensor[3] = (uint32_t)delta_us & 0xFF;
        tensor[4] = ((uint32_t)delta_us >> 8) & 0xFF;
        tensor[5] = ((uint32_t)delta_us >> 16) & 0xFF;
        tensor[6] = ((uint32_t)delta_us >> 24) & 0xFF;
        tensor[7] = (uint8_t)(rssi * frame_len);

        size_t out_len = 0;
        float out_buf[1];
        esp_err_t rc = ai_model_zoo_infer(g_model_name,
                                          tensor, sizeof(tensor),
                                          out_buf, sizeof(out_buf),
                                          &out_len);
        if (rc == ESP_OK && out_len >= sizeof(float)) {
            g_last_score = out_buf[0];
            if (g_last_score > g_threshold) {
                g_last_anomaly = true;
                g_anom_total++;
            } else {
                g_last_anomaly = false;
            }
            return ESP_OK;
        }
    }

    /* ESP-DL not linked: z-score fallback */
    g_last_score = detect_zscore(rssi, frame_len);
    if (g_last_score > g_threshold) {
        g_last_anomaly = true;
        g_anom_total++;
    } else {
        g_last_anomaly = false;
    }
    return ESP_OK;
}

esp_err_t ai_anomaly_get_result(ai_anomaly_result_t *out)
{
    if (out == NULL || !g_init_done) return ESP_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    out->score = g_last_score;
    out->is_anomaly = g_last_anomaly;
    out->packet_count = g_pkt_total;
    out->anomaly_count = g_anom_total;
    return ESP_OK;
}

esp_err_t ai_anomaly_json(char *buf, size_t bufsz)
{
    int w = snprintf(buf, bufsz,
        "{\"score\":%.4f,\"anomaly\":%s,\"total\":%lu,\"flagged\":%lu,"
        "\"threshold\":%.3f,\"model\":\"%s\"}",
        (double)g_last_score,
        g_last_anomaly ? "true" : "false",
        (unsigned long)g_pkt_total,
        (unsigned long)g_anom_total,
        (double)g_threshold,
        g_model_name);
    if (w < 0 || (size_t)w >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

void ai_anomaly_deinit(void)
{
    memset(g_window, 0, sizeof(g_window));
    g_widx = g_wcount = g_pkt_total = g_anom_total = 0;
    g_last_score = 0.0f;
    g_last_anomaly = false;
    g_init_done = false;
    ESP_LOGI(TAG, "anomaly detector deinit");
}
