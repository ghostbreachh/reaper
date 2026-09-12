#include "ai_anomaly.h"
#include "ai_model.h"

#include <string.h>
#include <stdio.h>
#include <math.h>
#include <ctype.h>
#include <stdint.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "ai_anom";

typedef struct {
    int8_t   rssi;
    uint16_t frame_len;
    uint64_t timestamp_us;
} ai_anom_pkt_t;

static ai_anom_pkt_t g_window[AI_ANOMALY_WINDOW];

static uint32_t g_widx = 0;
static uint32_t g_wcount = 0;

static uint32_t g_pkt_total = 0;
static uint32_t g_anom_total = 0;

static char g_model_name[64] = {0};

static float g_threshold = AI_ANOMALY_DEFAULT_THRESHOLD;
static uint32_t g_infer_every = AI_ANOMALY_DEFAULT_INFER_EVERY;

static float g_last_score = 0.0f;
static bool g_last_anomaly = false;

static bool g_init_done = false;

static SemaphoreHandle_t g_lock = NULL;

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

static float compute_zscore_against_window(int8_t rssi,
                                           uint16_t frame_len,
                                           uint32_t n_prev)
{
    if (n_prev < AI_ANOMALY_MIN_SAMPLES) {
        return 0.0f;
    }

    float r_sum = 0.0f;
    float l_sum = 0.0f;

    for (uint32_t i = 0; i < n_prev; i++) {
        r_sum += (float)((int32_t)g_window[i].rssi + 128);
        l_sum += (float)g_window[i].frame_len;
    }

    float r_mean = r_sum / (float)n_prev;
    float l_mean = l_sum / (float)n_prev;

    float r_var = 0.0f;
    float l_var = 0.0f;

    for (uint32_t i = 0; i < n_prev; i++) {
        float r_sample = (float)((int32_t)g_window[i].rssi + 128);
        float l_sample = (float)g_window[i].frame_len;

        float dr = r_sample - r_mean;
        float dl = l_sample - l_mean;

        r_var += dr * dr;
        l_var += dl * dl;
    }

    float r_std = sqrtf(r_var / (float)n_prev);
    float l_std = sqrtf(l_var / (float)n_prev);

    float z_rssi = 0.0f;
    float z_len = 0.0f;

    if (r_std > 0.001f) {
        float current = (float)((int32_t)rssi + 128);
        z_rssi = fabsf(current - r_mean) / r_std;
    }

    if (l_std > 0.001f) {
        float current = (float)frame_len;
        z_len = fabsf(current - l_mean) / l_std;
    }

    float z = fmaxf(z_rssi, z_len);

    /*
     * Normalize into a soft 0..1-ish score.
     * A z-score of 10 maps to ~1.0.
     */
    return z / 10.0f;
}

static void build_feature_tensor(uint8_t tensor[AI_ANOMALY_FEAT_SZ],
                                 int8_t rssi,
                                 uint16_t frame_len,
                                 uint32_t delta_us)
{
    memset(tensor, 0, AI_ANOMALY_FEAT_SZ);

    /* RSSI shifted to 0..255 */
    tensor[0] = (uint8_t)((int32_t)rssi + 128);

    /* Frame length, little-endian 16-bit */
    tensor[1] = (uint8_t)(frame_len & 0xFFu);
    tensor[2] = (uint8_t)((frame_len >> 8) & 0xFFu);

    /* Inter-arrival time in microseconds, little-endian 32-bit */
    tensor[3] = (uint8_t)(delta_us & 0xFFu);
    tensor[4] = (uint8_t)((delta_us >> 8) & 0xFFu);
    tensor[5] = (uint8_t)((delta_us >> 16) & 0xFFu);
    tensor[6] = (uint8_t)((delta_us >> 24) & 0xFFu);

    /*
     * Simple interaction feature.
     *
     * This is intentionally lightweight because the current model zoo API
     * accepts a byte tensor. If a real float tensor API is added later,
     * this should be replaced with normalized float features.
     */
    int32_t interaction = (int32_t)rssi * (int32_t)frame_len;
    tensor[7] = (uint8_t)((uint32_t)interaction & 0xFFu);
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t ai_anomaly_init(void)
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

    memset(g_window, 0, sizeof(g_window));

    g_widx = 0;
    g_wcount = 0;
    g_pkt_total = 0;
    g_anom_total = 0;

    g_last_score = 0.0f;
    g_last_anomaly = false;

    g_threshold = AI_ANOMALY_DEFAULT_THRESHOLD;
    g_infer_every = AI_ANOMALY_DEFAULT_INFER_EVERY;

    g_init_done = true;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Anomaly detector initialized (window=%d)", AI_ANOMALY_WINDOW);
    return ESP_OK;
}

void ai_anomaly_deinit(void)
{
    if (g_lock == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_window, 0, sizeof(g_window));

    g_widx = 0;
    g_wcount = 0;
    g_pkt_total = 0;
    g_anom_total = 0;

    g_last_score = 0.0f;
    g_last_anomaly = false;

    g_init_done = false;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Anomaly detector deinitialized");
}

esp_err_t ai_anomaly_reset(void)
{
    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_window, 0, sizeof(g_window));

    g_widx = 0;
    g_wcount = 0;
    g_pkt_total = 0;
    g_anom_total = 0;

    g_last_score = 0.0f;
    g_last_anomaly = false;

    xSemaphoreGive(g_lock);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Configuration
 * ----------------------------------------------------------------------- */

esp_err_t ai_anomaly_set_model(const char *model_name)
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

    ESP_LOGI(TAG, "Anomaly model set: '%s'", g_model_name);
    return ESP_OK;
}

esp_err_t ai_anomaly_set_threshold(float threshold)
{
    if (threshold < 0.0f || threshold > 1.0f) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    g_threshold = threshold;
    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Anomaly threshold set: %.3f", (double)threshold);
    return ESP_OK;
}

esp_err_t ai_anomaly_set_infer_every(uint32_t every_n)
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

    ESP_LOGI(TAG, "Model inference every %" PRIu32 " packets", every_n);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Feed / inference
 * ----------------------------------------------------------------------- */

esp_err_t ai_anomaly_feed(int8_t rssi, uint16_t frame_len, uint64_t timestamp_us)
{
    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    float fallback_score = 0.0f;
    bool should_infer = false;

    char model_local[sizeof(g_model_name)] = {0};
    uint8_t tensor[AI_ANOMALY_FEAT_SZ] = {0};

    xSemaphoreTake(g_lock, portMAX_DELAY);

    uint32_t n_prev = g_wcount;

    uint64_t prev_ts = 0;
    if (n_prev > 0) {
        uint32_t prev_idx = (g_widx == 0)
                                ? (AI_ANOMALY_WINDOW - 1)
                                : (g_widx - 1);
        prev_ts = g_window[prev_idx].timestamp_us;
    }

    uint64_t diff = 0;
    if (timestamp_us > prev_ts) {
        diff = timestamp_us - prev_ts;
    }

    if (diff > UINT32_MAX) {
        diff = UINT32_MAX;
    }

    /*
     * Score the new packet against the previous window.
     * Then insert it into the window.
     */
    fallback_score = compute_zscore_against_window(rssi, frame_len, n_prev);

    g_window[g_widx].rssi = rssi;
    g_window[g_widx].frame_len = frame_len;
    g_window[g_widx].timestamp_us = timestamp_us;

    g_widx = (g_widx + 1) % AI_ANOMALY_WINDOW;

    if (g_wcount < AI_ANOMALY_WINDOW) {
        g_wcount++;
    }

    g_pkt_total++;

    bool model_enabled = (g_model_name[0] != '\0');

    if (model_enabled && n_prev >= AI_ANOMALY_MIN_SAMPLES) {
        snprintf(model_local, sizeof(model_local), "%s", g_model_name);

        if (g_infer_every <= 1 || (g_pkt_total % g_infer_every) == 0) {
            build_feature_tensor(tensor, rssi, frame_len, (uint32_t)diff);
            should_infer = true;
        }
    }

    /*
     * If we are not running model inference, publish the fallback result now.
     * If we are running inference, publish after inference completes.
     */
    if (!should_infer) {
        g_last_score = fallback_score;
        g_last_anomaly = (fallback_score > g_threshold);

        if (g_last_anomaly) {
            g_anom_total++;
        }
    }

    xSemaphoreGive(g_lock);

    if (should_infer) {
        float out_buf[1] = {0.0f};
        size_t out_len = 0;
        float final_score = fallback_score;

        esp_err_t rc = ai_model_zoo_infer(
            model_local,
            tensor,
            sizeof(tensor),
            out_buf,
            sizeof(out_buf),
            &out_len
        );

        if (rc == ESP_OK && out_len >= sizeof(float)) {
            final_score = out_buf[0];
        } else {
            ESP_LOGD(TAG, "Model inference failed or returned no data; using fallback");
        }

        xSemaphoreTake(g_lock, portMAX_DELAY);

        g_last_score = final_score;
        g_last_anomaly = (final_score > g_threshold);

        if (g_last_anomaly) {
            g_anom_total++;
        }

        xSemaphoreGive(g_lock);
    }

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Result export
 * ----------------------------------------------------------------------- */

esp_err_t ai_anomaly_get_result(ai_anomaly_result_t *out)
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(out, 0, sizeof(*out));

    out->score = g_last_score;
    out->is_anomaly = g_last_anomaly;
    out->packet_count = g_pkt_total;
    out->anomaly_count = g_anom_total;

    xSemaphoreGive(g_lock);

    return ESP_OK;
}

esp_err_t ai_anomaly_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    float score;
    bool anomaly;
    uint32_t total;
    uint32_t flagged;
    float threshold;
    char model[sizeof(g_model_name)];

    xSemaphoreTake(g_lock, portMAX_DELAY);

    score = g_last_score;
    anomaly = g_last_anomaly;
    total = g_pkt_total;
    flagged = g_anom_total;
    threshold = g_threshold;
    snprintf(model, sizeof(model), "%s", g_model_name);

    xSemaphoreGive(g_lock);

    int w = snprintf(
        buf,
        bufsz,
        "{\"score\":%.4f,\"anomaly\":%s,\"total\":%" PRIu32
        ",\"flagged\":%" PRIu32 ",\"threshold\":%.3f,\"model\":\"%s\"}",
        (double)score,
        anomaly ? "true" : "false",
        total,
        flagged,
        (double)threshold,
        model
    );

    if (w < 0 || (size_t)w >= bufsz) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Wi-Fi observer wrapper
 * ----------------------------------------------------------------------- */

void ai_anomaly_wifi_observer(const wifi_pkt_msg_t *msg)
{
    if (msg == NULL || !g_init_done) {
        return;
    }

    uint64_t ts = (uint64_t)msg->tv.tv_sec * 1000000ULL +
                  (uint64_t)msg->tv.tv_usec;

    uint16_t len16 = (msg->len > 65535U)
                         ? 65535U
                         : (uint16_t)msg->len;

    ai_anomaly_feed(msg->rssi, len16, ts);
}
