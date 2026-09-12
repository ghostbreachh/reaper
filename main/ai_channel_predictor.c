#include "ai_channel_predictor.h"
#include "ai_model.h"
#include "channel_hopper.h"

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

static const char *TAG = "ai_chpred";

/* Occupancy snapshot per channel. */
typedef struct {
    uint32_t pkt_count;
    uint32_t beacon_count;
    uint8_t  channel;
} ch_occupancy_t;

static ch_occupancy_t g_history[AI_CH_PREDICTOR_HISTORY][14]; /* index 1..13 */

static uint8_t g_hist_idx = 0;
static uint8_t g_hist_count = 0;

static char g_model_name[64] = {0};

static bool g_init_done = false;

static uint32_t g_infer_count = 0;
static uint32_t g_fallback_count = 0;
static uint32_t g_last_infer_us = 0;

static uint32_t g_record_interval_ms = AI_CH_PREDICTOR_DEFAULT_RECORD_INTERVAL_MS;
static int64_t g_last_record_us = 0;

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

static uint8_t history_index(uint8_t steps_back)
{
    return (uint8_t)((g_hist_idx + AI_CH_PREDICTOR_HISTORY - steps_back) %
                     AI_CH_PREDICTOR_HISTORY);
}

static uint16_t saturate_u16(uint32_t v)
{
    if (v > 0xFFFFu) {
        return 0xFFFFu;
    }
    return (uint16_t)v;
}

static void put_u16_le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t ai_channel_predictor_init(void)
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

    memset(g_history, 0, sizeof(g_history));

    g_hist_idx = 0;
    g_hist_count = 0;

    g_infer_count = 0;
    g_fallback_count = 0;
    g_last_infer_us = 0;

    g_record_interval_ms = AI_CH_PREDICTOR_DEFAULT_RECORD_INTERVAL_MS;
    g_last_record_us = 0;

    g_init_done = true;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Channel predictor initialized (history=%d)", AI_CH_PREDICTOR_HISTORY);
    return ESP_OK;
}

void ai_channel_predictor_deinit(void)
{
    if (g_lock == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_history, 0, sizeof(g_history));

    g_hist_idx = 0;
    g_hist_count = 0;

    g_infer_count = 0;
    g_fallback_count = 0;
    g_last_infer_us = 0;

    g_record_interval_ms = AI_CH_PREDICTOR_DEFAULT_RECORD_INTERVAL_MS;
    g_last_record_us = 0;

    g_init_done = false;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Channel predictor deinitialized");
}

/* -------------------------------------------------------------------------
 *  Configuration
 * ----------------------------------------------------------------------- */

esp_err_t ai_channel_predictor_set_model(const char *model_name)
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

    ESP_LOGI(TAG, "Channel predictor model set: '%s'", g_model_name);
    return ESP_OK;
}

esp_err_t ai_channel_predictor_set_record_interval_ms(uint32_t interval_ms)
{
    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    g_record_interval_ms = interval_ms;
    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Record interval set to %" PRIu32 " ms", interval_ms);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Snapshot recording
 * ----------------------------------------------------------------------- */

esp_err_t ai_channel_predictor_record(void)
{
    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    int64_t now = esp_timer_get_time();

    /*
     * First throttle check before doing any channel-hopper work.
     */
    xSemaphoreTake(g_lock, portMAX_DELAY);

    bool allowed = false;

    if (g_record_interval_ms == 0) {
        allowed = true;
    } else {
        int64_t interval_us = (int64_t)g_record_interval_ms * 1000;
        allowed = (now - g_last_record_us) >= interval_us;
    }

    xSemaphoreGive(g_lock);

    if (!allowed) {
        return ESP_OK;
    }

    ch_hop_stats_t stats[14];
    esp_err_t rc = channel_hopper_get_all_stats(stats);
    if (rc != ESP_OK) {
        return rc;
    }

    ch_occupancy_t snapshot[14];
    memset(snapshot, 0, sizeof(snapshot));

    for (uint8_t ch = 1; ch <= 13; ch++) {
        snapshot[ch].pkt_count = stats[ch].pkt_count;
        snapshot[ch].beacon_count = stats[ch].beacon_count;
        snapshot[ch].channel = ch;
    }

    /*
     * Re-check throttle under lock in case another task recorded
     * while we were collecting stats.
     */
    xSemaphoreTake(g_lock, portMAX_DELAY);

    now = esp_timer_get_time();

    if (g_record_interval_ms == 0) {
        allowed = true;
    } else {
        int64_t interval_us = (int64_t)g_record_interval_ms * 1000;
        allowed = (now - g_last_record_us) >= interval_us;
    }

    if (allowed) {
        memcpy(g_history[g_hist_idx], snapshot, sizeof(snapshot));

        g_hist_idx = (uint8_t)((g_hist_idx + 1) % AI_CH_PREDICTOR_HISTORY);

        if (g_hist_count < AI_CH_PREDICTOR_HISTORY) {
            g_hist_count++;
        }

        g_last_record_us = now;
    }

    xSemaphoreGive(g_lock);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Prediction
 * ----------------------------------------------------------------------- */

esp_err_t ai_channel_predictor_predict(ai_channel_predict_t *out)
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    memset(out, 0, sizeof(*out));

    uint8_t tensor[104];
    memset(tensor, 0, sizeof(tensor));

    char model_local[sizeof(g_model_name)] = {0};
    bool model_enabled = false;

    uint8_t fallback_ch = 1;
    float fallback_conf = 0.0f;

    uint32_t hist_count = 0;

    /*
     * Build tensor and fallback decision under lock.
     */
    xSemaphoreTake(g_lock, portMAX_DELAY);

    hist_count = g_hist_count;

    if (hist_count > 0) {
        uint8_t curr_idx = history_index(1);
        bool has_prev = (hist_count > 1);
        uint8_t prev_idx = has_prev ? history_index(2) : curr_idx;

        uint32_t total_recent = 0;
        uint32_t best_recent = 0;

        for (uint8_t ch = 1; ch <= 13; ch++) {
            uint32_t curr_pkt = g_history[curr_idx][ch].pkt_count;
            uint32_t curr_bcn = g_history[curr_idx][ch].beacon_count;

            uint32_t prev_pkt = has_prev ? g_history[prev_idx][ch].pkt_count : 0;
            uint32_t prev_bcn = has_prev ? g_history[prev_idx][ch].beacon_count : 0;

            /*
             * Handle counter resets safely.
             */
            uint32_t recent_pkt = (curr_pkt >= prev_pkt)
                                      ? (curr_pkt - prev_pkt)
                                      : curr_pkt;

            uint32_t recent_bcn = (curr_bcn >= prev_bcn)
                                      ? (curr_bcn - prev_bcn)
                                      : curr_bcn;

            total_recent += recent_pkt;

            if (recent_pkt > best_recent) {
                best_recent = recent_pkt;
                fallback_ch = ch;
            }

            size_t base = (size_t)(ch - 1) * 8;

            put_u16_le(&tensor[base + 0], saturate_u16(curr_pkt));
            put_u16_le(&tensor[base + 2], saturate_u16(curr_bcn));
            put_u16_le(&tensor[base + 4], saturate_u16(recent_pkt));
            put_u16_le(&tensor[base + 6], saturate_u16(recent_bcn));
        }

        if (total_recent > 0 && best_recent > 0) {
            float ratio = (float)best_recent / (float)total_recent;
            fallback_conf = 0.3f + (0.7f * ratio);

            if (fallback_conf > 1.0f) {
                fallback_conf = 1.0f;
            }
        } else {
            fallback_conf = 0.0f;
        }
    }

    model_enabled = (g_model_name[0] != '\0');

    if (model_enabled) {
        snprintf(model_local, sizeof(model_local), "%s", g_model_name);
    }

    xSemaphoreGive(g_lock);

    /*
     * Try model inference outside the state lock.
     */
    if (model_enabled) {
        uint8_t model_out[4] = {0};
        size_t out_len = 0;

        uint64_t t0 = esp_timer_get_time();

        esp_err_t rc = ai_model_zoo_infer(
            model_local,
            tensor,
            sizeof(tensor),
            model_out,
            sizeof(model_out),
            &out_len
        );

        uint64_t dt = esp_timer_get_time() - t0;

        if (rc == ESP_OK && out_len >= 4) {
            uint8_t ch = model_out[0];

            if (ch >= 1 && ch <= 13) {
                float confidence = (float)model_out[1] / 255.0f;

                xSemaphoreTake(g_lock, portMAX_DELAY);

                g_infer_count++;
                g_last_infer_us = (uint32_t)dt;

                out->best_channel = ch;
                out->confidence = confidence;
                out->history_count = g_hist_count;
                out->infer_count = g_infer_count;
                out->fallback_count = g_fallback_count;
                out->model_loaded = true;
                out->inference_us = g_last_infer_us;

                xSemaphoreGive(g_lock);

                return ESP_OK;
            }
        }

        ESP_LOGD(TAG, "Model inference failed or invalid; using fallback");
    }

    /*
     * Heuristic fallback.
     */
    xSemaphoreTake(g_lock, portMAX_DELAY);

    g_fallback_count++;

    out->best_channel = fallback_ch;
    out->confidence = fallback_conf;
    out->history_count = g_hist_count;
    out->infer_count = g_infer_count;
    out->fallback_count = g_fallback_count;
    out->model_loaded = false;
    out->inference_us = 0;

    xSemaphoreGive(g_lock);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Stats / JSON
 * ----------------------------------------------------------------------- */

esp_err_t ai_channel_predictor_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    uint32_t history_count;
    uint32_t infer_count;
    uint32_t fallback_count;
    uint32_t last_infer_us;
    uint32_t record_interval_ms;
    char model_name[sizeof(g_model_name)];

    xSemaphoreTake(g_lock, portMAX_DELAY);

    history_count = g_hist_count;
    infer_count = g_infer_count;
    fallback_count = g_fallback_count;
    last_infer_us = g_last_infer_us;
    record_interval_ms = g_record_interval_ms;
    snprintf(model_name, sizeof(model_name), "%s", g_model_name);

    xSemaphoreGive(g_lock);

    int w = snprintf(
        buf,
        bufsz,
        "{\"history\":%" PRIu32
        ",\"infer\":%" PRIu32
        ",\"fallback\":%" PRIu32
        ",\"last_infer_us\":%" PRIu32
        ",\"record_interval_ms\":%" PRIu32
        ",\"model_name\":\"%s\"}",
        history_count,
        infer_count,
        fallback_count,
        last_infer_us,
        record_interval_ms,
        model_name
    );

    if (w < 0 || (size_t)w >= bufsz) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}
