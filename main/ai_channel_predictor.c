#include "ai_channel_predictor.h"
#include "ai_model.h"
#include "channel_hopper.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* ============================================================================
 *  CHANNEL PREDICTOR (LSTM on historical occupancy)
 * ============================================================================
 *
 *  Branch A — Full LSTM state machine inside predictor
 *    Decision: REJECTED. LSTM inference belongs in model zoo; predictor
 *              should only manage history + dispatch.
 *  Branch B — History buffer + model zoo inference + argmax fallback
 *    Decision: ACCEPTED. Records occupancy snapshots, builds tensor,
 *              calls ai_model_zoo_infer(). Falls back to max-occupancy.
 *  Branch C — Simple moving average only
 *    Decision: REJECTED. Moving average misses temporal patterns; LSTM
 *              on occupancy trends predicts burst channels better.
 */

static const char *TAG = "ai_chpred";

/* Occupancy snapshot per channel. */
typedef struct {
    uint32_t pkt_count;
    uint32_t beacon_count;
    uint8_t  channel;
} ch_occupancy_t;

static ch_occupancy_t   g_history[AI_CH_PREDICTOR_HISTORY][14]; /* ch 1..13 */
static uint8_t          g_hist_idx = 0;
static uint8_t          g_hist_count = 0;
static char             g_model_name[64] = {0};
static bool             g_init_done = false;
static uint32_t         g_infer_count = 0;
static uint32_t         g_fallback_count = 0;
static uint32_t         g_last_infer_us = 0;

esp_err_t ai_channel_predictor_init(void)
{
    if (g_init_done) return ESP_OK;

    memset(g_history, 0, sizeof(g_history));
    g_hist_idx = g_hist_count = 0;
    g_infer_count = g_fallback_count = 0;
    g_last_infer_us = 0;
    g_init_done = true;
    ESP_LOGI(TAG, "channel predictor init (history=%d)", AI_CH_PREDICTOR_HISTORY);
    return ESP_OK;
}

esp_err_t ai_channel_predictor_set_model(const char *model_name)
{
    if (model_name == NULL) return ESP_ERR_INVALID_ARG;
    snprintf(g_model_name, sizeof(g_model_name), "%s", model_name);
    ESP_LOGI(TAG, "predictor model set: '%s'", g_model_name);
    return ESP_OK;
}

esp_err_t ai_channel_predictor_record(void)
{
    if (!g_init_done) return ESP_ERR_INVALID_STATE;

    ch_occupancy_t *slot = g_history[g_hist_idx];
    for (uint8_t ch = 1; ch <= 13; ch++) {
        ch_hop_stats_t st;
        if (channel_hopper_get_stats(ch, &st) == ESP_OK) {
            slot[ch].pkt_count = st.pkt_count;
            slot[ch].beacon_count = st.beacon_count;
            slot[ch].channel = ch;
        } else {
            slot[ch].pkt_count = 0;
            slot[ch].beacon_count = 0;
            slot[ch].channel = ch;
        }
    }

    g_hist_idx = (g_hist_idx + 1) % AI_CH_PREDICTOR_HISTORY;
    if (g_hist_count < AI_CH_PREDICTOR_HISTORY) g_hist_count++;
    return ESP_OK;
}

esp_err_t ai_channel_predictor_predict(ai_channel_predict_t *out)
{
    if (out == NULL || !g_init_done) return ESP_ERR_INVALID_STATE;

    memset(out, 0, sizeof(*out));

    /* Build 104-byte tensor: 13 channels x 8 bytes per snapshot
     * Layout per channel: [pkt_count_lo, pkt_count_hi, beacon_lo, beacon_hi,
     *                      recent_pkt_lo, recent_pkt_hi, recent_bcn_lo, recent_bcn_hi]
     * recent = delta from previous snapshot in history.
     */
    uint8_t tensor[104];
    memset(tensor, 0, sizeof(tensor));

    for (uint8_t ch = 1; ch <= 13; ch++) {
        size_t base = (ch - 1) * 8;
        uint32_t curr_pkt = g_history[(g_hist_idx == 0) ? (AI_CH_PREDICTOR_HISTORY - 1) : (g_hist_idx - 1)][ch].pkt_count;
        uint32_t curr_bcn = g_history[(g_hist_idx == 0) ? (AI_CH_PREDICTOR_HISTORY - 1) : (g_hist_idx - 1)][ch].beacon_count;
        uint32_t prev_pkt = 0, prev_bcn = 0;
        if (g_hist_count > 1) {
            uint8_t prev = (g_hist_idx == 0) ? (AI_CH_PREDICTOR_HISTORY - 2) : (g_hist_idx - 2);
            prev_pkt = g_history[prev][ch].pkt_count;
            prev_bcn = g_history[prev][ch].beacon_count;
        }

        tensor[base + 0] = curr_pkt & 0xFF;
        tensor[base + 1] = (curr_pkt >> 8) & 0xFF;
        tensor[base + 2] = curr_bcn & 0xFF;
        tensor[base + 3] = (curr_bcn >> 8) & 0xFF;
        tensor[base + 4] = (curr_pkt > prev_pkt ? (curr_pkt - prev_pkt) : 0) & 0xFF;
        tensor[base + 5] = ((curr_pkt > prev_pkt ? (curr_pkt - prev_pkt) : 0) >> 8) & 0xFF;
        tensor[base + 6] = (curr_bcn > prev_bcn ? (curr_bcn - prev_bcn) : 0) & 0xFF;
        tensor[base + 7] = ((curr_bcn > prev_bcn ? (curr_bcn - prev_bcn) : 0) >> 8) & 0xFF;
    }

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
        g_last_infer_us = (uint32_t)dt;

        if (rc == ESP_OK && out_len >= 4) {
            uint8_t ch = model_out[0];
            if (ch >= 1 && ch <= 13) {
                out->best_channel = ch;
                out->confidence = (float)model_out[1] / 255.0f;
                out->model_loaded = true;
                out->inference_us = g_last_infer_us;
                g_infer_count++;
                return ESP_OK;
            }
        }
    }

    /* Fallback: pick channel with highest recent packet count */
    g_fallback_count++;
    uint32_t best_pkt = 0;
    uint8_t best_ch = 1;
    for (uint8_t ch = 1; ch <= 13; ch++) {
        uint32_t pkt = g_history[(g_hist_idx == 0) ? (AI_CH_PREDICTOR_HISTORY - 1) : (g_hist_idx - 1)][ch].pkt_count;
        if (pkt > best_pkt) {
            best_pkt = pkt;
            best_ch = ch;
        }
    }

    out->best_channel = best_ch;
    out->confidence = best_pkt > 0 ? 0.5f : 0.0f;
    out->model_loaded = false;
    out->inference_us = 0;
    return ESP_OK;
}

esp_err_t ai_channel_predictor_json(char *buf, size_t bufsz)
{
    int w = snprintf(buf, bufsz,
        "{\"history\":%d,\"infer\":%lu,\"fallback\":%lu,\"model\":\"%s\"}",
        g_hist_count,
        (unsigned long)g_infer_count,
        (unsigned long)g_fallback_count,
        g_model_name);
    if (w < 0 || (size_t)w >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

void ai_channel_predictor_deinit(void)
{
    memset(g_history, 0, sizeof(g_history));
    g_hist_idx = g_hist_count = 0;
    g_infer_count = g_fallback_count = 0;
    g_last_infer_us = 0;
    g_init_done = false;
    ESP_LOGI(TAG, "channel predictor deinit");
}
