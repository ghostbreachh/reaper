#include "ai_handshake_quality.h"
#include "ai_model.h"
#include "handshake_crack.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* ============================================================================
 *  HANDSHAKE QUALITY SCORER (predict crackability)
 * ============================================================================
 *
 *  Branch A — External cracking estimator library
 *    Decision: REJECTED. Keep it self-contained; reuse model zoo.
 *  Branch B — Feature extractor from captured handshake + model inference
 *    Decision: ACCEPTED. Reads g_hs directly, builds tensor from EAPOL
 *              flags, RSSI, timing; calls ai_model_zoo_infer().
 *  Branch C — Simple count-based heuristic only
 *    Decision: REJECTED. EAPOL timing + MIC flags + RSSI jointly predict
 *              crackability better than frame counts alone.
 */

static const char *TAG = "ai_hsq";

static char            g_model_name[64] = {0};
static bool            g_init_done      = false;
static uint32_t        g_score_count    = 0;
static uint32_t        g_heuristic_count= 0;

esp_err_t ai_hs_quality_init(void)
{
    if (g_init_done) return ESP_OK;

    memset(g_model_name, 0, sizeof(g_model_name));
    g_init_done = true;
    g_score_count = 0;
    g_heuristic_count = 0;
    ESP_LOGI(TAG, "handshake quality init");
    return ESP_OK;
}

esp_err_t ai_hs_quality_set_model(const char *model_name)
{
    if (model_name == NULL) return ESP_ERR_INVALID_ARG;
    snprintf(g_model_name, sizeof(g_model_name), "%s", model_name);
    ESP_LOGI(TAG, "handshake quality model set: '%s'", g_model_name);
    return ESP_OK;
}

/**
 * @brief Build 8-byte feature tensor from handshake state.
 *
 * Layout:
 *   [0] EAPOL flags: bit0=has_M1, bit1=has_M2, bit2=has_M3, bit3=has_M4
 *   [1] RSSI clamped 0..255
 *   [2] eapol_len_lo
 *   [3] eapol_len_hi
 *   [4] key_info_lo
 *   [5] key_info_hi
 *   [6] has_pmkid (0/1)
 *   [7] reserved / future
 */
static void build_hs_tensor(uint8_t *tensor)
{
    memset(tensor, 0, 8);
    const handshake_t *hs = handshake_get();
    if (hs == NULL) return;

    uint8_t flags = 0;
    if (hs->has_anonce) flags |= 0x01;
    if (hs->has_snonce) flags |= 0x02;
    if (hs->has_mic)    flags |= 0x04;
    if (hs->has_pmkid)  flags |= 0x08;
    tensor[0] = flags;
    tensor[1] = (uint8_t)((int32_t)(hs->rssi != 0 ? hs->rssi : -100) + 100);
    tensor[2] = hs->eapol_len & 0xFF;
    tensor[3] = (hs->eapol_len >> 8) & 0xFF;

    /* key_info from EAPOL if available */
    if (hs->eapol_len >= 8) {
        uint16_t key_info = hs->eapol[5] | (hs->eapol[6] << 8);
        tensor[4] = key_info & 0xFF;
        tensor[5] = (key_info >> 8) & 0xFF;
    }

    tensor[6] = hs->has_pmkid ? 1 : 0;
}

esp_err_t ai_hs_quality_score(ai_hs_quality_t *out)
{
    if (out == NULL || !g_init_done) return ESP_ERR_INVALID_STATE;

    memset(out, 0, sizeof(*out));

    const handshake_t *hs = handshake_get();
    if (hs == NULL) {
        out->score = 0.0f;
        return ESP_OK;
    }

    /* Derive presence flags from raw fields */
    bool anonce_ok = false, snonce_ok = false, mic_ok = false;
    for (int i = 0; i < 32; i++) { if (hs->anonce[i]) { anonce_ok = true; break; } }
    for (int i = 0; i < 32; i++) { if (hs->snonce[i]) { snonce_ok = true; break; } }
    for (int i = 0; i < 16; i++) { if (hs->mic[i])   { mic_ok = true;   break; } }

    out->has_anonce = anonce_ok;
    out->has_snonce = snonce_ok;
    out->has_mic = mic_ok;
    out->has_pmkid = hs->has_pmkid;
    out->complete = handshake_has_capture();

    /* Count M1/M2 from EAPOL key_info if eapol buffer valid */
    if (hs->eapol_len >= 8) {
        uint16_t key_info = hs->eapol[5] | (hs->eapol[6] << 8);
        bool is_m1 = !(key_info & 0x0800); /* install bit clear */
        bool is_m2 = (key_info & 0x0800) && !(key_info & 0x0400);
        if (is_m1) out->m1_count++;
        if (is_m2) out->m2_count++;
    }

    /* Try model inference */
    if (g_model_name[0] != '\0') {
        uint8_t tensor[8];
        build_hs_tensor(tensor);

        uint8_t model_out[4];
        size_t out_len = 0;
        uint64_t t0 = esp_timer_get_time();
        esp_err_t rc = ai_model_zoo_infer(g_model_name,
                                          tensor, sizeof(tensor),
                                          model_out, sizeof(model_out),
                                          &out_len);
        uint64_t dt = esp_timer_get_time() - t0;

        if (rc == ESP_OK && out_len >= 4) {
            out->score = (float)model_out[0] / 255.0f;
            out->factors = (uint32_t)model_out[1] << 24 |
                           (uint32_t)model_out[2] << 16 |
                           (uint32_t)model_out[3] << 8;
            g_score_count++;
            return ESP_OK;
        }
    }

    /* Heuristic fallback */
    g_heuristic_count++;

    float score = 0.0f;
    uint32_t factors = 0;

    if (out->complete) {
        score += 0.5f;
        factors |= (1 << 0);
    }
    if (anonce_ok && snonce_ok) {
        score += 0.3f;
        factors |= (1 << 1);
    }
    if (mic_ok) {
        score += 0.1f;
        factors |= (1 << 2);
    }
    if (out->has_pmkid) {
        score += 0.2f;
        factors |= (1 << 3);
    }
    if (out->eapol_len > 0) {
        score += 0.05f;
        factors |= (1 << 5);
    }

    if (score > 1.0f) score = 1.0f;
    out->score = score;
    out->factors = factors;
    return ESP_OK;
}

esp_err_t ai_hs_quality_json(char *buf, size_t bufsz)
{
    ai_hs_quality_t q;
    ai_hs_quality_score(&q);

    int w = snprintf(buf, bufsz,
        "{\"score\":%.4f,\"complete\":%s,\"anonce\":%s,\"snonce\":%s,"
        "\"mic\":%s,\"pmkid\":%s,\"rssi\":%d,"
        "\"model_scored\":%lu,\"heuristic\":%lu,\"model\":\"%s\"}",
        (double)q.score,
        q.complete ? "true" : "false",
        q.has_anonce ? "true" : "false",
        q.has_snonce ? "true" : "false",
        q.has_mic ? "true" : "false",
        q.has_pmkid ? "true" : "false",
        (int)q.rssi,
        (unsigned long)g_score_count,
        (unsigned long)g_heuristic_count,
        g_model_name);
    if (w < 0 || (size_t)w >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

void ai_hs_quality_deinit(void)
{
    memset(g_model_name, 0, sizeof(g_model_name));
    g_init_done = false;
    g_score_count = 0;
    g_heuristic_count = 0;
    ESP_LOGI(TAG, "handshake quality deinit");
}
