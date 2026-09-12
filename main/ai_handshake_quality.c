#include "ai_handshake_quality.h"
#include "ai_model.h"
#include "handshake_crack.h"
#include "wifi_sniffer.h"

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

static const char *TAG = "ai_hsq";

static char g_model_name[64] = {0};

static bool g_init_done = false;

static uint32_t g_total_count = 0;
static uint32_t g_model_count = 0;
static uint32_t g_heuristic_count = 0;
static uint32_t g_last_infer_us = 0;

static ai_hs_quality_t g_last_result;
static bool g_has_last_result = false;

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

static bool buffer_nonzero(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) {
            return true;
        }
    }

    return false;
}

static bool mac_is_zero(const uint8_t *mac)
{
    if (mac == NULL) {
        return true;
    }

    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0) {
            return false;
        }
    }

    return true;
}

static uint8_t normalize_rssi_feature(int8_t rssi)
{
    int32_t v = (int32_t)rssi;

    if (v < -100) {
        v = -100;
    }

    if (v > 0) {
        v = 0;
    }

    /*
     * Map -100..0 to 0..255.
     */
    int32_t normalized = ((v + 100) * 255) / 100;

    if (normalized < 0) {
        normalized = 0;
    }

    if (normalized > 255) {
        normalized = 255;
    }

    return (uint8_t)normalized;
}

static uint16_t get_eapol_key_info(const handshake_t *hs)
{
    if (hs == NULL) {
        return 0;
    }

    if (hs->eapol_len < 7) {
        return 0;
    }

    /*
     * EAPOL-Key Key Information is big-endian in 802.11i.
     */
    return (uint16_t)(((uint16_t)hs->eapol[5] << 8) | (uint16_t)hs->eapol[6]);
}

/* -------------------------------------------------------------------------
 *  Feature extraction
 * ----------------------------------------------------------------------- */

static void build_hs_tensor(const handshake_t *hs,
                            bool has_anonce,
                            bool has_snonce,
                            bool has_mic,
                            int8_t rssi,
                            uint16_t key_info,
                            uint8_t tensor[8])
{
    memset(tensor, 0, 8);

    uint8_t flags = 0;

    if (has_anonce) {
        flags |= 0x01;
    }

    if (has_snonce) {
        flags |= 0x02;
    }

    if (has_mic) {
        flags |= 0x04;
    }

    if (hs->has_pmkid) {
        flags |= 0x08;
    }

    if (hs->valid) {
        flags |= 0x10;
    }

    tensor[0] = flags;
    tensor[1] = normalize_rssi_feature(rssi);

    uint16_t eapol_len = hs->eapol_len;
    if (eapol_len > EAPOL_BUF_SIZE) {
        eapol_len = EAPOL_BUF_SIZE;
    }

    tensor[2] = (uint8_t)(eapol_len & 0xFFu);
    tensor[3] = (uint8_t)((eapol_len >> 8) & 0xFFu);

    tensor[4] = (uint8_t)(key_info & 0xFFu);
    tensor[5] = (uint8_t)((key_info >> 8) & 0xFFu);

    tensor[6] = hs->has_pmkid ? 1 : 0;
    tensor[7] = (uint8_t)strlen(hs->ssid);
}

/* -------------------------------------------------------------------------
 *  Heuristic fallback
 * ----------------------------------------------------------------------- */

static void heuristic_score(const handshake_t *hs,
                            bool has_anonce,
                            bool has_snonce,
                            bool has_mic,
                            int8_t rssi,
                            float *out_score,
                            uint32_t *out_factors)
{
    float score = 0.0f;
    uint32_t factors = 0;

    if (hs->valid) {
        score += 0.45f;
        factors |= AI_HS_FACTOR_COMPLETE;
    }

    if (has_anonce && has_snonce) {
        score += 0.20f;
        factors |= AI_HS_FACTOR_NONCES;
    }

    if (has_mic) {
        score += 0.15f;
        factors |= AI_HS_FACTOR_MIC;
    }

    if (hs->has_pmkid) {
        score += 0.25f;
        factors |= AI_HS_FACTOR_PMKID;
    }

    if (hs->eapol_len > 0) {
        score += 0.05f;
        factors |= AI_HS_FACTOR_EAPOL;
    }

    if (rssi >= -60) {
        score += 0.05f;
        factors |= AI_HS_FACTOR_STRONG_RSSI;
    } else if (rssi <= -85) {
        score -= 0.10f;
    }

    if (score < 0.0f) {
        score = 0.0f;
    }

    if (score > 1.0f) {
        score = 1.0f;
    }

    *out_score = score;
    *out_factors = factors;
}

static void fill_result(ai_hs_quality_t *out,
                        const handshake_t *hs,
                        bool has_anonce,
                        bool has_snonce,
                        bool has_mic,
                        int8_t rssi,
                        float score,
                        uint32_t factors,
                        bool model_loaded,
                        uint32_t inference_us)
{
    memset(out, 0, sizeof(*out));

    out->score = score;
    out->factors = factors;

    out->m1_count = has_anonce ? 1 : 0;
    out->m2_count = (has_snonce && has_mic) ? 1 : 0;

    out->rssi = rssi;

    out->eapol_len = hs->eapol_len;
    if (out->eapol_len > EAPOL_BUF_SIZE) {
        out->eapol_len = EAPOL_BUF_SIZE;
    }

    out->has_anonce = has_anonce;
    out->has_snonce = has_snonce;
    out->has_mic = has_mic;
    out->has_pmkid = hs->has_pmkid;
    out->complete = hs->valid;

    out->model_loaded = model_loaded;
    out->inference_us = inference_us;
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t ai_hs_quality_init(void)
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
    memset(&g_last_result, 0, sizeof(g_last_result));

    g_init_done = true;
    g_total_count = 0;
    g_model_count = 0;
    g_heuristic_count = 0;
    g_last_infer_us = 0;
    g_has_last_result = false;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Handshake quality scorer initialized");
    return ESP_OK;
}

void ai_hs_quality_deinit(void)
{
    if (g_lock == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_model_name, 0, sizeof(g_model_name));
    memset(&g_last_result, 0, sizeof(g_last_result));

    g_init_done = false;
    g_total_count = 0;
    g_model_count = 0;
    g_heuristic_count = 0;
    g_last_infer_us = 0;
    g_has_last_result = false;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Handshake quality scorer deinitialized");
}

/* -------------------------------------------------------------------------
 *  Configuration
 * ----------------------------------------------------------------------- */

esp_err_t ai_hs_quality_set_model(const char *model_name)
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

    ESP_LOGI(TAG, "Handshake quality model set: '%s'", g_model_name);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Scoring
 * ----------------------------------------------------------------------- */

esp_err_t ai_hs_quality_score(ai_hs_quality_t *out)
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    memset(out, 0, sizeof(*out));

    handshake_t hs;

    if (handshake_get_snapshot(&hs) != ESP_OK) {
        memset(&hs, 0, sizeof(hs));
    }

    bool has_anonce = buffer_nonzero(hs.anonce, sizeof(hs.anonce));
    bool has_snonce = buffer_nonzero(hs.snonce, sizeof(hs.snonce));
    bool has_mic = buffer_nonzero(hs.mic, sizeof(hs.mic));

    int8_t rssi = -100;

    if (!mac_is_zero(hs.ap_mac)) {
        wifi_sniffer_get_rssi(hs.ap_mac, &rssi);
    }

    uint16_t key_info = get_eapol_key_info(&hs);

    uint8_t tensor[8];
    build_hs_tensor(&hs, has_anonce, has_snonce, has_mic, rssi, key_info, tensor);

    char model_local[sizeof(g_model_name)] = {0};
    bool model_enabled = false;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    g_total_count++;

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

        if (rc == ESP_OK && out_len >= 1) {
            float score = (float)model_out[0] / 255.0f;

            uint32_t factors = 0;

            if (out_len >= 2) {
                factors |= (uint32_t)model_out[1];
            }

            if (out_len >= 3) {
                factors |= ((uint32_t)model_out[2] << 8);
            }

            if (out_len >= 4) {
                factors |= ((uint32_t)model_out[3] << 16);
            }

            fill_result(
                out,
                &hs,
                has_anonce,
                has_snonce,
                has_mic,
                rssi,
                score,
                factors,
                true,
                (uint32_t)dt
            );

            xSemaphoreTake(g_lock, portMAX_DELAY);

            g_model_count++;
            g_last_infer_us = (uint32_t)dt;
            g_last_result = *out;
            g_has_last_result = true;

            xSemaphoreGive(g_lock);

            return ESP_OK;
        }

        ESP_LOGD(TAG, "Model inference failed or invalid; using heuristic");
    }

    float score = 0.0f;
    uint32_t factors = 0;

    heuristic_score(
        &hs,
        has_anonce,
        has_snonce,
        has_mic,
        rssi,
        &score,
        &factors
    );

    fill_result(
        out,
        &hs,
        has_anonce,
        has_snonce,
        has_mic,
        rssi,
        score,
        factors,
        false,
        0
    );

    xSemaphoreTake(g_lock, portMAX_DELAY);

    g_heuristic_count++;
    g_last_result = *out;
    g_has_last_result = true;

    xSemaphoreGive(g_lock);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Stats / JSON
 * ----------------------------------------------------------------------- */

esp_err_t ai_hs_quality_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    ai_hs_quality_t q;

    esp_err_t rc = ai_hs_quality_score(&q);
    if (rc != ESP_OK) {
        return rc;
    }

    uint32_t total;
    uint32_t model;
    uint32_t heuristic;
    uint32_t last_infer_us;
    char model_name[sizeof(g_model_name)];

    xSemaphoreTake(g_lock, portMAX_DELAY);

    total = g_total_count;
    model = g_model_count;
    heuristic = g_heuristic_count;
    last_infer_us = g_last_infer_us;
    snprintf(model_name, sizeof(model_name), "%s", g_model_name);

    xSemaphoreGive(g_lock);

    int w = snprintf(
        buf,
        bufsz,
        "{\"score\":%.4f,\"complete\":%s,\"anonce\":%s,\"snonce\":%s,"
        "\"mic\":%s,\"pmkid\":%s,\"rssi\":%d,\"eapol_len\":%" PRIu16
        ",\"factors\":%" PRIu32
        ",\"total\":%" PRIu32
        ",\"model\":%" PRIu32
        ",\"heuristic\":%" PRIu32
        ",\"last_infer_us\":%" PRIu32
        ",\"model_name\":\"%s\"}",
        (double)q.score,
        q.complete ? "true" : "false",
        q.has_anonce ? "true" : "false",
        q.has_snonce ? "true" : "false",
        q.has_mic ? "true" : "false",
        q.has_pmkid ? "true" : "false",
        (int)q.rssi,
        q.eapol_len,
        q.factors,
        total,
        model,
        heuristic,
        last_infer_us,
        model_name
    );

    if (w < 0 || (size_t)w >= bufsz) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}
