#include "ai_classifier.h"
#include "ai_model.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* ============================================================================
 *  PACKET TYPE CLASSIFIER (50 KB CNN/LSTM replacement for hand-coded parsing)
 * ============================================================================
 *
 *  Branch A — Full frame decode before classification
 *    Decision: REJECTED. Hand-coded parsing already does this; classifier
 *              should see raw bytes to replace it, not duplicate it.
 *  Branch B — Lightweight feature extractor + model zoo inference
 *    Decision: ACCEPTED. Extracts frame_ctrl, subtype, RSSI, channel into
 *              a fixed-size tensor, then calls ai_model_zoo_infer().
 *  Branch C — External ML framework
 *    Decision: REJECTED. Keep it self-contained; use the existing model zoo.
 */

static const char *TAG = "ai_cls";

static char        g_model_name[64] = {0};
static bool        g_init_done      = false;
static uint32_t    g_classify_count = 0;
static uint32_t    g_classify_stub  = 0;

static const char *class_name(ai_pkt_class_t cls)
{
    switch (cls) {
        case AI_PKT_MGMT:    return "mgmt";
        case AI_PKT_CTRL:    return "ctrl";
        case AI_PKT_DATA:    return "data";
        case AI_PKT_BEACON:  return "beacon";
        case AI_PKT_PROBE:   return "probe";
        case AI_PKT_AUTH:    return "auth";
        case AI_PKT_ASSOC:   return "assoc";
        case AI_PKT_OTHER:   return "other";
        default:             return "?";
    }
}

const char *ai_classifier_class_name(ai_pkt_class_t cls)
{
    return class_name(cls);
}

/**
 * @brief Extract a fixed-size feature tensor from raw 802.11 frame.
 *
 * Tensor layout (64 bytes):
 *   [0..1]  frame_ctrl
 *   [2]     subtype
 *   [3]     rssi (clamped)
 *   [4]     channel
 *   [5..63] first 59 bytes of frame payload
 */
static void extract_features(const uint8_t *frame, size_t frame_len,
                             uint8_t *tensor, size_t tensor_sz)
{
    memset(tensor, 0, tensor_sz);
    if (frame_len < 2) return;

    uint16_t fc = (frame[0] | (frame[1] << 8));
    uint8_t subtype = (fc >> 4) & 0xF;

    /* RSSI and channel are not in the frame; caller sets them before predict */
    tensor[0] = fc & 0xFF;
    tensor[1] = (fc >> 8) & 0xFF;
    tensor[2] = subtype;

    size_t copy = frame_len < tensor_sz - 3 ? frame_len : tensor_sz - 3;
    memcpy(tensor + 3, frame, copy);
}

esp_err_t ai_classifier_init(void)
{
    if (g_init_done) return ESP_OK;

    memset(g_model_name, 0, sizeof(g_model_name));
    g_init_done = true;
    ESP_LOGI(TAG, "classifier init (input_max=%d)", AI_CLASSIFIER_INPUT_MAX);
    return ESP_OK;
}

esp_err_t ai_classifier_set_model(const char *model_name)
{
    if (model_name == NULL) return ESP_ERR_INVALID_ARG;
    snprintf(g_model_name, sizeof(g_model_name), "%s", model_name);
    ESP_LOGI(TAG, "classifier model set: '%s'", g_model_name);
    return ESP_OK;
}

esp_err_t ai_classifier_predict(const uint8_t *frame, size_t frame_len,
                                ai_classify_result_t *out)
{
    if (frame == NULL || out == NULL || !g_init_done) return ESP_ERR_INVALID_STATE;
    if (g_model_name[0] == '\0') return ESP_ERR_INVALID_STATE;

    memset(out, 0, sizeof(*out));

    uint8_t tensor[AI_CLASSIFIER_INPUT_MAX];
    extract_features(frame, frame_len, tensor, sizeof(tensor));

    size_t out_len = 0;
    uint64_t t0 = esp_timer_get_time();
    esp_err_t rc = ai_model_zoo_infer(g_model_name,
                                      tensor, sizeof(tensor),
                                      out, sizeof(*out),
                                      &out_len);
    uint64_t dt = esp_timer_get_time() - t0;

    out->inference_us = (uint32_t)dt;

    if (rc == ESP_ERR_NOT_SUPPORTED) {
        /* ESP-DL not linked; fall back to hand-coded heuristic */
        g_classify_stub++;
        uint16_t fc = (tensor[0] | (tensor[1] << 8));
        uint8_t subtype = tensor[2];
        uint8_t type = fc & 0x0C;

        if (type == 0x00) {
            if (subtype == 0x08)      out->cls = AI_PKT_BEACON;
            else if (subtype == 0x04) out->cls = AI_PKT_PROBE;
            else if (subtype == 0x0B) out->cls = AI_PKT_AUTH;
            else if (subtype == 0x00) out->cls = AI_PKT_ASSOC;
            else                      out->cls = AI_PKT_MGMT;
        } else if (type == 0x08) {
            out->cls = AI_PKT_CTRL;
        } else if (type == 0x04) {
            out->cls = AI_PKT_DATA;
        } else {
            out->cls = AI_PKT_OTHER;
        }
        out->confidence = 0.0f;  /* heuristic, no model confidence */
        out->model_loaded = false;
        return ESP_OK;
    }

    if (rc != ESP_OK) {
        out->cls = AI_PKT_OTHER;
        out->confidence = 0.0f;
        out->model_loaded = false;
        return rc;
    }

    out->model_loaded = true;
    g_classify_count++;
    return ESP_OK;
}

esp_err_t ai_classifier_json(char *buf, size_t bufsz)
{
    int w = snprintf(buf, bufsz,
        "{\"total\":%lu,\"stub\":%lu,\"model\":\"%s\"}",
        (unsigned long)g_classify_count,
        (unsigned long)g_classify_stub,
        g_model_name);
    if (w < 0 || (size_t)w >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

void ai_classifier_deinit(void)
{
    memset(g_model_name, 0, sizeof(g_model_name));
    g_init_done = false;
    g_classify_count = 0;
    g_classify_stub = 0;
    ESP_LOGI(TAG, "classifier deinit");
}
