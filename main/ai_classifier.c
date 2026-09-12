#include "ai_classifier.h"
#include "ai_model.h"

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

static const char *TAG = "ai_cls";

static char g_model_name[64] = {0};

static bool g_init_done = false;

static uint32_t g_total_count = 0;
static uint32_t g_model_count = 0;
static uint32_t g_heuristic_count = 0;
static uint32_t g_last_infer_us = 0;

static uint32_t g_infer_every = AI_CLASSIFIER_DEFAULT_INFER_EVERY;

static SemaphoreHandle_t g_lock = NULL;
static SemaphoreHandle_t g_infer_lock = NULL;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

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

/* -------------------------------------------------------------------------
 *  Feature extraction
 * ----------------------------------------------------------------------- */

static void extract_features(const uint8_t *frame,
                             size_t frame_len,
                             int8_t rssi,
                             uint8_t channel,
                             uint8_t tensor[AI_CLASSIFIER_INPUT_MAX])
{
    memset(tensor, 0, AI_CLASSIFIER_INPUT_MAX);

    if (frame != NULL && frame_len >= 1) {
        tensor[0] = frame[0];
    }

    if (frame != NULL && frame_len >= 2) {
        tensor[1] = frame[1];
    }

    uint8_t type = 0;
    uint8_t subtype = 0;

    if (frame != NULL && frame_len >= 2) {
        uint16_t fc = (uint16_t)(frame[0] | ((uint16_t)frame[1] << 8));
        type = (uint8_t)((fc >> 2) & 0x03u);
        subtype = (uint8_t)((fc >> 4) & 0x0Fu);
    }

    tensor[2] = (uint8_t)((type << 4) | subtype);
    tensor[3] = (uint8_t)((int32_t)rssi + 128);
    tensor[4] = channel;

    if (frame != NULL && frame_len > 0) {
        size_t max_copy = AI_CLASSIFIER_INPUT_MAX - 5;
        size_t copy = (frame_len > max_copy) ? max_copy : frame_len;
        memcpy(&tensor[5], frame, copy);
    }
}

/* -------------------------------------------------------------------------
 *  Heuristic classifier
 * ----------------------------------------------------------------------- */

static ai_pkt_class_t heuristic_classify(const uint8_t *frame, size_t frame_len)
{
    if (frame == NULL || frame_len < 2) {
        return AI_PKT_OTHER;
    }

    uint16_t fc = (uint16_t)(frame[0] | ((uint16_t)frame[1] << 8));

    uint8_t type = (uint8_t)((fc >> 2) & 0x03u);
    uint8_t subtype = (uint8_t)((fc >> 4) & 0x0Fu);

    if (type == 0) {
        /* Management */
        switch (subtype) {
            case 0x08: /* Beacon */
                return AI_PKT_BEACON;

            case 0x04: /* Probe Request */
            case 0x05: /* Probe Response */
                return AI_PKT_PROBE;

            case 0x0B: /* Authentication */
                return AI_PKT_AUTH;

            case 0x00: /* Association Request */
            case 0x01: /* Association Response */
            case 0x02: /* Reassociation Request */
            case 0x03: /* Reassociation Response */
                return AI_PKT_ASSOC;

            default:
                return AI_PKT_MGMT;
        }
    }

    if (type == 1) {
        return AI_PKT_CTRL;
    }

    if (type == 2) {
        return AI_PKT_DATA;
    }

    return AI_PKT_OTHER;
}

static float heuristic_confidence(ai_pkt_class_t cls)
{
    if (cls == AI_PKT_OTHER) {
        return 0.3f;
    }

    return 0.8f;
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t ai_classifier_init(void)
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

    g_init_done = true;
    g_total_count = 0;
    g_model_count = 0;
    g_heuristic_count = 0;
    g_last_infer_us = 0;
    g_infer_every = AI_CLASSIFIER_DEFAULT_INFER_EVERY;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Classifier initialized (input_max=%d)", AI_CLASSIFIER_INPUT_MAX);
    return ESP_OK;
}

void ai_classifier_deinit(void)
{
    if (g_lock == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_model_name, 0, sizeof(g_model_name));

    g_init_done = false;
    g_total_count = 0;
    g_model_count = 0;
    g_heuristic_count = 0;
    g_last_infer_us = 0;
    g_infer_every = AI_CLASSIFIER_DEFAULT_INFER_EVERY;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Classifier deinitialized");
}

/* -------------------------------------------------------------------------
 *  Configuration
 * ----------------------------------------------------------------------- */

esp_err_t ai_classifier_set_model(const char *model_name)
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

    ESP_LOGI(TAG, "Classifier model set: '%s'", g_model_name);
    return ESP_OK;
}

esp_err_t ai_classifier_set_infer_every(uint32_t every_n)
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

    ESP_LOGI(TAG, "Classifier inference every %" PRIu32 " calls", every_n);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Prediction
 * ----------------------------------------------------------------------- */

esp_err_t ai_classifier_predict_meta(const uint8_t *frame,
                                     size_t frame_len,
                                     int8_t rssi,
                                     uint8_t channel,
                                     ai_classify_result_t *out)
{
    if (frame == NULL || out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    memset(out, 0, sizeof(*out));

    uint8_t tensor[AI_CLASSIFIER_INPUT_MAX];
    extract_features(frame, frame_len, rssi, channel, tensor);

    ai_pkt_class_t heuristic_cls = heuristic_classify(frame, frame_len);
    float heuristic_conf = heuristic_confidence(heuristic_cls);

    char model_local[sizeof(g_model_name)] = {0};
    bool should_infer = false;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    g_total_count++;

    bool model_enabled = (g_model_name[0] != '\0');

    if (model_enabled) {
        if (g_infer_every <= 1 || (g_total_count % g_infer_every) == 0) {
            snprintf(model_local, sizeof(model_local), "%s", g_model_name);
            should_infer = true;
        }
    }

    xSemaphoreGive(g_lock);

    if (should_infer) {
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
            uint8_t cls_byte = model_out[0];

            if (cls_byte < AI_CLASSIFIER_NUM_CLASSES) {
                float confidence = 0.5f;

                if (out_len >= 2) {
                    confidence = (float)model_out[1] / 255.0f;
                }

                xSemaphoreTake(g_lock, portMAX_DELAY);

                g_model_count++;
                g_last_infer_us = (uint32_t)dt;

                out->cls = (ai_pkt_class_t)cls_byte;
                out->confidence = confidence;
                out->inference_us = g_last_infer_us;
                out->model_loaded = true;

                xSemaphoreGive(g_lock);

                return ESP_OK;
            }
        }

        ESP_LOGD(TAG, "Model inference failed or invalid; using heuristic");
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    g_heuristic_count++;

    out->cls = heuristic_cls;
    out->confidence = heuristic_conf;
    out->inference_us = 0;
    out->model_loaded = false;

    xSemaphoreGive(g_lock);

    return ESP_OK;
}

esp_err_t ai_classifier_predict(const uint8_t *frame,
                                size_t frame_len,
                                ai_classify_result_t *out)
{
    return ai_classifier_predict_meta(frame, frame_len, 0, 0, out);
}

/* -------------------------------------------------------------------------
 *  Stats / JSON
 * ----------------------------------------------------------------------- */

esp_err_t ai_classifier_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    uint32_t total;
    uint32_t model;
    uint32_t heuristic;
    uint32_t last_infer_us;
    uint32_t infer_every;
    char model_name[sizeof(g_model_name)];

    xSemaphoreTake(g_lock, portMAX_DELAY);

    total = g_total_count;
    model = g_model_count;
    heuristic = g_heuristic_count;
    last_infer_us = g_last_infer_us;
    infer_every = g_infer_every;
    snprintf(model_name, sizeof(model_name), "%s", g_model_name);

    xSemaphoreGive(g_lock);

    int w = snprintf(
        buf,
        bufsz,
        "{\"total\":%" PRIu32
        ",\"model\":%" PRIu32
        ",\"heuristic\":%" PRIu32
        ",\"last_infer_us\":%" PRIu32
        ",\"infer_every\":%" PRIu32
        ",\"model_name\":\"%s\"}",
        total,
        model,
        heuristic,
        last_infer_us,
        infer_every,
        model_name
    );

    if (w < 0 || (size_t)w >= bufsz) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}
