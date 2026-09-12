#ifndef AI_CLASSIFIER_H
#define AI_CLASSIFIER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum raw frame bytes used as classifier input. */
#define AI_CLASSIFIER_INPUT_MAX          64

/* Number of packet type classes. */
#define AI_CLASSIFIER_NUM_CLASSES        8

/* Default model inference divider. */
#define AI_CLASSIFIER_DEFAULT_INFER_EVERY 4

/* Packet type class labels. */
typedef enum {
    AI_PKT_MGMT   = 0,
    AI_PKT_CTRL   = 1,
    AI_PKT_DATA   = 2,
    AI_PKT_BEACON = 3,
    AI_PKT_PROBE  = 4,
    AI_PKT_AUTH   = 5,
    AI_PKT_ASSOC  = 6,
    AI_PKT_OTHER  = 7
} ai_pkt_class_t;

/* Classifier result. */
typedef struct {
    ai_pkt_class_t cls;
    float confidence;
    uint32_t inference_us;
    bool model_loaded;
} ai_classify_result_t;

/**
 * @brief Initialize packet classifier subsystem.
 */
esp_err_t ai_classifier_init(void);

/**
 * @brief Deinit classifier.
 */
void ai_classifier_deinit(void);

/**
 * @brief Set which model name to use for classification.
 */
esp_err_t ai_classifier_set_model(const char *model_name);

/**
 * @brief Set how often model inference runs.
 *
 * every_n = 1 -> every classification
 * every_n = 4 -> every 4 classifications
 */
esp_err_t ai_classifier_set_infer_every(uint32_t every_n);

/**
 * @brief Classify a raw 802.11 frame without RSSI/channel metadata.
 */
esp_err_t ai_classifier_predict(const uint8_t *frame,
                                size_t frame_len,
                                ai_classify_result_t *out);

/**
 * @brief Classify a raw 802.11 frame with RSSI/channel metadata.
 */
esp_err_t ai_classifier_predict_meta(const uint8_t *frame,
                                     size_t frame_len,
                                     int8_t rssi,
                                     uint8_t channel,
                                     ai_classify_result_t *out);

/**
 * @brief Convert class enum to human-readable string.
 */
const char *ai_classifier_class_name(ai_pkt_class_t cls);

/**
 * @brief Return JSON with classifier stats.
 */
esp_err_t ai_classifier_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif /* AI_CLASSIFIER_H */
