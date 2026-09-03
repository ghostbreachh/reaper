#ifndef AI_CLASSIFIER_H
#define AI_CLASSIFIER_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum raw frame bytes used as classifier input. */
#define AI_CLASSIFIER_INPUT_MAX  64

/* Number of packet type classes. */
#define AI_CLASSIFIER_NUM_CLASSES 8

/* Packet type class labels. */
typedef enum {
    AI_PKT_MGMT  = 0,
    AI_PKT_CTRL  = 1,
    AI_PKT_DATA  = 2,
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
 *
 * Does NOT load any model; load is explicit via ai_model_zoo_load().
 */
esp_err_t ai_classifier_init(void);

/**
 * @brief Set which model name to use for classification.
 *
 * Model must be loaded in the zoo first.
 */
esp_err_t ai_classifier_set_model(const char *model_name);

/**
 * @brief Classify a raw 802.11 frame.
 *
 * @param frame      Pointer to raw frame bytes (starting from frame_ctrl)
 * @param frame_len  Length of frame in bytes (capped at AI_CLASSIFIER_INPUT_MAX)
 * @param out        Output result struct
 */
esp_err_t ai_classifier_predict(const uint8_t *frame, size_t frame_len,
                                ai_classify_result_t *out);

/**
 * @brief Convert class enum to human-readable string. */
const char *ai_classifier_class_name(ai_pkt_class_t cls);

/**
 * @brief Return JSON with last classification stats. */
esp_err_t ai_classifier_json(char *buf, size_t bufsz);

/**
 * @brief Deinit classifier. */
void ai_classifier_deinit(void);

#ifdef __cplusplus
}
#endif
#endif /* AI_CLASSIFIER_H */
