#ifndef AI_DEAUTH_PREDICTOR_H
#define AI_DEAUTH_PREDICTOR_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Deauth prediction result. */
typedef struct {
    float    probability;   /* 0..1: higher = more likely to succeed */
    uint8_t  target_index;  /* which target this prediction is for */
    uint8_t  flags;         /* bitmask of risk factors */
    bool     model_loaded;
    uint32_t inference_us;
} ai_deauth_prediction_t;

/**
 * @brief Initialize deauth effectiveness predictor.
 */
esp_err_t ai_deauth_predictor_init(void);

/**
 * @brief Set model name for effectiveness predictor.
 */
esp_err_t ai_deauth_predictor_set_model(const char *model_name);

/**
 * @brief Predict deauth success probability for a specific target.
 *
 * @param target_index  Index into deauth target array
 * @param out           Output prediction
 */
esp_err_t ai_deauth_predictor_predict(uint8_t target_index,
                                       ai_deauth_prediction_t *out);

/**
 * @brief Predict for all active targets.
 */
esp_err_t ai_deauth_predictor_predict_all(void);

/**
 * @brief Return predictor stats as JSON. */
esp_err_t ai_deauth_predictor_json(char *buf, size_t bufsz);

/**
 * @brief Deinit predictor. */
void ai_deauth_predictor_deinit(void);

#ifdef __cplusplus
}
#endif
#endif /* AI_DEAUTH_PREDICTOR_H */
