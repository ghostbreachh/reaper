#ifndef AI_DEAUTH_PREDICTOR_H
#define AI_DEAUTH_PREDICTOR_H

#include <stdint.h>
#include <stdbool.h>

#include "esp_err.h"
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum tracked targets. */
#define AI_DEAUTH_PREDICTOR_MAX_TARGETS MAX_TARGET_APS

/* Prediction flag bits. */
#define AI_DEAUTH_FLAG_UNPROTECTED     (1u << 0)
#define AI_DEAUTH_FLAG_STRONG_SIGNAL   (1u << 1)
#define AI_DEAUTH_FLAG_UNICAST_TARGET  (1u << 2)
#define AI_DEAUTH_FLAG_NO_FALLBACK     (1u << 3)
#define AI_DEAUTH_FLAG_PMF_REQUIRED    (1u << 4)
#define AI_DEAUTH_FLAG_WPA3            (1u << 5)

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
 * @brief Deinit predictor.
 */
void ai_deauth_predictor_deinit(void);

/**
 * @brief Set model name for effectiveness predictor.
 */
esp_err_t ai_deauth_predictor_set_model(const char *model_name);

/**
 * @brief Predict deauth success probability for a specific target.
 */
esp_err_t ai_deauth_predictor_predict(uint8_t target_index,
                                      ai_deauth_prediction_t *out);

/**
 * @brief Predict for all active targets.
 */
esp_err_t ai_deauth_predictor_predict_all(void);

/**
 * @brief Return predictor predictions as JSON array.
 */
esp_err_t ai_deauth_predictor_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif /* AI_DEAUTH_PREDICTOR_H */
