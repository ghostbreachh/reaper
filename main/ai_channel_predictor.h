#ifndef AI_CHANNEL_PREDICTOR_H
#define AI_CHANNEL_PREDICTOR_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* History window size: number of past occupancy snapshots to keep. */
#define AI_CH_PREDICTOR_HISTORY   8

/* Predicted result. */
typedef struct {
    uint8_t  best_channel;     /* predicted best channel (1..13) */
    float    confidence;       /* model confidence 0..1 */
    uint32_t history_count;    /* snapshots collected so far */
    uint32_t infer_count;      /* successful model inferences */
    uint32_t fallback_count;   /* heuristic fallback uses */
    bool     model_loaded;
    uint32_t inference_us;
} ai_channel_predict_t;

/**
 * @brief Initialize channel predictor.
 */
esp_err_t ai_channel_predictor_init(void);

/**
 * @brief Set model name for LSTM predictor.
 */
esp_err_t ai_channel_predictor_set_model(const char *model_name);

/**
 * @brief Record current channel occupancy snapshot.
 *
 * Call this after channel_hopper_get_all_stats() to push new data.
 */
esp_err_t ai_channel_predictor_record(void);

/**
 * @brief Predict best next channel for attacks/scanning.
 *
 * Uses LSTM model if loaded; otherwise picks channel with highest
 * recent packet count from history.
 */
esp_err_t ai_channel_predictor_predict(ai_channel_predict_t *out);

/**
 * @brief Return predictor stats as JSON. */
esp_err_t ai_channel_predictor_json(char *buf, size_t bufsz);

/**
 * @brief Deinit predictor. */
void ai_channel_predictor_deinit(void);

#ifdef __cplusplus
}
#endif
#endif /* AI_CHANNEL_PREDICTOR_H */
