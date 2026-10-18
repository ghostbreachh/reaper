#ifndef AI_CHANNEL_PREDICTOR_H
#define AI_CHANNEL_PREDICTOR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* History window size: number of past occupancy snapshots to keep. */
#define AI_CH_PREDICTOR_HISTORY                   8

/* Default minimum time between automatic snapshot records. */
#define AI_CH_PREDICTOR_DEFAULT_RECORD_INTERVAL_MS 250

/* Predicted result. */
typedef struct {
    uint8_t  best_channel;     /* predicted best channel (1..13) */
    float    confidence;       /* confidence 0..1 */
    uint32_t history_count;    /* snapshots collected so far */
    uint32_t infer_count;      /* successful model inferences */
    uint32_t fallback_count;   /* heuristic fallback uses */
    bool     model_loaded;     /* true if last prediction used model */
    uint32_t inference_us;     /* last model inference time */
} ai_channel_predict_t;

/**
 * @brief Initialize channel predictor.
 */
esp_err_t ai_channel_predictor_init(void);

/**
 * @brief Deinit predictor.
 */
void ai_channel_predictor_deinit(void);

/**
 * @brief Set model name for LSTM predictor.
 */
esp_err_t ai_channel_predictor_set_model(const char *model_name);

/**
 * @brief Set minimum interval between record snapshots.
 *
 * interval_ms = 0 allows every call, but this is not recommended
 * when called from packet-processing paths.
 */
esp_err_t ai_channel_predictor_set_record_interval_ms(uint32_t interval_ms);

/**
 * @brief Record current channel occupancy snapshot.
 *
 * This is internally throttled by the record interval.
 */
esp_err_t ai_channel_predictor_record(void);

/**
 * @brief Predict best next channel for scanning/attack planning.
 *
 * Uses LSTM model if loaded; otherwise picks channel with highest
 * recent packet delta from history.
 */
esp_err_t ai_channel_predictor_predict(ai_channel_predict_t *out);

/**
 * @brief Return predictor stats as JSON.
 */
esp_err_t ai_channel_predictor_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif /* AI_CHANNEL_PREDICTOR_H */
