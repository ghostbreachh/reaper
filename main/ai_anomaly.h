#ifndef AI_ANOMALY_H
#define AI_ANOMALY_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Anomaly detector window size (number of packets to buffer). */
#define AI_ANOMALY_WINDOW    16

/* Feature vector size per packet. */
#define AI_ANOMALY_FEAT_SZ   8

/* Anomaly detection result. */
typedef struct {
    float    score;        /* Reconstruction error (higher = more anomalous) */
    bool     is_anomaly;   /* true if score exceeds threshold */
    uint32_t packet_count; /* total packets fed */
    uint32_t anomaly_count;/* total anomalies flagged */
} ai_anomaly_result_t;

/**
 * @brief Initialize anomaly detector.
 */
esp_err_t ai_anomaly_init(void);

/**
 * @brief Set model name for autoencoder inference.
 */
esp_err_t ai_anomaly_set_model(const char *model_name);

/**
 * @brief Set anomaly threshold (default 0.5).
 */
esp_err_t ai_anomaly_set_threshold(float threshold);

/**
 * @brief Feed a packet into the sliding window.
 *
 * @param rssi         Packet RSSI (dBm)
 * @param frame_len    Frame length in bytes
 * @param timestamp_us Timestamp in microseconds (for inter-arrival calc)
 */
esp_err_t ai_anomaly_feed(int8_t rssi, uint16_t frame_len, uint64_t timestamp_us);

/**
 * @brief Get latest anomaly result.
 */
esp_err_t ai_anomaly_get_result(ai_anomaly_result_t *out);

/**
 * @brief Return anomaly stats as JSON.
 */
esp_err_t ai_anomaly_json(char *buf, size_t bufsz);

/**
 * @brief Deinit anomaly detector.
 */
void ai_anomaly_deinit(void);

#ifdef __cplusplus
}
#endif
#endif /* AI_ANOMALY_H */
