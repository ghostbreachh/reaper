#ifndef AI_ANOMALY_H
#define AI_ANOMALY_H

#include <stdint.h>
#include <stdbool.h>

#include "esp_err.h"
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Anomaly detector window size (number of packets to buffer). */
#define AI_ANOMALY_WINDOW               16

/* Feature vector size per packet. */
#define AI_ANOMALY_FEAT_SZ              8

/* Minimum number of previous samples required before anomaly scoring. */
#define AI_ANOMALY_MIN_SAMPLES          4

/* Default threshold for anomaly classification. */
#define AI_ANOMALY_DEFAULT_THRESHOLD    0.5f

/*
 * Default model inference divider.
 *
 * If set to 4, model inference runs every 4 packets.
 * Lightweight fallback scoring still runs every packet.
 */
#define AI_ANOMALY_DEFAULT_INFER_EVERY  4

/* Anomaly detection result. */
typedef struct {
    float    score;         /* Reconstruction/error score. Higher = more anomalous. */
    bool     is_anomaly;    /* true if score exceeds threshold */
    uint32_t packet_count;  /* total packets fed */
    uint32_t anomaly_count; /* total anomalies flagged */
} ai_anomaly_result_t;

/**
 * @brief Initialize anomaly detector.
 */
esp_err_t ai_anomaly_init(void);

/**
 * @brief Deinitialize anomaly detector.
 */
void ai_anomaly_deinit(void);

/**
 * @brief Reset window and counters without losing model/threshold config.
 */
esp_err_t ai_anomaly_reset(void);

/**
 * @brief Set model name for autoencoder inference.
 */
esp_err_t ai_anomaly_set_model(const char *model_name);

/**
 * @brief Set anomaly threshold.
 */
esp_err_t ai_anomaly_set_threshold(float threshold);

/**
 * @brief Set how often model inference runs.
 *
 * every_n = 1 -> every packet
 * every_n = 4 -> every 4 packets
 */
esp_err_t ai_anomaly_set_infer_every(uint32_t every_n);

/**
 * @brief Feed a packet into the sliding window.
 *
 * @param rssi         Packet RSSI (dBm)
 * @param frame_len    Frame length in bytes
 * @param timestamp_us Timestamp in microseconds
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
 * @brief Wi-Fi sniffer observer wrapper.
 *
 * Register with:
 *   wifi_sniffer_register_observer(ai_anomaly_wifi_observer);
 */
void ai_anomaly_wifi_observer(const wifi_pkt_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* AI_ANOMALY_H */
