#ifndef AI_TRAINING_H
#define AI_TRAINING_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Training capture mode. */
typedef enum {
    AI_TRAIN_MODE_OFF = 0,
    AI_TRAIN_MODE_WIFI = 1,
    AI_TRAIN_MODE_BLE = 2,
    AI_TRAIN_MODE_BOTH = 3
} ai_train_mode_t;

/* Per-packet label for training data. */
typedef struct {
    uint64_t timestamp_us;
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  pkt_class;   /* from ai_classifier */
    float    pkt_confidence;
    uint8_t  device_class;/* from ai_fingerprint / ai_ble_profiler */
    bool     is_anomaly;
    float    anomaly_score;
    bool     is_rogue;
    uint8_t  flags;       /* bitmask of extra labels */
    uint8_t  mac[6];      /* BSSID or BLE MAC */
    uint8_t  mac_len;     /* 6 for BSSID/BLE, 0 if unknown */
} ai_train_label_t;

/**
 * @brief Initialize training data capture subsystem.
 */
esp_err_t ai_train_init(void);

/**
 * @brief Start capture in specified mode.
 *
 * Writes PCAP to /sd/train_<timestamp>.pcap and labels to sidecar JSON.
 */
esp_err_t ai_train_start(ai_train_mode_t mode);

/**
 * @brief Stop capture and close files. */
esp_err_t ai_train_stop(void);

/**
 * @brief Label a captured WiFi packet. */
esp_err_t ai_train_label_wifi(const uint8_t *mac, const uint8_t *frame,
                              size_t frame_len, uint8_t channel,
                              int8_t rssi, uint64_t timestamp_us);

/**
 * @brief Label a captured BLE packet. */
esp_err_t ai_train_label_ble(const uint8_t *mac, const uint8_t *adv_data,
                             size_t adv_len, int8_t rssi,
                             uint64_t timestamp_us);

/**
 * @brief Get current capture status. */
ai_train_mode_t ai_train_get_mode(void);

/**
 * @brief Return training stats as JSON. */
esp_err_t ai_train_json(char *buf, size_t bufsz);

/**
 * @brief Deinit training capture. */
void ai_train_deinit(void);

#ifdef __cplusplus
}
#endif
#endif /* AI_TRAINING_H */
