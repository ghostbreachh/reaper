#ifndef WARDIRVE_H
#define WARDIRVE_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Wardrive logging mode. */
typedef enum {
    WARDIRVE_MODE_OFF = 0,
    WARDIRVE_MODE_WIFI,
    WARDIRVE_MODE_BLE,
    WARDIRVE_MODE_BOTH
} wardrive_mode_t;

/* Wardrive statistics. */
typedef struct {
    uint32_t wifi_points;
    uint32_t ble_points;
    uint32_t total_points;
    uint64_t start_us;
    uint64_t end_us;
    uint32_t geo_points;    /* points with valid GPS */
    uint32_t skipped_no_geo; /* skipped because no GPS */
    char export_path[128];
} wardrive_stats_t;

/* Initialize wardrive module. */
esp_err_t wardrive_init(void);

/* Start logging with given mode. */
esp_err_t wardrive_start(wardrive_mode_t mode);

/* Stop logging and close file. */
esp_err_t wardrive_stop(void);

/* Log a WiFi AP/device. */
esp_err_t wardrive_log_wifi(const char *bssid, const char *ssid,
                            int8_t rssi, uint8_t channel,
                            const char *security);

/* Log a BLE device. */
esp_err_t wardrive_log_ble(const uint8_t *addr, const char *name,
                           int8_t rssi, uint8_t channel);

/* Get current statistics. */
esp_err_t wardrive_get_stats(wardrive_stats_t *out);

/* Export stats as JSON string. */
esp_err_t wardrive_json(char *buf, size_t bufsz);

/* Get current mode without blocking. */
wardrive_mode_t wardrive_get_mode(void);

/* Deinit. */
esp_err_t wardrive_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* WARDIRVE_H */
