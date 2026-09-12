#ifndef WARDRIVE_H
#define WARDRIVE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Wardrive logging mode. */
typedef enum {
    WARDRIVE_MODE_OFF = 0,
    WARDRIVE_MODE_WIFI,
    WARDRIVE_MODE_BLE,
    WARDRIVE_MODE_BOTH
} wardrive_mode_t;

/* Backward compatibility for previous typo */
#define WARDIRVE_MODE_OFF  WARDRIVE_MODE_OFF
#define WARDIRVE_MODE_WIFI WARDRIVE_MODE_WIFI
#define WARDIRVE_MODE_BLE  WARDRIVE_MODE_BLE
#define WARDIRVE_MODE_BOTH WARDRIVE_MODE_BOTH

/* Wardrive statistics. */
typedef struct {
    uint32_t wifi_points;
    uint32_t ble_points;
    uint32_t total_points;
    uint64_t start_us;
    uint64_t end_us;
    uint32_t geo_points;     /* points with valid GPS */
    uint32_t no_geo_points;  /* points logged without GPS */
    char export_path[128];
} wardrive_stats_t;

esp_err_t wardrive_init(void);
esp_err_t wardrive_start(wardrive_mode_t mode);
esp_err_t wardrive_stop(void);

esp_err_t wardrive_log_wifi(const char *bssid, const char *ssid,
                            int8_t rssi, uint8_t channel,
                            const char *security);

esp_err_t wardrive_log_ble(const uint8_t *addr, const char *name,
                           int8_t rssi, uint8_t channel);

esp_err_t wardrive_get_stats(wardrive_stats_t *out);
esp_err_t wardrive_json(char *buf, size_t bufsz);
wardrive_mode_t wardrive_get_mode(void);
esp_err_t wardrive_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* WARDRIVE_H */
