#ifndef COEX_H
#define COEX_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Coexistence preference: which radio gets priority. */
typedef enum {
    COEX_PREF_WIFI = 0,   /* WiFi gets airtime priority (sniffing/attacks) */
    COEX_PREF_BLE  = 1,   /* BLE gets airtime priority (tracking) */
    COEX_PREF_BALANCE = 2 /* Split evenly; ESP-IDF handles arbitration */
} coex_pref_t;

/* Runtime coexistence status snapshot. */
typedef struct {
    bool     wifi_has_radio;   /* WiFi currently transmitting/receiving */
    bool     ble_has_radio;    /* BLE currently active */
    bool     wifi_preempted;   /* WiFi was paused for BLE */
    bool     ble_preempted;    /* BLE was paused for WiFi */
    uint32_t wifi_preempt_count;
    uint32_t ble_preempt_count;
} coex_status_t;

/**
 * @brief Initialize coexistence subsystem.
 *
 * Registers the ESP-IDF coexistence adapter and sets initial preference.
 * Must be called BEFORE esp_wifi_init() and esp_bt_controller_enable().
 */
esp_err_t coex_init(void);

/**
 * @brief Set airtime preference between WiFi and BLE.
 */
esp_err_t coex_set_preference(coex_pref_t pref);

/**
 * @brief Get current preference. */
coex_pref_t coex_get_preference(void);

/**
 * @brief Take a snapshot of current coexistence status. */
esp_err_t coex_get_status(coex_status_t *out_status);

/**
 * @brief Return formatted JSON with preference + status. */
esp_err_t coex_json(char *buf, size_t bufsz);

/**
 * @brief Query whether WiFi is currently active on air.
 */
bool coex_wifi_active(void);

/**
 * @brief Query whether BLE is currently active on air.
 */
bool coex_ble_active(void);

#ifdef __cplusplus
}
#endif
#endif /* COEX_H */
