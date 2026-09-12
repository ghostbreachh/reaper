#ifndef STEALTH_H
#define STEALTH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Stealth operating mode. */
typedef enum {
    STEALTH_MODE_OFF = 0,    /* normal operation */
    STEALTH_MODE_PASSIVE,    /* random MAC, min TX, no active frames */
    STEALTH_MODE_ACTIVE      /* random MAC, min TX, active attacks allowed */
} stealth_mode_t;

esp_err_t stealth_init(void);
esp_err_t stealth_set_mode(stealth_mode_t mode);

esp_err_t stealth_set_random_mac(void);
esp_err_t stealth_restore_mac(void);

esp_err_t stealth_set_min_tx_power(void);
esp_err_t stealth_restore_tx_power(void);

stealth_mode_t stealth_get_mode(void);
bool stealth_can_transmit(void);

/**
 * @brief Check if transmission is allowed.
 * 
 * Offensive modules should call this before sending packets.
 * Returns ESP_OK if allowed, ESP_ERR_NOT_ALLOWED if in passive mode.
 */
esp_err_t stealth_check_tx(const char *module_name);

esp_err_t stealth_json(char *buf, size_t bufsz);
esp_err_t stealth_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* STEALTH_H */
