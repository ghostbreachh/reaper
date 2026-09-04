#ifndef STEALTH_H
#define STEALTH_H

#include <stdint.h>
#include <stdbool.h>
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

/* Initialize stealth module. */
esp_err_t stealth_init(void);

/* Set current stealth mode. */
esp_err_t stealth_set_mode(stealth_mode_t mode);

/* Generate and apply a random locally administered MAC. */
esp_err_t stealth_set_random_mac(void);

/* Restore factory MAC. */
esp_err_t stealth_restore_mac(void);

/* Set minimum TX power (0 dBm). */
esp_err_t stealth_set_min_tx_power(void);

/* Restore default TX power (19 dBm). */
esp_err_t stealth_restore_tx_power(void);

/* Get current mode. */
stealth_mode_t stealth_get_mode(void);

/* Check whether active TX is permitted. */
bool stealth_can_transmit(void);

/* Export stats as JSON. */
esp_err_t stealth_json(char *buf, size_t bufsz);

/* Deinit. */
esp_err_t stealth_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* STEALTH_H */
