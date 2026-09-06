#ifndef THREAD_BORDER_ROUTER_H
#define THREAD_BORDER_ROUTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Thread Border Router stub for future ESP32-H2/C6 hardware.
 *
 *  Feature 92 — [HW] Thread border router
 *
 *  Current hardware: ESP32-S3 has no 802.15.4 radio.
 *  This module provides the API surface for future hardware.
 *  All functions are safe no-ops until compiled with
 *  CONFIG_IDF_TARGET_ESP32H2 or similar Thread-capable target.
 */

esp_err_t thread_br_init(void);
esp_err_t thread_br_start(void);
esp_err_t thread_br_stop(void);
bool thread_br_is_active(void);
esp_err_t thread_br_get_dataset(char *out, size_t max_len);

#ifdef __cplusplus
}
#endif
#endif
