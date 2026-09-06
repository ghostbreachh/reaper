#ifndef MATTER_COMMISSIONER_H
#define MATTER_COMMISSIONER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Matter commissioner stub for future Thread-capable hardware.
 *
 *  Feature 93 — [HW] Matter commissioner
 *
 *  Current hardware: ESP32-S3 has no 802.15.4 radio.
 *  Matter over WiFi is theoretically possible but commissioning
 *  requires Thread or BLE. This module provides the API surface
 *  for future hardware with native Thread support.
 */

esp_err_t matter_commissioner_init(void);
esp_err_t matter_commissioner_start(const char *setup_payload);
esp_err_t matter_commissioner_stop(void);
bool matter_commissioner_is_active(void);
esp_err_t matter_commissioner_get_devices(char *out, size_t max_len);

#ifdef __cplusplus
}
#endif
#endif
