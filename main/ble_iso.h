#ifndef BLE_ISO_H
#define BLE_ISO_H

#include <stdint.h>
#include <stdbool.h>
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize BLE ISO/BIG prep subsystem. */
esp_err_t ble_iso_init(void);

/* Parse BLE advertising data for ISO-related fields.
 * Returns true if any ISO evidence was found.
 * out_has_big:      true if Broadcast ISO / BIG info seen
 * out_iso_channels: receives number of ISO channels if present
 * out_bis_handles:  receives BIS handle array (max 4 handles)
 * out_iso_interval: receives ISO interval in microseconds if present */
bool ble_iso_parse(const uint8_t *data, uint8_t len,
                   bool *out_has_big, uint8_t *out_iso_channels,
                   uint8_t out_bis_handles[4], uint32_t *out_iso_interval);

/* Check if ISO/BIG is active on a known device. */
bool ble_iso_is_known(const uint8_t *mac);

/* Get ISO stats as JSON string. */
int ble_iso_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif
#endif /* BLE_ISO_H */
