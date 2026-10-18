#ifndef BLE_ISO_H
#define BLE_ISO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize BLE ISO/BIG prep subsystem. */
esp_err_t ble_iso_init(void);

/* Parse BLE advertising data for ISO-related fields.
 * Returns true if any ISO evidence was found. */
bool ble_iso_parse(const uint8_t *data, uint8_t len,
                   bool *out_has_big, uint8_t *out_iso_channels,
                   uint8_t out_bis_handles[4], uint32_t *out_iso_interval);

/* Record a device in the ISO tracking list.
 * Call this from the scanner after ble_iso_parse returns true. */
void ble_iso_record(const uint8_t *mac, bool has_big,
                    uint8_t iso_channels, uint32_t iso_interval_us);

/* Check if ISO/BIG is active on a known device. */
bool ble_iso_is_known(const uint8_t *mac);

/* Get ISO stats as JSON string. */
int ble_iso_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif /* BLE_ISO_H */
