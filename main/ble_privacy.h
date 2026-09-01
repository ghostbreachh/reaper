#ifndef BLE_PRIVACY_H
#define BLE_PRIVACY_H

#include <stdint.h>
#include <stdbool.h>
#include "common_types.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize BLE privacy subsystem. */
esp_err_t ble_privacy_init(void);

/* Parse BLE address to detect Resolvable Private Address (RPA).
 * addr_type: 0=public, 1=random, 2=public identity, 3=random identity
 * mac: 6-byte address
 * out_is_rpa: receives true if RPA detected
 * out_hash: receives lower 3 bytes of RPA hash if RPA, else zeros
 * Returns true if parsing succeeded. */
bool ble_privacy_parse_rpa(uint8_t addr_type, const uint8_t *mac,
                           bool *out_is_rpa, uint8_t out_hash[3]);

/* Set local IRK for address resolution.
 * irk: 16-byte Identity Resolving Key */
void ble_privacy_set_local_irk(const uint8_t irk[16]);

/* Check whether a MAC looks like an RPA.
 * Returns true if addr_type=random and top 2 bits of byte[5] == 0b01. */
bool ble_privacy_is_rpa(uint8_t addr_type, const uint8_t *mac);

/* Get RPA hash for a MAC. Returns false if not RPA. */
bool ble_privacy_get_rpa_hash(const uint8_t *mac, uint8_t out_hash[3]);

/* Count how many discovered BLE devices are using RPAs. */
uint16_t ble_privacy_count_resolvable(void);

/* Build JSON string with privacy stats.
 * buf: destination buffer
 * bufsz: buffer size
 * Returns bytes written. */
int ble_privacy_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif
#endif /* BLE_PRIVACY_H */
