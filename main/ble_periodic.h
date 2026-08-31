#ifndef BLE_PERIODIC_H
#define BLE_PERIODIC_H

#include <stdint.h>
#include <stdbool.h>
#include "common_types.h"
#include "esp_err.h"

#define PA_INTERVAL_DEFAULT_1_25MS  80   /* 100 ms */

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize periodic advertising subsystem.
 * Must be called after nimble_port_init().
 * Returns ESP_OK on success. */
esp_err_t ble_periodic_init(void);

/* Query whether periodic sync is active for a given device.
 * adv_mode: 0=legacy, 1=non-connectable, 2=scannable
 * mac: 6-byte BLE address
 * Returns true if periodic sync is established. */
bool ble_periodic_is_synced(uint8_t adv_mode, const uint8_t *mac);

/* Initiate periodic advertising sync transfer.
 * This attempts to establish a sync with a periodic advertiser.
 * Returns ESP_OK if sync request was sent. */
esp_err_t ble_periodic_transfer_sync(const uint8_t *mac, uint8_t adv_mode);

/* Update periodic advertising state from parsed fields.
 * Called by ble_ext_adv_parse() or ble_scanner when periodic evidence is found.
 * Returns true if state changed (new sync established). */
bool ble_periodic_update(const uint8_t *mac, uint8_t adv_mode,
                         bool has_aux_ptr, uint16_t interval_1_25ms);

#ifdef __cplusplus
}
#endif
#endif /* BLE_PERIODIC_H */
