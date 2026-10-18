#ifndef BLE_PHY_H
#define BLE_PHY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "common_types.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * Parse BLE coded PHY flags from advertisement data.
 * Returns true if any PHY evidence was found.
 */
static inline esp_err_t ble_phy_init(void) { return ESP_OK; }

bool ble_phy_parse(const uint8_t *data, uint8_t len,
                   bool *out_phy_coded, bool *out_phy_coded_s8,
                   bool *out_phy_1m, bool *out_phy_2m,
                   bool *out_phy_coded_supported);

/* 
 * Set scan PHY preferences.
 * Note: This only updates the configuration state. The actual NimBLE 
 * scanner task should read this via ble_phy_get_scan_phys().
 */
esp_err_t ble_phy_start_scan(uint8_t phys);

/* 
 * Get the currently configured scan PHY mask.
 */
uint8_t ble_phy_get_scan_phys(void);

#ifdef __cplusplus
}
#endif

#endif /* BLE_PHY_H */
