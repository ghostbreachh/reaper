#ifndef BLE_PHY_H
#define BLE_PHY_H

#include <stdint.h>
#include <stdbool.h>
#include "common_types.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Parse BLE coded PHY flags from advertisement data.
 * Returns true if any PHY evidence was found.
 * out_phy_coded:      true if coded PHY was seen
 * out_phy_coded_s8:   true if S=8 coding was seen
 * out_phy_1m:         true if 1M PHY was seen
 * out_phy_2m:         true if 2M PHY was seen
 * out_phy_coded_supported: true if advertiser claims coded PHY support */
bool ble_phy_parse(const uint8_t *data, uint8_t len,
                   bool *out_phy_coded, bool *out_phy_coded_s8,
                   bool *out_phy_1m, bool *out_phy_2m,
                   bool *out_phy_coded_supported);

/* Start scanning with specific PHY preferences.
 * phys: bitmask of BLE_GAP_SCAN_PHY_* flags
 * Returns ESP_OK on success. */
esp_err_t ble_phy_start_scan(uint8_t phys);

#ifdef __cplusplus
}
#endif
#endif /* BLE_PHY_H */
