#ifndef BLE_EXT_ADV_H
#define BLE_EXT_ADV_H

#include <stdint.h>
#include <stdbool.h>
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Parse BLE 5.0 extended advertising fields from advertisement data.
 * Returns true if extended advertising evidence was found.
 * out_has_aux_ptr: true if Auxiliary Pointer present
 * out_has_adi:     true if Advertising Data Info present
 * out_adv_mode:    0=legacy, 1=non-connectable, 2=scannable
 * out_has_scan_rsp: true if this looks like a scan response
 * out_tx_power:    TX power in dBm if present, else 0x7F=unavailable */
bool ble_ext_adv_parse(const uint8_t *data, uint8_t len,
                       bool *out_has_aux_ptr, bool *out_has_adi,
                       uint8_t *out_adv_mode, bool *out_has_scan_rsp,
                       uint8_t *out_tx_power);

#ifdef __cplusplus
}
#endif
#endif /* BLE_EXT_ADV_H */
