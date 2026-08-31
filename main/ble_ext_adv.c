#include "ble_ext_adv.h"
#include <string.h>
#include <stdbool.h>
#include "esp_log.h"

static const char *TAG = "ble_ext_adv";

/* BLE advertising data types */
#define ADV_TYPE_FLAGS                   0x01
#define ADV_TYPE_NAME                    0x09
#define ADV_TYPE_MFG_DATA                0xFF
#define ADV_TYPE_AUX_PTR                 0x1F
#define ADV_TYPE_ADI                     0x29

/* ADI subfield: 2 bytes = SID + DID */

/* Extended advertising mode bits in ADI/header */
#define ADV_MODE_NONCONN                 (1 << 0)
#define ADV_MODE_SCANNABLE               (1 << 1)

/* TX Power level AD type */
#define ADV_TYPE_TX_POWER_LEVEL          0x0A

bool ble_ext_adv_parse(const uint8_t *data, uint8_t len,
                       bool *out_has_aux_ptr, bool *out_has_adi,
                       uint8_t *out_adv_mode, bool *out_has_scan_rsp,
                       uint8_t *out_tx_power)
{
    if (data == NULL || len == 0) return false;
    if (out_has_aux_ptr) *out_has_aux_ptr = false;
    if (out_has_adi) *out_has_adi = false;
    if (out_has_scan_rsp) *out_has_scan_rsp = false;
    if (out_adv_mode) *out_adv_mode = 0;
    if (out_tx_power) *out_tx_power = 0x7F;

    bool saw_ext = false;
    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t adv_len = data[pos];
        if (adv_len == 0) break;
        if (pos + 1 + adv_len > len) break;

        uint8_t type = data[pos + 1];
        uint8_t payload_len = adv_len - 1;

        switch (type) {
            case ADV_TYPE_AUX_PTR:
                if (out_has_aux_ptr) *out_has_aux_ptr = true;
                saw_ext = true;
                break;

            case ADV_TYPE_ADI:
                if (out_has_adi) *out_has_adi = true;
                saw_ext = true;
                if (payload_len >= 2) {
                    uint8_t mode = data[pos + 3] & 0x03;
                    if (out_adv_mode) *out_adv_mode = mode;
                }
                break;

            case ADV_TYPE_TX_POWER_LEVEL:
                if (out_tx_power && payload_len >= 1) {
                    *out_tx_power = data[pos + 2];
                }
                break;

            case ADV_TYPE_FLAGS:
                if (payload_len >= 1) {
                    uint8_t flags = data[pos + 2];
                    /* BR/EDR not supported + LE General = extended-capable */
                    if ((flags & 0x04) && (flags & 0x18)) saw_ext = true;
                }
                break;

            default:
                break;
        }

        pos += 1 + adv_len;
    }

    return saw_ext;
}
