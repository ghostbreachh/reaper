#include "ble_phy.h"
#include <string.h>
#include <stdbool.h>
#include "esp_log.h"

static const char *TAG = "ble_phy";

/* BLE advertising data type for Coded PHY indication */
#define ADV_TYPE_LE_PHY                0x27

/* Flags within LE_PHY field:
 * bit 0 = LE 1M PHY supported
 * bit 1 = LE 2M PHY supported
 * bit 2 = LE Coded PHY (S=2) supported
 * bit 3 = LE Coded PHY (S=8) supported
 */
#define PHY_1M_SUPPORTED                (1 << 0)
#define PHY_2M_SUPPORTED                (1 << 1)
#define PHY_CODED_S2_SUPPORTED          (1 << 2)
#define PHY_CODED_S8_SUPPORTED          (1 << 3)

/* Scan PHY config */
static uint8_t g_scan_phys = 0x01; /* default: 1M only */

bool ble_phy_parse(const uint8_t *data, uint8_t len,
                   bool *out_phy_coded, bool *out_phy_coded_s8,
                   bool *out_phy_1m, bool *out_phy_2m,
                   bool *out_phy_coded_supported)
{
    if (data == NULL || len == 0) return false;
    if (out_phy_coded) *out_phy_coded = false;
    if (out_phy_coded_s8) *out_phy_coded_s8 = false;
    if (out_phy_1m) *out_phy_1m = false;
    if (out_phy_2m) *out_phy_2m = false;
    if (out_phy_coded_supported) *out_phy_coded_supported = false;

    bool saw_any = false;
    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t adv_len = data[pos];
        if (adv_len == 0) break;
        if (pos + 1 + adv_len > len) break;

        uint8_t type = data[pos + 1];
        uint8_t payload_len = adv_len - 1;

        switch (type) {
            case ADV_TYPE_LE_PHY:
                if (payload_len >= 2) {
                    uint8_t tx = data[pos + 2];
                    uint8_t rx = data[pos + 3];
                    if (out_phy_1m && (tx & PHY_1M_SUPPORTED || rx & PHY_1M_SUPPORTED)) {
                        *out_phy_1m = true;
                    }
                    if (out_phy_2m && (tx & PHY_2M_SUPPORTED || rx & PHY_2M_SUPPORTED)) {
                        *out_phy_2m = true;
                    }
                    if (out_phy_coded_supported &&
                        (tx & (PHY_CODED_S2_SUPPORTED | PHY_CODED_S8_SUPPORTED) ||
                         rx & (PHY_CODED_S2_SUPPORTED | PHY_CODED_S8_SUPPORTED))) {
                        *out_phy_coded_supported = true;
                    }
                    if (out_phy_coded_s8 &&
                        (tx & PHY_CODED_S8_SUPPORTED || rx & PHY_CODED_S8_SUPPORTED)) {
                        *out_phy_coded_s8 = true;
                    }
                    if (out_phy_coded &&
                        (tx & (PHY_CODED_S2_SUPPORTED | PHY_CODED_S8_SUPPORTED) ||
                         rx & (PHY_CODED_S2_SUPPORTED | PHY_CODED_S8_SUPPORTED))) {
                        *out_phy_coded = true;
                    }
                    saw_any = true;
                }
                break;

            default:
                break;
        }

        pos += 1 + adv_len;
    }

    return saw_any;
}

esp_err_t ble_phy_start_scan(uint8_t phys)
{
    g_scan_phys = phys ? phys : 0x01;
    ESP_LOGI(TAG, "BLE scan PHY mask=0x%02X", g_scan_phys);
    return ESP_OK;
}

uint8_t ble_phy_get_scan_phys(void)
{
    return g_scan_phys;
}
