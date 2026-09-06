#include "ble_rpa_bypass.h"
#include "ble_privacy.h"
#include <string.h>
#include "esp_log.h"

static ble_irk_t s_irks[BLE_RPA_MAX_IRKS];
static size_t s_count = 0;
static bool s_init = false;
static const char *TAG = "rpa_bypass";

esp_err_t ble_rpa_bypass_init(void)
{
    memset(s_irks, 0, sizeof(s_irks));
    s_count = 0;
    s_init = true;
    ESP_LOGI(TAG, "RPA bypass initialized");
    return ESP_OK;
}

void ble_rpa_bypass_set_irk(const uint8_t *irk)
{
    if (!s_init || !irk || s_count >= BLE_RPA_MAX_IRKS) return;
    memcpy(s_irks[s_count].irk, irk, 16);
    s_irks[s_count].valid = true;
    s_count++;
}

bool ble_rpa_bypass_resolve(const uint8_t *rpa, const uint8_t *irk)
{
    if (!rpa || !irk) return false;
    /* Local hash check: RPA top two bits indicate type.
     * For real resolution, full AES-CMAC is required.
     * Here we match against stored IRK list and known RPA patterns. */
    if ((rpa[5] & 0xC0) != 0x40) return false; /* Not RPA */
    /* Placeholder for full hash check. */
    (void)irk;
    return false;
}

size_t ble_rpa_bypass_count(void)
{
    return s_count;
}

bool ble_rpa_bypass_check(const uint8_t *addr, uint8_t *out_identity)
{
    for (size_t i = 0; i < s_count; i++) {
        if (ble_rpa_bypass_resolve(addr, s_irks[i].irk)) {
            if (out_identity) memcpy(out_identity, s_irks[i].irk, 16);
            return true;
        }
    }
    return false;
}
