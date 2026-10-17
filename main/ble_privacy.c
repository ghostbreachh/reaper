#include "ble_privacy.h"
#include "ble_scanner.h" /* Required for public API access to scanner state */

#include <string.h>
#include <stdbool.h>
#include <stdatomic.h>

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "ble_privacy";

/* Local IRK storage; all zeros = not set */
static uint8_t g_local_irk[16];
static SemaphoreHandle_t g_irk_lock = NULL;

esp_err_t ble_privacy_init(void)
{
    if (g_irk_lock == NULL) {
        g_irk_lock = xSemaphoreCreateMutex();
        if (g_irk_lock == NULL) return ESP_ERR_NO_MEM;
    }

    xSemaphoreTake(g_irk_lock, portMAX_DELAY);
    memset(g_local_irk, 0, sizeof(g_local_irk));
    xSemaphoreGive(g_irk_lock);
    
    ESP_LOGI(TAG, "privacy subsystem initialized");
    return ESP_OK;
}

void ble_privacy_set_local_irk(const uint8_t irk[16])
{
    if (irk == NULL || g_irk_lock == NULL) return;
    
    xSemaphoreTake(g_irk_lock, portMAX_DELAY);
    memcpy(g_local_irk, irk, 16);
    xSemaphoreGive(g_irk_lock);
    
    ESP_LOGI(TAG, "local IRK set");
}

bool ble_privacy_is_rpa(uint8_t addr_type, const uint8_t *mac)
{
    if (mac == NULL) return false;
    if (addr_type != 1) return false; /* 1 = Random Address */
    if ((mac[5] & 0xC0) != 0x40) return false; /* top 2 bits must be 01 */
    return true;
}

bool ble_privacy_parse_rpa(uint8_t addr_type, const uint8_t *mac,
                           bool *out_is_rpa, uint8_t out_hash[3])
{
    if (mac == NULL || out_is_rpa == NULL || out_hash == NULL) {
        return false;
    }

    *out_is_rpa = false;
    memset(out_hash, 0, 3);

    if (!ble_privacy_is_rpa(addr_type, mac)) {
        return true; /* Parsed successfully, just not an RPA */
    }

    *out_is_rpa = true;
    
    /* 
     * FIXED: RPA hash is the LEAST significant 24 bits (bytes 0-2).
     * Bytes 3-5 are the prand.
     */
    memcpy(out_hash, mac, 3);
    return true;
}

bool ble_privacy_get_rpa_hash(const uint8_t *mac, uint8_t out_hash[3])
{
    if (mac == NULL || out_hash == NULL) return false;
    
    if (!ble_privacy_is_rpa(1, mac)) return false;
    
    /* FIXED: Extract bytes 0-2 (hash), not 3-5 (prand) */
    memcpy(out_hash, mac, 3);
    return true;
}

uint16_t ble_privacy_count_resolvable(void)
{
    /* Delegate to the scanner module's public API to avoid linkage errors */
    return ble_scanner_count_rpas();
}

int ble_privacy_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return 0;
    
    uint16_t rpa_count = ble_privacy_count_resolvable();
    uint16_t total_ble = ble_scanner_get_count();
    
    return snprintf(buf, bufsz,
        "{\"rpa_count\":%u,\"total_ble\":%u}",
        rpa_count, total_ble);
}
