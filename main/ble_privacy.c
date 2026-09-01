#include "ble_privacy.h"
#include <string.h>
#include <stdbool.h>
#include "esp_log.h"

static const char *TAG = "ble_privacy";

/* Local IRK storage; all zeros = not set */
static uint8_t g_local_irk[16];

esp_err_t ble_privacy_init(void)
{
    memset(g_local_irk, 0, sizeof(g_local_irk));
    ESP_LOGI(TAG, "privacy subsystem initialized");
    return ESP_OK;
}

void ble_privacy_set_local_irk(const uint8_t irk[16])
{
    if (irk == NULL) return;
    memcpy(g_local_irk, irk, 16);
    ESP_LOGI(TAG, "local IRK set");
}

bool ble_privacy_is_rpa(uint8_t addr_type, const uint8_t *mac)
{
    if (mac == NULL) return false;
    if (addr_type != 1) return false; /* random static/identity are not RPA */
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
        return true;
    }

    *out_is_rpa = true;
    /* RPA hash is bytes 3-5 of the address */
    memcpy(out_hash, mac + 3, 3);
    return true;
}

bool ble_privacy_get_rpa_hash(const uint8_t *mac, uint8_t out_hash[3])
{
    if (mac == NULL || out_hash == NULL) return false;
    memcpy(out_hash, mac + 3, 3);
    return true;
}

uint16_t ble_privacy_count_resolvable(void)
{
    if (g_ble_lock == NULL) return 0;

    uint16_t count = 0;
    xSemaphoreTake(g_ble_lock, portMAX_DELAY);
    for (int i = 0; i < g_ble_count; i++) {
        if (ble_privacy_is_rpa(g_ble_list[i].addr_type, g_ble_list[i].mac)) {
            count++;
        }
    }
    xSemaphoreGive(g_ble_lock);
    return count;
}

int ble_privacy_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return 0;
    uint16_t rpa_count = ble_privacy_count_resolvable();
    return snprintf(buf, bufsz,
        "{\"rpa_count\":%d,\"total_ble\":%d}",
        rpa_count, g_ble_count);
}
