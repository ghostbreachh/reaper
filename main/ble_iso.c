#include "ble_iso.h"

#include <string.h>
#include <stdbool.h>
#include <stdatomic.h>

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "ble_iso";

/* Known ISO-capable device tracking */
#define MAX_ISO_DEVICES 16

typedef struct {
    uint8_t mac[6];
    bool active;
    bool has_big;
    uint8_t iso_channels;
    uint8_t bis_handles[4];
    uint32_t iso_interval_us;
} iso_device_t;

static iso_device_t g_iso_devices[MAX_ISO_DEVICES];
static atomic_bool g_iso_init_done = ATOMIC_VAR_INIT(false);
static SemaphoreHandle_t g_iso_lock = NULL;

/* BLE AD type hints for ISO-capable advertising. */
#define ADV_TYPE_BROADCAST_AUDIO 0x2A

esp_err_t ble_iso_init(void)
{
    if (atomic_load(&g_iso_init_done)) return ESP_OK;

    if (g_iso_lock == NULL) {
        g_iso_lock = xSemaphoreCreateMutex();
        if (g_iso_lock == NULL) return ESP_ERR_NO_MEM;
    }

    xSemaphoreTake(g_iso_lock, portMAX_DELAY);
    memset(g_iso_devices, 0, sizeof(g_iso_devices));
    xSemaphoreGive(g_iso_lock);

    atomic_store(&g_iso_init_done, true);
    ESP_LOGI(TAG, "ISO/BIG prep subsystem initialized");
    return ESP_OK;
}

/* Internal helper: find or create device slot (must be called with lock held) */
static iso_device_t *iso_find_or_create_locked(const uint8_t *mac)
{
    for (int i = 0; i < MAX_ISO_DEVICES; i++) {
        if (g_iso_devices[i].active &&
            memcmp(g_iso_devices[i].mac, mac, 6) == 0) {
            return &g_iso_devices[i];
        }
    }
    for (int i = 0; i < MAX_ISO_DEVICES; i++) {
        if (!g_iso_devices[i].active) {
            memcpy(g_iso_devices[i].mac, mac, 6);
            g_iso_devices[i].active = true;
            return &g_iso_devices[i];
        }
    }
    return NULL;
}

bool ble_iso_parse(const uint8_t *data, uint8_t len,
                   bool *out_has_big, uint8_t *out_iso_channels,
                   uint8_t out_bis_handles[4], uint32_t *out_iso_interval)
{
    if (data == NULL || len == 0) return false;
    
    if (out_has_big) *out_has_big = false;
    if (out_iso_channels) *out_iso_channels = 0;
    if (out_iso_interval) *out_iso_interval = 0;
    if (out_bis_handles) memset(out_bis_handles, 0, 4);

    bool saw_iso = false;
    size_t pos = 0;

    while (pos + 2 <= len) {
        uint8_t adv_len = data[pos];
        if (adv_len == 0) break;
        if (pos + 1 + adv_len > len) break;

        uint8_t type = data[pos + 1];
        uint8_t payload_len = adv_len - 1;

        switch (type) {
            case ADV_TYPE_BROADCAST_AUDIO:
                saw_iso = true;
                if (out_has_big) *out_has_big = true;
                
                if (out_iso_channels && payload_len >= 1) {
                    *out_iso_channels = data[pos + 2] & 0x0F;
                }
                
                if (out_iso_interval && payload_len >= 3) {
                    uint16_t interval_raw = data[pos + 3] |
                                            (data[pos + 4] << 8);
                    /* ISO interval is in units of 1.25 ms */
                    *out_iso_interval = (uint32_t)interval_raw * 1250;
                }
                
                if (out_bis_handles && payload_len >= 5) {
                    uint8_t bis_count = data[pos + 5];
                    if (bis_count > 4) bis_count = 4;
                    
                    for (int i = 0; i < bis_count; i++) {
                        if (pos + 6 + i < len) {
                            out_bis_handles[i] = data[pos + 6 + i];
                        }
                    }
                }
                break;

            default:
                break;
        }

        pos += 1 + adv_len;
    }

    return saw_iso;
}

/* 
 * FIXED: Added public API to record devices.
 * This function must be called by the scanner after ble_iso_parse returns true.
 */
void ble_iso_record(const uint8_t *mac, bool has_big,
                    uint8_t iso_channels, uint32_t iso_interval_us)
{
    if (mac == NULL || !atomic_load(&g_iso_init_done) || g_iso_lock == NULL) return;

    if (xSemaphoreTake(g_iso_lock, 0) != pdTRUE) return; /* Non-blocking for hot path */

    iso_device_t *dev = iso_find_or_create_locked(mac);
    if (dev != NULL) {
        dev->has_big = has_big;
        dev->iso_channels = iso_channels;
        dev->iso_interval_us = iso_interval_us;
    }

    xSemaphoreGive(g_iso_lock);
}

bool ble_iso_is_known(const uint8_t *mac)
{
    if (mac == NULL || !atomic_load(&g_iso_init_done) || g_iso_lock == NULL) return false;

    bool known = false;
    if (xSemaphoreTake(g_iso_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        for (int i = 0; i < MAX_ISO_DEVICES; i++) {
            if (g_iso_devices[i].active &&
                memcmp(g_iso_devices[i].mac, mac, 6) == 0) {
                known = true;
                break;
            }
        }
        xSemaphoreGive(g_iso_lock);
    }
    return known;
}

int ble_iso_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return 0;
    if (!atomic_load(&g_iso_init_done) || g_iso_lock == NULL) return 0;

    uint16_t known = 0;
    
    if (xSemaphoreTake(g_iso_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        for (int i = 0; i < MAX_ISO_DEVICES; i++) {
            if (g_iso_devices[i].active) known++;
        }
        xSemaphoreGive(g_iso_lock);
    }

    return snprintf(buf, bufsz,
        "{\"iso_devices\":%d,\"prepared\":%s}",
        known, atomic_load(&g_iso_init_done) ? "true" : "false");
}
