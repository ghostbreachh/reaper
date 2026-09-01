#include "ble_iso.h"
#include <string.h>
#include <stdbool.h>
#include "esp_log.h"

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
static bool g_iso_init_done = false;

/* BLE AD type hints for ISO-capable advertising.
 * These are informational values rather than official AD types
 * for Broadcast ISO / BIG, because the exact codepoints depend on
 * the Bluetooth Core Spec version adopted by the controller. */
#define ADV_TYPE_BROADCAST_AUDIO       0x2A

esp_err_t ble_iso_init(void)
{
    if (g_iso_init_done) return ESP_OK;
    memset(g_iso_devices, 0, sizeof(g_iso_devices));
    g_iso_init_done = true;
    ESP_LOGI(TAG, "ISO/BIG prep subsystem initialized");
    return ESP_OK;
}

static iso_device_t *iso_find_or_create(const uint8_t *mac)
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
                    uint8_t bis_count = (payload_len >= 2) ? data[pos + 5] : 0;
                    if (bis_count > 4) bis_count = 4;
                    for (int i = 0; i < bis_count; i++) {
                        if (6 + i < len) {
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

bool ble_iso_is_known(const uint8_t *mac)
{
    if (mac == NULL) return false;
    for (int i = 0; i < MAX_ISO_DEVICES; i++) {
        if (g_iso_devices[i].active &&
            memcmp(g_iso_devices[i].mac, mac, 6) == 0) {
            return true;
        }
    }
    return false;
}

int ble_iso_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return 0;
    uint16_t known = 0;
    for (int i = 0; i < MAX_ISO_DEVICES; i++) {
        if (g_iso_devices[i].active) known++;
    }
    return snprintf(buf, bufsz,
        "{\"iso_devices\":%d,\"prepared\":%s}",
        known, g_iso_init_done ? "true" : "false");
}
