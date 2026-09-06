#include "ble_findmy.h"
#include <string.h>
#include "esp_log.h"

static findmy_device_t s_devs[FINDMY_MAX_DEVICES];
static size_t s_count = 0;
static bool s_init = false;
static const char *TAG = "findmy";

esp_err_t findmy_init(void)
{
    memset(s_devs, 0, sizeof(s_devs));
    s_count = 0;
    s_init = true;
    ESP_LOGI(TAG, "Apple Find My detector initialized");
    return ESP_OK;
}

void findmy_parse_adv(const uint8_t *adv, size_t len,
                      const uint8_t *mac)
{
    if (!s_init || !adv || !mac || len < 30) return;
    /* Detect Apple company ID + Find My service UUID pattern. */
    bool apple = false;
    bool findmy_service = false;
    for (size_t i = 0; i + 2 <= len; i++) {
        if (adv[i] == 0xFF && i + 6 <= len) {
            uint16_t cid = (uint16_t)(adv[i + 1] | (adv[i + 2] << 8));
            if (cid == 0x004C) { apple = true; }
        }
        if (adv[i] == 0x03 && i + 4 <= len) {
            uint16_t uuid16 = (uint16_t)(adv[i + 1] | (adv[i + 2] << 8));
            if (uuid16 == 0xFD3C) { findmy_service = true; }
        }
    }
    if (!apple || !findmy_service) return;
    if (s_count >= FINDMY_MAX_DEVICES) return;
    memcpy(s_devs[s_count].mac, mac, 6);
    s_devs[s_count].status = 1;
    s_devs[s_count].battery = 0;
    s_devs[s_count].valid = true;
    s_count++;
}

size_t findmy_list(findmy_device_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_count < max ? s_count : max;
    memcpy(out, s_devs, n * sizeof(findmy_device_t));
    return n;
}

void findmy_clear(void)
{
    memset(s_devs, 0, sizeof(s_devs));
    s_count = 0;
}
