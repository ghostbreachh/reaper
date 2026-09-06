#include "ble_smarttag.h"
#include <string.h>
#include "esp_log.h"

static smarttag_device_t s_devs[SMARTTAG_MAX_DEVICES];
static size_t s_count = 0;
static bool s_init = false;
static const char *TAG = "smarttag";

esp_err_t smarttag_init(void)
{
    memset(s_devs, 0, sizeof(s_devs));
    s_count = 0;
    s_init = true;
    ESP_LOGI(TAG, "SmartTag/Tile detector initialized");
    return ESP_OK;
}

void smarttag_parse_adv(const uint8_t *adv, size_t len,
                        const uint8_t *mac)
{
    if (!s_init || !adv || !mac || len < 20) return;
    bool samsung = false;
    bool tile = false;
    for (size_t i = 0; i + 2 <= len; i++) {
        if (adv[i] == 0xFF && i + 6 <= len) {
            uint16_t cid = (uint16_t)(adv[i + 1] | (adv[i + 2] << 8));
            if (cid == 0x0075) { samsung = true; }
            if (cid == 0x009E) { tile = true; }
        }
    }
    if (!samsung && !tile) return;
    if (s_count >= SMARTTAG_MAX_DEVICES) return;
    memcpy(s_devs[s_count].mac, mac, 6);
    s_devs[s_count].type = samsung ? 1 : 2;
    s_devs[s_count].battery = 0;
    s_devs[s_count].valid = true;
    s_count++;
}

size_t smarttag_list(smarttag_device_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_count < max ? s_count : max;
    memcpy(out, s_devs, n * sizeof(smarttag_device_t));
    return n;
}

void smarttag_clear(void)
{
    memset(s_devs, 0, sizeof(s_devs));
    s_count = 0;
}
