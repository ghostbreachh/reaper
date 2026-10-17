#include "ble_smarttag.h"

#include <string.h>
#include <stdatomic.h>

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "smarttag";

#define AD_TYPE_MFG_SPECIFIC 0xFF
#define CID_SAMSUNG          0x0075
#define CID_TILE             0x009E

static smarttag_device_t s_devs[SMARTTAG_MAX_DEVICES];
static size_t s_count = 0;
static atomic_bool s_init = ATOMIC_VAR_INIT(false);
static SemaphoreHandle_t s_lock = NULL;

esp_err_t smarttag_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
        if (s_lock == NULL) return ESP_ERR_NO_MEM;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    memset(s_devs, 0, sizeof(s_devs));
    s_count = 0;
    xSemaphoreGive(s_lock);

    atomic_store(&s_init, true);
    ESP_LOGI(TAG, "SmartTag/Tile detector initialized");
    return ESP_OK;
}

/* 
 * Properly iterate AD structures and detect known tracker company IDs.
 * AD format: [Length][Type][Data...]
 */
static bool detect_tracker(const uint8_t *adv, size_t len, uint8_t *out_type)
{
    size_t offset = 0;

    while (offset < len) {
        uint8_t ad_len = adv[offset];
        if (ad_len == 0) break; /* End of AD structures */

        /* Sanity: ensure we don't read past the buffer */
        if (offset + 1 + ad_len > len) break;

        uint8_t ad_type = adv[offset + 1];

        if (ad_type == AD_TYPE_MFG_SPECIFIC && ad_len >= 3) {
            /* Manufacturer ID is the first 2 bytes after the AD type */
            uint16_t cid = (uint16_t)(adv[offset + 2] | (adv[offset + 3] << 8));

            if (cid == CID_SAMSUNG) {
                *out_type = 1;
                return true;
            }
            if (cid == CID_TILE) {
                *out_type = 2;
                return true;
            }
        }

        /* Skip to next AD structure: length byte + length bytes of data */
        offset += 1 + ad_len;
    }

    return false;
}

void smarttag_parse_adv(const uint8_t *adv, size_t len,
                        const uint8_t *mac)
{
    if (!atomic_load(&s_init) || !adv || !mac || len == 0) return;
    if (s_lock == NULL) return;

    uint8_t tracker_type = 0;
    if (!detect_tracker(adv, len, &tracker_type)) return;

    /* Non-blocking lock: drop if contended to avoid stalling BLE scanner */
    if (xSemaphoreTake(s_lock, 0) != pdTRUE) return;

    /* Deduplication: update existing entry if MAC matches */
    for (size_t i = 0; i < s_count; i++) {
        if (memcmp(s_devs[i].mac, mac, 6) == 0) {
            s_devs[i].type = tracker_type;
            xSemaphoreGive(s_lock);
            return;
        }
    }

    /* Add new device if capacity allows */
    if (s_count >= SMARTTAG_MAX_DEVICES) {
        xSemaphoreGive(s_lock);
        return;
    }

    memcpy(s_devs[s_count].mac, mac, 6);
    s_devs[s_count].type = tracker_type;
    s_devs[s_count].battery = 0xFF; /* Unknown until parsed from mfg data */
    s_devs[s_count].valid = true;
    s_count++;

    xSemaphoreGive(s_lock);

    ESP_LOGI(TAG, "Tracker detected: type=%u mac=%02X:%02X:%02X:%02X:%02X:%02X",
             tracker_type, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

size_t smarttag_list(smarttag_device_t *out, size_t max)
{
    if (!out || max == 0 || !atomic_load(&s_init) || s_lock == NULL) return 0;

    size_t n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        n = (s_count < max) ? s_count : max;
        memcpy(out, s_devs, n * sizeof(smarttag_device_t));
        xSemaphoreGive(s_lock);
    }
    return n;
}

void smarttag_clear(void)
{
    if (!atomic_load(&s_init) || s_lock == NULL) return;

    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        memset(s_devs, 0, sizeof(s_devs));
        s_count = 0;
        xSemaphoreGive(s_lock);
    }
}
