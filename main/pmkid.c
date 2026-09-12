#include "pmkid.h"
#include "common_types.h"

#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_mac.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#ifndef MACSTR
#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#endif

static const char *TAG = "pmkid";

static pmkid_entry_t s_entries[PMKID_MAX_ENTRIES];
static size_t s_count = 0;
static atomic_bool s_init = ATOMIC_VAR_INIT(false);
static SemaphoreHandle_t s_lock = NULL;

esp_err_t pmkid_init(void)
{
    if (atomic_load(&s_init)) {
        return ESP_OK;
    }

    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
        if (s_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    memset(s_entries, 0, sizeof(s_entries));
    s_count = 0;
    xSemaphoreGive(s_lock);

    atomic_store(&s_init, true);
    ESP_LOGI(TAG, "PMKID capture initialized, max=%d", PMKID_MAX_ENTRIES);
    return ESP_OK;
}

void pmkid_add(const uint8_t *bssid, const uint8_t *pmkid, int8_t rssi)
{
    if (!atomic_load(&s_init) || s_lock == NULL || !bssid || !pmkid) return;

    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE) return;

    /* 1. Check if BSSID already exists to avoid duplicates */
    for (size_t i = 0; i < s_count; i++) {
        if (memcmp(s_entries[i].bssid, bssid, 6) == 0) {
            memcpy(s_entries[i].pmkid, pmkid, 16);
            s_entries[i].rssi = rssi;
            s_entries[i].ts_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);
            s_entries[i].valid = true;
            xSemaphoreGive(s_lock);
            ESP_LOGD(TAG, "PMKID updated for " MACSTR, MAC2STR(bssid));
            return;
        }
    }

    /* 2. Find an empty slot or replace the oldest */
    size_t idx = s_count;
    if (idx >= PMKID_MAX_ENTRIES) {
        idx = 0;
        for (size_t i = 1; i < PMKID_MAX_ENTRIES; i++) {
            if (s_entries[i].ts_ms < s_entries[idx].ts_ms) {
                idx = i;
            }
        }
    }

    memcpy(s_entries[idx].bssid, bssid, 6);
    memcpy(s_entries[idx].pmkid, pmkid, 16);
    s_entries[idx].rssi = rssi;
    s_entries[idx].ts_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);
    s_entries[idx].valid = true;
    
    if (idx == s_count && s_count < PMKID_MAX_ENTRIES) {
        s_count++;
    }

    xSemaphoreGive(s_lock);
    ESP_LOGI(TAG, "PMKID captured " MACSTR " rssi=%d", MAC2STR(bssid), rssi);
}

size_t pmkid_count(void)
{
    if (!atomic_load(&s_init) || s_lock == NULL) return 0;
    
    size_t count = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        count = s_count;
        xSemaphoreGive(s_lock);
    }
    return count;
}

size_t pmkid_list(pmkid_entry_t *out, size_t max)
{
    if (!out || max == 0 || !atomic_load(&s_init) || s_lock == NULL) return 0;
    
    size_t n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        n = (s_count < max) ? s_count : max;
        memcpy(out, s_entries, n * sizeof(pmkid_entry_t));
        xSemaphoreGive(s_lock);
    }
    return n;
}

void pmkid_clear(void)
{
    if (!atomic_load(&s_init) || s_lock == NULL) return;
    
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        memset(s_entries, 0, sizeof(s_entries));
        s_count = 0;
        xSemaphoreGive(s_lock);
    }
}

bool pmkid_has(const uint8_t *bssid, uint8_t *out_pmkid)
{
    if (!bssid || !atomic_load(&s_init) || s_lock == NULL) return false;
    
    bool found = false;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        for (size_t i = 0; i < s_count; i++) {
            if (memcmp(s_entries[i].bssid, bssid, 6) == 0) {
                if (out_pmkid) memcpy(out_pmkid, s_entries[i].pmkid, 16);
                found = true;
                break;
            }
        }
        xSemaphoreGive(s_lock);
    }
    return found;
}
