#include "pmkid.h"
#include "common_types.h"
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"

static pmkid_entry_t s_entries[PMKID_MAX_ENTRIES];
static size_t s_count = 0;
static bool s_init = false;
static const char *TAG = "pmkid";

esp_err_t pmkid_init(void)
{
    memset(s_entries, 0, sizeof(s_entries));
    s_count = 0;
    s_init = true;
    ESP_LOGI(TAG, "PMKID capture initialized, max=%d", PMKID_MAX_ENTRIES);
    return ESP_OK;
}

void pmkid_add(const uint8_t *bssid, const uint8_t *pmkid, int8_t rssi)
{
    if (!s_init || !bssid || !pmkid) return;
    size_t idx = s_count;
    if (idx >= PMKID_MAX_ENTRIES) {
        /* Replace oldest */
        idx = 0;
        for (size_t i = 1; i < PMKID_MAX_ENTRIES; i++) {
            if (s_entries[i].ts_ms < s_entries[idx].ts_ms) idx = i;
        }
    }
    memcpy(s_entries[idx].bssid, bssid, 6);
    memcpy(s_entries[idx].pmkid, pmkid, 16);
    s_entries[idx].rssi = rssi;
    s_entries[idx].ts_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);
    s_entries[idx].valid = true;
    if (idx == s_count && s_count < PMKID_MAX_ENTRIES) s_count++;
    ESP_LOGI(TAG, "PMKID captured " MACSTR " rssi=%d", MAC2STR(bssid), rssi);
}

size_t pmkid_count(void)
{
    return s_count;
}

size_t pmkid_list(pmkid_entry_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_count < max ? s_count : max;
    memcpy(out, s_entries, n * sizeof(pmkid_entry_t));
    return n;
}

void pmkid_clear(void)
{
    memset(s_entries, 0, sizeof(s_entries));
    s_count = 0;
}

bool pmkid_has(const uint8_t *bssid, uint8_t *out_pmkid)
{
    for (size_t i = 0; i < s_count; i++) {
        if (memcmp(s_entries[i].bssid, bssid, 6) == 0) {
            if (out_pmkid) memcpy(out_pmkid, s_entries[i].pmkid, 16);
            return true;
        }
    }
    return false;
}
