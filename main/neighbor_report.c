#include "neighbor_report.h"
#include <string.h>
#include "esp_log.h"

static nr_entry_t s_entries[NR_MAX_ENTRIES];
static size_t s_count = 0;
static bool s_init = false;
static const char *TAG = "neighbor_report";

esp_err_t neighbor_report_init(void)
{
    memset(s_entries, 0, sizeof(s_entries));
    s_count = 0;
    s_init = true;
    ESP_LOGI(TAG, "802.11k neighbor report parser initialized");
    return ESP_OK;
}

void neighbor_report_parse(const uint8_t *ie, size_t len)
{
    if (!s_init || !ie || len < 13) return;
    size_t offset = 0;
    while (offset + 13 <= len && s_count < NR_MAX_ENTRIES) {
        const uint8_t *entry = ie + offset;
        memcpy(s_entries[s_count].bssid, entry, 6);
        s_entries[s_count].channel = entry[6];
        s_entries[s_count].phy = entry[8];
        s_entries[s_count].valid = true;
        s_count++;
        offset += 13;
    }
}

size_t neighbor_report_list(nr_entry_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_count < max ? s_count : max;
    memcpy(out, s_entries, n * sizeof(nr_entry_t));
    return n;
}

void neighbor_report_clear(void)
{
    memset(s_entries, 0, sizeof(s_entries));
    s_count = 0;
}
