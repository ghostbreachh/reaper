#include "neighbor_report.h"

#include <string.h>
#include <stdatomic.h>

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "neighbor_report";

static nr_entry_t s_entries[NR_MAX_ENTRIES];
static size_t s_count = 0;
static atomic_bool s_init = ATOMIC_VAR_INIT(false);
static SemaphoreHandle_t s_lock = NULL;

esp_err_t neighbor_report_init(void)
{
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
    ESP_LOGI(TAG, "802.11k neighbor report parser initialized");
    return ESP_OK;
}

void neighbor_report_parse(const uint8_t *ie, size_t len)
{
    if (!atomic_load(&s_init) || s_lock == NULL || !ie || len < 13) return;

    /* Non-blocking: drop if contended to avoid stalling the sniffer */
    if (xSemaphoreTake(s_lock, 0) != pdTRUE) return;

    size_t offset = 0;
    while (offset + 13 <= len && s_count < NR_MAX_ENTRIES) {
        const uint8_t *entry = ie + offset;
        
        /* Check if BSSID already exists to avoid duplicates */
        bool exists = false;
        for (size_t i = 0; i < s_count; i++) {
            if (memcmp(s_entries[i].bssid, entry, 6) == 0) {
                /* Update existing entry with correct offsets */
                s_entries[i].channel = entry[11]; /* Operating Class is 10, Channel is 11 */
                s_entries[i].phy = entry[12];     /* PHY Type is 12 */
                exists = true;
                break;
            }
        }
        
        if (!exists) {
            memcpy(s_entries[s_count].bssid, entry, 6);
            s_entries[s_count].channel = entry[11]; /* Fixed offset */
            s_entries[s_count].phy = entry[12];     /* Fixed offset */
            s_entries[s_count].valid = true;
            s_count++;
        }
        
        offset += 13;
    }

    xSemaphoreGive(s_lock);
}

size_t neighbor_report_list(nr_entry_t *out, size_t max)
{
    if (!out || max == 0 || !atomic_load(&s_init) || s_lock == NULL) return 0;
    
    size_t n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        n = s_count < max ? s_count : max;
        memcpy(out, s_entries, n * sizeof(nr_entry_t));
        xSemaphoreGive(s_lock);
    }
    return n;
}

void neighbor_report_clear(void)
{
    if (!atomic_load(&s_init) || s_lock == NULL) return;
    
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        memset(s_entries, 0, sizeof(s_entries));
        s_count = 0;
        xSemaphoreGive(s_lock);
    }
}
