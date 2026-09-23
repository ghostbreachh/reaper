#include "ft_roam.h"

#include <string.h>
#include <stdatomic.h>

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "ft_roam";

static ft_target_t s_targets[FT_MAX_TARGETS];
static size_t s_count = 0;
static atomic_bool s_init = ATOMIC_VAR_INIT(false);
static SemaphoreHandle_t s_lock = NULL;

esp_err_t ft_roam_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
        if (s_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    memset(s_targets, 0, sizeof(s_targets));
    s_count = 0;
    xSemaphoreGive(s_lock);

    atomic_store(&s_init, true);
    ESP_LOGI(TAG, "802.11r FT attack module initialized");
    return ESP_OK;
}

void ft_roam_record_target(const uint8_t *bssid, uint8_t channel,
                            uint8_t mobility_domain)
{
    if (!atomic_load(&s_init) || s_lock == NULL || !bssid) return;

    /* Non-blocking: drop if contended to avoid stalling the sniffer */
    if (xSemaphoreTake(s_lock, 0) != pdTRUE) return;

    /* Check for existing BSSID to avoid duplicates */
    for (size_t i = 0; i < s_count; i++) {
        if (memcmp(s_targets[i].bssid, bssid, 6) == 0) {
            s_targets[i].channel = channel;
            s_targets[i].mobility_domain = mobility_domain;
            xSemaphoreGive(s_lock);
            return;
        }
    }

    if (s_count >= FT_MAX_TARGETS) {
        xSemaphoreGive(s_lock);
        return;
    }

    memcpy(s_targets[s_count].bssid, bssid, 6);
    s_targets[s_count].channel = channel;
    s_targets[s_count].mobility_domain = mobility_domain;
    s_targets[s_count].valid = true;
    s_count++;

    xSemaphoreGive(s_lock);
}

size_t ft_roam_targets(ft_target_t *out, size_t max)
{
    if (!out || max == 0 || !atomic_load(&s_init) || s_lock == NULL) return 0;

    size_t n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        n = (s_count < max) ? s_count : max;
        memcpy(out, s_targets, n * sizeof(ft_target_t));
        xSemaphoreGive(s_lock);
    }
    return n;
}

bool ft_roam_inject_reassoc_request(const uint8_t *src_bssid,
                                    const uint8_t *dst_bssid)
{
    (void)src_bssid; 
    (void)dst_bssid;
    
    /* 
     * Stub: Actual injection requires raw 802.11 frame transmission 
     * via esp_wifi_80211_tx or similar bypass.
     */
    ESP_LOGD(TAG, "FT Reassoc injection not yet implemented");
    return false;
}
