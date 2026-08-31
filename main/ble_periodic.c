#include "ble_periodic.h"
#include <string.h>
#include <stdbool.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_err.h"

static const char *TAG = "ble_periodic";

/* Internal periodic advertising state per device.
 * Sized to match MAX_DISCOVERED_BLE for 1:1 indexing. */
typedef struct {
    uint8_t mac[6];
    bool synced;
    uint16_t interval_1_25ms; /* periodic adv interval, 0=unknown */
    uint8_t sid;              /* advertising set identifier */
} pa_state_t;

static pa_state_t g_pa_state[MAX_DISCOVERED_BLE];
static uint16_t g_pa_count = 0;
static SemaphoreHandle_t g_pa_lock = NULL;

/* Default periodic advertising interval when not explicitly set. */
#define PA_INTERVAL_DEFAULT_1_25MS  80   /* 100 ms */

static void pa_lock_init(void)
{
    if (g_pa_lock == NULL) {
        g_pa_lock = xSemaphoreCreateMutex();
    }
}

static pa_state_t *pa_find_or_create(const uint8_t *mac)
{
    if (g_pa_lock == NULL) pa_lock_init();
    xSemaphoreTake(g_pa_lock, portMAX_DELAY);

    for (int i = 0; i < g_pa_count; i++) {
        if (memcmp(g_pa_state[i].mac, mac, 6) == 0) {
            xSemaphoreGive(g_pa_lock);
            return &g_pa_state[i];
        }
    }

    if (g_pa_count < MAX_DISCOVERED_BLE) {
        memcpy(g_pa_state[g_pa_count].mac, mac, 6);
        g_pa_state[g_pa_count].synced = false;
        g_pa_state[g_pa_count].interval_1_25ms = 0;
        g_pa_state[g_pa_count].sid = 0xFF;
        pa_state_t *out = &g_pa_state[g_pa_count];
        g_pa_count++;
        xSemaphoreGive(g_pa_lock);
        return out;
    }

    xSemaphoreGive(g_pa_lock);
    return NULL;
}

esp_err_t ble_periodic_init(void)
{
    pa_lock_init();
    ESP_LOGI(TAG, "periodic advertising subsystem initialized");
    return ESP_OK;
}

bool ble_periodic_is_synced(uint8_t adv_mode, const uint8_t *mac)
{
    if (mac == NULL) return false;

    pa_state_t *st = pa_find_or_create(mac);
    if (st == NULL) return false;

    /* Sync only applies to non-connectable extended advertising */
    if (adv_mode == 1) {
        return st->synced;
    }
    return false;
}

esp_err_t ble_periodic_transfer_sync(const uint8_t *mac, uint8_t adv_mode)
{
    if (mac == NULL) return ESP_ERR_INVALID_ARG;
    if (adv_mode != 1) {
        ESP_LOGW(TAG, "sync transfer only valid for non-connectable mode");
        return ESP_ERR_INVALID_STATE;
    }

    pa_state_t *st = pa_find_or_create(mac);
    if (st == NULL) return ESP_ERR_NO_MEM;

    /* In production, this would call ble_gap_periodic_adv_sync_transfer().
     * For now, mark the device as sync-capable and log the intent. */
    st->sid = 0;
    st->interval_1_25ms = PA_INTERVAL_DEFAULT_1_25MS;
    ESP_LOGI(TAG, "sync transfer requested for %02X:%02X:%02X:%02X:%02X:%02X",
             mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
    return ESP_OK;
}

bool ble_periodic_update(const uint8_t *mac, uint8_t adv_mode,
                         bool has_aux_ptr, uint16_t interval_1_25ms)
{
    if (mac == NULL) return false;

    pa_state_t *st = pa_find_or_create(mac);
    if (st == NULL) return false;

    bool changed = false;

    /* Auxiliary pointer on non-connectable mode implies periodic capability */
    if (adv_mode == 1 && has_aux_ptr && !st->synced) {
        st->synced = true;
        st->interval_1_25ms = interval_1_25ms ? interval_1_25ms : PA_INTERVAL_DEFAULT_1_25MS;
        changed = true;
    }

    return changed;
}
