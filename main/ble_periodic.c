#include "ble_periodic.h"

#include <string.h>
#include <stdbool.h>

#include "esp_log.h"
#include "esp_err.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "ble_periodic";

/* Internal periodic advertising state per device. */
typedef struct {
    uint8_t mac[6];
    bool synced;
    uint16_t interval_1_25ms;
    uint8_t sid;
} pa_state_t;

static pa_state_t g_pa_state[MAX_DISCOVERED_BLE];
static uint16_t g_pa_count = 0;
static SemaphoreHandle_t g_pa_lock = NULL;

#define PA_INTERVAL_DEFAULT_1_25MS  80   /* 100 ms */

/* =========================================================================
 *  Internal helpers (must be called with g_pa_lock held)
 * ========================================================================= */

/* Read-only lookup. Does NOT create entries. */
static pa_state_t *pa_find_locked(const uint8_t *mac)
{
    for (int i = 0; i < g_pa_count; i++) {
        if (memcmp(g_pa_state[i].mac, mac, 6) == 0) {
            return &g_pa_state[i];
        }
    }
    return NULL;
}

/* Find or create. Creates a new entry if space is available. */
static pa_state_t *pa_find_or_create_locked(const uint8_t *mac)
{
    pa_state_t *found = pa_find_locked(mac);
    if (found != NULL) {
        return found;
    }

    if (g_pa_count < MAX_DISCOVERED_BLE) {
        pa_state_t *out = &g_pa_state[g_pa_count];
        memcpy(out->mac, mac, 6);
        out->synced = false;
        out->interval_1_25ms = 0;
        out->sid = 0xFF;
        g_pa_count++;
        return out;
    }

    return NULL; /* Table full */
}

/* =========================================================================
 *  Public API
 * ========================================================================= */

esp_err_t ble_periodic_init(void)
{
    if (g_pa_lock == NULL) {
        g_pa_lock = xSemaphoreCreateMutex();
        if (g_pa_lock == NULL) {
            ESP_LOGE(TAG, "Failed to create PA mutex");
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(g_pa_lock, portMAX_DELAY);
    memset(g_pa_state, 0, sizeof(g_pa_state));
    g_pa_count = 0;
    xSemaphoreGive(g_pa_lock);

    ESP_LOGI(TAG, "Periodic advertising subsystem initialized");
    return ESP_OK;
}

bool ble_periodic_is_synced(uint8_t adv_mode, const uint8_t *mac)
{
    if (mac == NULL || g_pa_lock == NULL) return false;

    /* Sync only applies to non-connectable extended advertising */
    if (adv_mode != 1) return false;

    xSemaphoreTake(g_pa_lock, portMAX_DELAY);

    /* Read-only lookup: does NOT create phantom entries */
    pa_state_t *st = pa_find_locked(mac);
    bool result = (st != NULL) ? st->synced : false;

    xSemaphoreGive(g_pa_lock);
    return result;
}

esp_err_t ble_periodic_transfer_sync(const uint8_t *mac, uint8_t adv_mode)
{
    if (mac == NULL) return ESP_ERR_INVALID_ARG;
    if (g_pa_lock == NULL) return ESP_ERR_INVALID_STATE;

    if (adv_mode != 1) {
        ESP_LOGW(TAG, "sync transfer only valid for non-connectable mode");
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_pa_lock, portMAX_DELAY);

    pa_state_t *st = pa_find_or_create_locked(mac);
    if (st == NULL) {
        xSemaphoreGive(g_pa_lock);
        ESP_LOGW(TAG, "PA state table full");
        return ESP_ERR_NO_MEM;
    }

    /* In production, this would call ble_gap_periodic_adv_sync_transfer(). */
    st->sid = 0;
    st->interval_1_25ms = PA_INTERVAL_DEFAULT_1_25MS;

    xSemaphoreGive(g_pa_lock);

    ESP_LOGI(TAG, "sync transfer requested for %02X:%02X:%02X:%02X:%02X:%02X",
             mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
    return ESP_OK;
}

bool ble_periodic_update(const uint8_t *mac, uint8_t adv_mode,
                         bool has_aux_ptr, uint16_t interval_1_25ms)
{
    if (mac == NULL || g_pa_lock == NULL) return false;

    xSemaphoreTake(g_pa_lock, portMAX_DELAY);

    pa_state_t *st = pa_find_or_create_locked(mac);
    if (st == NULL) {
        xSemaphoreGive(g_pa_lock);
        return false;
    }

    bool changed = false;

    /* Auxiliary pointer on non-connectable mode implies periodic capability */
    if (adv_mode == 1 && has_aux_ptr && !st->synced) {
        st->synced = true;
        st->interval_1_25ms = interval_1_25ms ? interval_1_25ms : PA_INTERVAL_DEFAULT_1_25MS;
        changed = true;
    }

    xSemaphoreGive(g_pa_lock);
    return changed;
}
