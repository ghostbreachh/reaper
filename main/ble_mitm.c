#include "ble_mitm.h"
#include "common_types.h"

#include <string.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#ifndef MACSTR
#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#endif

static const char *TAG = "ble_mitm";

static ble_mitm_target_t s_targets[BLE_MITM_MAX_TARGETS];
static size_t s_count = 0;
static atomic_bool s_init = ATOMIC_VAR_INIT(false);
static SemaphoreHandle_t s_lock = NULL;

esp_err_t ble_mitm_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
        if (s_lock == NULL) return ESP_ERR_NO_MEM;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    memset(s_targets, 0, sizeof(s_targets));
    s_count = 0;
    xSemaphoreGive(s_lock);

    atomic_store(&s_init, true);
    ESP_LOGI(TAG, "BLE MITM module initialized");
    return ESP_OK;
}

esp_err_t ble_mitm_add_target(const uint8_t *target_mac,
                               const uint8_t *spoof_mac)
{
    if (!atomic_load(&s_init) || s_lock == NULL || !target_mac || !spoof_mac) {
        return ESP_ERR_INVALID_ARG;
    }

    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    if (s_count >= BLE_MITM_MAX_TARGETS) {
        xSemaphoreGive(s_lock);
        return ESP_ERR_NO_MEM;
    }

    size_t idx = s_count++;
    memcpy(s_targets[idx].target_mac, target_mac, 6);
    memcpy(s_targets[idx].spoof_mac, spoof_mac, 6);
    s_targets[idx].state = BLE_MITM_STATE_LISTENING;
    s_targets[idx].last_seen_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);
    s_targets[idx].pkts_injected = 0;
    s_targets[idx].active = true;

    xSemaphoreGive(s_lock);

    ESP_LOGI(TAG, "MITM target added " MACSTR " -> " MACSTR,
             MAC2STR(target_mac), MAC2STR(spoof_mac));
    return ESP_OK;
}

size_t ble_mitm_targets(ble_mitm_target_t *out, size_t max)
{
    if (!out || max == 0 || !atomic_load(&s_init) || s_lock == NULL) return 0;

    size_t n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        n = s_count < max ? s_count : max;
        memcpy(out, s_targets, n * sizeof(ble_mitm_target_t));
        xSemaphoreGive(s_lock);
    }
    return n;
}

bool ble_mitm_is_spoofing(const uint8_t *mac)
{
    if (!mac || !atomic_load(&s_init) || s_lock == NULL) return false;

    bool spoofing = false;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        for (size_t i = 0; i < s_count; i++) {
            if (memcmp(s_targets[i].target_mac, mac, 6) == 0) {
                spoofing = (s_targets[i].state == BLE_MITM_STATE_SPOOFING);
                break;
            }
        }
        xSemaphoreGive(s_lock);
    }
    return spoofing;
}

void ble_mitm_tick(uint64_t ts_us)
{
    if (!atomic_load(&s_init) || s_lock == NULL) return;

    uint32_t now = (uint32_t)(ts_us / 1000ULL);

    /* Non-blocking: drop if contended to avoid stalling BLE scanner */
    if (xSemaphoreTake(s_lock, 0) != pdTRUE) return;

    for (size_t i = 0; i < s_count; i++) {
        if (!s_targets[i].active) continue;

        /* 
         * Simple state machine: 
         * Transition to SPOOFING if we haven't "seen" the target in 1s.
         * Note: last_seen_ms is currently only set at creation. 
         * A real implementation would update last_seen_ms when advertisements 
         * from target_mac are observed by the scanner.
         */
        if (s_targets[i].state == BLE_MITM_STATE_LISTENING &&
            (now - s_targets[i].last_seen_ms) > 1000) {
            
            s_targets[i].state = BLE_MITM_STATE_SPOOFING;
            ESP_LOGI(TAG, "Target " MACSTR " switched to spoofing",
                     MAC2STR(s_targets[i].target_mac));
        }
    }

    xSemaphoreGive(s_lock);
}
