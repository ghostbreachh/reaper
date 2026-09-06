#include "ble_mitm.h"
#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"

static ble_mitm_target_t s_targets[BLE_MITM_MAX_TARGETS];
static size_t s_count = 0;
static bool s_init = false;
static const char *TAG = "ble_mitm";

esp_err_t ble_mitm_init(void)
{
    memset(s_targets, 0, sizeof(s_targets));
    s_count = 0;
    s_init = true;
    ESP_LOGI(TAG, "BLE MITM module initialized");
    return ESP_OK;
}

esp_err_t ble_mitm_add_target(const uint8_t *target_mac,
                               const uint8_t *spoof_mac)
{
    if (!s_init || !target_mac || !spoof_mac) return ESP_ERR_INVALID_ARG;
    if (s_count >= BLE_MITM_MAX_TARGETS) return ESP_ERR_NO_MEM;
    size_t idx = s_count++;
    memcpy(s_targets[idx].target_mac, target_mac, 6);
    memcpy(s_targets[idx].spoof_mac, spoof_mac, 6);
    s_targets[idx].state = BLE_MITM_STATE_LISTENING;
    s_targets[idx].last_seen_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);
    s_targets[idx].pkts_injected = 0;
    s_targets[idx].active = true;
    ESP_LOGI(TAG, "MITM target added "MACSTR" -> "MACSTR"",
             MAC2STR(target_mac), MAC2STR(spoof_mac));
    return ESP_OK;
}

size_t ble_mitm_targets(ble_mitm_target_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_count < max ? s_count : max;
    memcpy(out, s_targets, n * sizeof(ble_mitm_target_t));
    return n;
}

bool ble_mitm_is_spoofing(const uint8_t *mac)
{
    for (size_t i = 0; i < s_count; i++) {
        if (memcmp(s_targets[i].target_mac, mac, 6) == 0) {
            return s_targets[i].state == BLE_MITM_STATE_SPOOFING;
        }
    }
    return false;
}

void ble_mitm_tick(uint64_t ts_us)
{
    uint32_t now = (uint32_t)(ts_us / 1000ULL);
    for (size_t i = 0; i < s_count; i++) {
        if (!s_targets[i].active) continue;
        /* Advance state machine based on age. */
        if (now - s_targets[i].last_seen_ms > 1000 &&
            s_targets[i].state == BLE_MITM_STATE_LISTENING) {
            s_targets[i].state = BLE_MITM_STATE_SPOOFING;
            ESP_LOGI(TAG, "Target "MACSTR" switched to spoofing",
                     MAC2STR(s_targets[i].target_mac));
        }
    }
}
