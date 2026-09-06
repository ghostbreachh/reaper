#ifndef BLE_MITM_H
#define BLE_MITM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BLE_MITM_MAX_TARGETS 8

typedef enum {
    BLE_MITM_STATE_IDLE = 0,
    BLE_MITM_STATE_LISTENING,
    BLE_MITM_STATE_SPOOFING,
    BLE_MITM_STATE_INJECTING,
    BLE_MITM_STATE_ERROR
} ble_mitm_state_t;

typedef struct {
    uint8_t target_mac[6];
    uint8_t spoof_mac[6];
    ble_mitm_state_t state;
    uint32_t last_seen_ms;
    uint32_t pkts_injected;
    bool active;
} ble_mitm_target_t;

esp_err_t ble_mitm_init(void);
esp_err_t ble_mitm_add_target(const uint8_t *target_mac,
                               const uint8_t *spoof_mac);
size_t ble_mitm_targets(ble_mitm_target_t *out, size_t max);
bool ble_mitm_is_spoofing(const uint8_t *mac);
void ble_mitm_tick(uint64_t ts_us);

#ifdef __cplusplus
}
#endif
#endif
