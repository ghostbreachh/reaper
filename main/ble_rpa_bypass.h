#ifndef BLE_RPA_BYPASS_H
#define BLE_RPA_BYPASS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BLE_RPA_MAX_IRKS 16

typedef struct {
    uint8_t irk[16];
    bool valid;
} ble_irk_t;

esp_err_t ble_rpa_bypass_init(void);
void ble_rpa_bypass_set_irk(const uint8_t *irk);
bool ble_rpa_bypass_resolve(const uint8_t *rpa, const uint8_t *irk);
size_t ble_rpa_bypass_count(void);
bool ble_rpa_bypass_check(const uint8_t *addr, uint8_t *out_identity);

#ifdef __cplusplus
}
#endif
#endif
