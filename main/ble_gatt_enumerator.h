#ifndef BLE_GATT_ENUMERATOR_H
#define BLE_GATT_ENUMERATOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BLE_GATT_ENUM_MAX_SVCS 32
#define BLE_GATT_ENUM_MAX_CHARS 128

typedef enum {
    BLE_GATT_PERM_NONE     = 0,
    BLE_GATT_PERM_READ     = 1 << 0,
    BLE_GATT_PERM_WRITE    = 1 << 1,
    BLE_GATT_PERM_NOTIFY   = 1 << 2,
    BLE_GATT_PERM_INDICATE = 1 << 3
} ble_gatt_perm_t;

typedef struct {
    uint16_t start_handle;
    uint16_t end_handle;
    uint8_t uuid_len;
    uint8_t uuid[16];
} ble_gatt_enum_svc_t;

typedef struct {
    uint16_t decl_handle;
    uint16_t value_handle;
    uint8_t props;
    uint8_t uuid_len;
    uint8_t uuid[16];
    ble_gatt_perm_t perm;
} ble_gatt_enum_char_t;

esp_err_t ble_gatt_enumerator_init(void);
esp_err_t ble_gatt_enumerator_enumerate(const uint8_t *mac,
                                        uint32_t timeout_ms);
size_t ble_gatt_enumerator_services(ble_gatt_enum_svc_t *out, size_t max);
size_t ble_gatt_enumerator_chars(ble_gatt_enum_char_t *out, size_t max);
void ble_gatt_enumerator_clear(void);

#ifdef __cplusplus
}
#endif
#endif
