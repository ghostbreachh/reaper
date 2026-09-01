#ifndef BLE_GATT_CLIENT_H
#define BLE_GATT_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* GATT connection handle returned by nimble on successful connect. */
typedef uint16_t ble_gattc_conn_t;

/* GATT client states */
typedef enum {
    BLE_GATTC_STATE_IDLE = 0,
    BLE_GATTC_STATE_CONNECTING,
    BLE_GATTC_STATE_CONNECTED,
    BLE_GATTC_STATE_DISCOVERING,
    BLE_GATTC_STATE_READING,
    BLE_GATTC_STATE_ERROR
} ble_gattc_state_t;

/* GATT service summary */
typedef struct {
    uint16_t start_handle;
    uint16_t end_handle;
    uint8_t type;
    uint8_t uuid_len;
    uint8_t uuid[16];
} ble_gattc_svc_t;

/* GATT characteristic summary */
typedef struct {
    uint16_t decl_handle;
    uint16_t value_handle;
    uint8_t props;
    uint8_t uuid_len;
    uint8_t uuid[16];
} ble_gattc_char_t;

/* Callback types for async discovery results.
 * svc_fn called per discovered service with summary.
 * char_fn called per discovered characteristic. */
typedef void (*ble_gattc_disc_svc_fn)(ble_gattc_conn_t conn_handle,
                                      const ble_gattc_svc_t *svc, void *arg);
typedef void (*ble_gattc_disc_char_fn)(ble_gattc_conn_t conn_handle,
                                       const ble_gattc_char_t *chr, void *arg);

/* Initialize GATT client subsystem. Call once at startup. */
esp_err_t ble_gattc_init(void);

/* Initiate connection to a peripheral by MAC.
 * mac: 6-byte BLE address
 * timeout_ms: connection timeout in milliseconds
 * out_conn_handle: receives connection handle on success
 * Returns ESP_OK on connection established, or error code. */
esp_err_t ble_gattc_connect(const uint8_t *mac, uint32_t timeout_ms,
                            ble_gattc_conn_t *out_conn_handle);

/* Disconnect active GATT connection. */
esp_err_t ble_gattc_disconnect(ble_gattc_conn_t conn_handle);

/* Discover all services on an established connection.
 * svcs: output array
 * max: maximum entries to write
 * out_count: receives number of services found
 * Returns ESP_OK on success. */
esp_err_t ble_gattc_discover_services(ble_gattc_conn_t conn_handle,
                                      ble_gattc_svc_t *svcs, size_t max,
                                      size_t *out_count,
                                      ble_gattc_disc_svc_fn cb, void *cb_arg);

/* Discover characteristics within a service range.
 * conn_handle: active connection
 * start_handle: service start handle
 * end_handle: service end handle
 * chars: output array
 * max: maximum entries to write
 * out_count: receives number of characteristics found
 * Returns ESP_OK on success. */
esp_err_t ble_gattc_discover_chars(ble_gattc_conn_t conn_handle,
                                   uint16_t start_handle, uint16_t end_handle,
                                   ble_gattc_char_t *chars, size_t max,
                                   size_t *out_count,
                                   ble_gattc_disc_char_fn cb, void *cb_arg);

/* Read characteristic value.
 * conn_handle: active connection
 * char_handle: characteristic value handle
 * buf: destination buffer
 * max_len: buffer size
 * out_len: receives bytes read
 * Returns ESP_OK on success. */
esp_err_t ble_gattc_read_char(ble_gattc_conn_t conn_handle,
                              uint16_t char_handle,
                              uint8_t *buf, size_t max_len, size_t *out_len);

/* Query connection state. */
ble_gattc_state_t ble_gattc_get_state(ble_gattc_conn_t conn_handle);

/* Query remote MAC for a connection handle. Returns true if found. */
bool ble_gattc_get_remote_mac(ble_gattc_conn_t conn_handle, uint8_t *out_mac);

#ifdef __cplusplus
}
#endif
#endif /* BLE_GATT_CLIENT_H */
