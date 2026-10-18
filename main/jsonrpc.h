#ifndef JSONRPC_H
#define JSONRPC_H

#include "common_types.h"
#include "port_detect.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define JSONRPC_MAX_LINE     1024
#define JSONRPC_MAX_DEPTH    8

typedef enum {
    JSONRPC_REQ_INVALID = 0,
    JSONRPC_REQ_CALL,
    JSONRPC_REQ_BATCH_CALL,
    JSONRPC_REQ_NOTIFY
} jsonrpc_request_type_t;

typedef esp_err_t (*jsonrpc_method_fn_t)(const char *method,
                                         const char *params_json,
                                         char *out_json,
                                         size_t out_cap,
                                         void *user_ctx);

typedef struct {
    const char *name;
    jsonrpc_method_fn_t fn;
    void *user_ctx;
} jsonrpc_method_entry_t;

#define JSONRPC_CODE_PARSE_ERROR      (-32700)
#define JSONRPC_CODE_INVALID_REQUEST  (-32600)
#define JSONRPC_CODE_METHOD_NOT_FOUND (-32601)
#define JSONRPC_CODE_INVALID_PARAMS   (-32602)
#define JSONRPC_CODE_INTERNAL_ERROR   (-32603)

typedef enum {
    JSONRPC_EVENT_UNKNOWN = 0,
    JSONRPC_EVENT_WIFI_AP,
    JSONRPC_EVENT_WIFI_CLIENT,
    JSONRPC_EVENT_BLE_DEV,
    JSONRPC_EVENT_HANDSHAKE,
    JSONRPC_EVENT_CRED,
    JSONRPC_EVENT_HEALTH,
    JSONRPC_EVENT_PCAP,
    JSONRPC_EVENT_DEAUTH,
    JSONRPC_EVENT_DIAG,
    JSONRPC_EVENT_OTA_PROGRESS,
    JSONRPC_EVENT_COUNT,
} jsonrpc_event_type_t;

typedef struct {
    jsonrpc_method_entry_t *methods;
    uint16_t method_count;
    uint16_t method_cap;
    void *user_ctx;
    bool running;
} jsonrpc_dispatch_t;

/* ---------------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------------- */

esp_err_t jsonrpc_init(jsonrpc_dispatch_t *dispatch,
                       jsonrpc_method_entry_t *method_table,
                       uint16_t method_count,
                       void *user_ctx);

esp_err_t jsonrpc_deinit(void);

/* Called by cli_transport when a JSON-RPC frame is received */
void jsonrpc_handle_message(const char *frame);

esp_err_t jsonrpc_event_post(jsonrpc_event_type_t type, const char *event_json);
esp_err_t jsonrpc_send_result(int32_t id, const char *result_json, char *out, size_t out_sz);
esp_err_t jsonrpc_send_error(int32_t id, int32_t code, const char *message, char *out, size_t out_sz);

bool jsonrpc_is_host_connected(void);
port_transport_t jsonrpc_active_transport(void);

#ifdef __cplusplus
}
#endif

#endif // JSONRPC_H
