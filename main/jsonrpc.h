#ifndef JSONRPC_H
#define JSONRPC_H

#include "common_types.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum length of a single JSON-RPC frame.
#define JSONRPC_MAX_LINE     1024
// Maximum JSON object nesting depth accepted from the peer.
#define JSONRPC_MAX_DEPTH    8

// RPC request flavours observed on the wire.
typedef enum {
    JSONRPC_REQ_INVALID = 0,
    JSONRPC_REQ_CALL,            // {"jsonrpc":"2.0","id":N,"method":"...","params":{...}}
    JSONRPC_REQ_BATCH_CALL,      // [ {...}, {...} ]
    JSONRPC_REQ_NOTIFY           // {"jsonrpc":"2.0","method":"...","params":{...}}
} jsonrpc_request_type_t;

// Synchronous RPC method handler. Implementations must not block forever.
// - `method`    : method name string, never NULL
// - `params`    : raw params object JSON text, NULL when absent
// - `out_json`  : caller-owned buffer for response text
// - `out_cap`   : capacity of `out_json`
// - `user_ctx`  : opaque pointer passed through from registration table
//
// Return ESP_OK on success, with response text in `out_json`, or
// return a typed `marauder_err_t` / `esp_err_t` to generate an error response.
typedef esp_err_t (*jsonrpc_method_fn_t)(const char *method,
                                         const char *params_json,
                                         char *out_json,
                                         size_t out_cap,
                                         void *user_ctx);

// Method registration entry. `name` is the JSON-RPC method string, e.g. "wifi.start_sniff".
typedef struct {
    const char *name;
    jsonrpc_method_fn_t fn;
    void *user_ctx;
} jsonrpc_method_entry_t;

// Async event categories emitted to the companion app.
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
} jsonrpc_event_type_t;

// Dispatch/transport control block. Initialise with jsonrpc_init().
typedef struct {
    jsonrpc_method_entry_t *methods;
    uint16_t method_count;
    uint16_t method_cap;
    void *user_ctx;
    bool running;
} jsonrpc_dispatch_t;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Initialise TinyUSB CDC-ACM + JSON-RPC dispatch.
// Must be called after TinyUSB and the chosen CDC port are ready.
esp_err_t jsonrpc_init(jsonrpc_dispatch_t *dispatch,
                       jsonrpc_method_entry_t *method_table,
                       uint16_t method_count,
                       void *user_ctx);

// Stop the dispatcher and release the CDC line. Blocks until tasks exit.
esp_err_t jsonrpc_deinit(void);

// Push an async event to the phone app. Thread-safe from ISR context.
esp_err_t jsonrpc_event_post(jsonrpc_event_type_t type,
                             const char *event_json);

// Query whether a CDC host is currently connected.
bool jsonrpc_is_host_connected(void);

// Return the detected active USB transport for this session.
port_transport_t jsonrpc_active_transport(void);

#ifdef __cplusplus
}
#endif

#endif // JSONRPC_H
