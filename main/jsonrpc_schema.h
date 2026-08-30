#ifndef JSONRPC_SCHEMA_H
#define JSONRPC_SCHEMA_H

#include <stdint.h>
#include <stdbool.h>
#include "jsonrpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 *  JSON-RPC Schema v1 — 7 method groups + async events
 * -------------------------------------------------------------------------
 *
 *  T2T Step 3.2 — Research & Brainstorming
 *
 *  Branch A — Single flat dispatch table in jsonrpc.c
 *    Decision: REJECTED. Unmaintainable as method count grows; violates
 *    single-responsibility; mixes schema docs with transport logic.
 *
 *  Branch B — Grouped schema file + separate method table
 *    Decision: ACCEPTED. Clean separation; each group is documented and
 *    versioned; companion app can query schema for UI generation.
 *
 *  Branch C — Dynamic runtime method registration via linked list
 *    Decision: REJECTED. Overhead and fragmentation; static table is
 *    sufficient and safer for embedded.
 * ------------------------------------------------------------------------- */

/* Async event types for notifications pushed to companion app. */
typedef enum {
    JSONRPC_EVENT_WIFI_AP = 0,
    JSONRPC_EVENT_WIFI_CLIENT,
    JSONRPC_EVENT_BLE_DEV,
    JSONRPC_EVENT_HANDSHAKE,
    JSONRPC_EVENT_CRED,
    JSONRPC_EVENT_HEALTH,
    JSONRPC_EVENT_PCAP,
    JSONRPC_EVENT_DEAUTH,
    JSONRPC_EVENT_DIAG,
    JSONRPC_EVENT_OTA_PROGRESS,
} jsonrpc_event_type_t;

/* Method group identifiers. */
typedef enum {
    JSONRPC_GROUP_SYSTEM = 0,
    JSONRPC_GROUP_WIFI,
    JSONRPC_GROUP_DEAUTH,
    JSONRPC_GROUP_PCAP,
    JSONRPC_GROUP_BLE,
    JSONRPC_GROUP_STORAGE,
    JSONRPC_GROUP_OTA,
    JSONRPC_GROUP_COUNT,
} jsonrpc_group_t;

/* Build the static method table for all v1 groups.
 * Caller passes a pre-allocated array and its capacity; returns count.
 */
uint16_t jsonrpc_schema_v1_build(jsonrpc_method_entry_t *table, uint16_t cap);

/* Post an async event notification to the host. Thread-safe. */
esp_err_t jsonrpc_schema_event_post(jsonrpc_event_type_t type,
                                    const char *event_json);

/* Return schema version string. */
const char *jsonrpc_schema_version(void);

#ifdef __cplusplus
}
#endif

#endif /* JSONRPC_SCHEMA_H */
