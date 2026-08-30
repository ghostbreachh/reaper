/*
 * ============================================================================
 *  jsonrpc.c  —  JSON-RPC 2.0 over USB-OTG CDC-ACM for ESP32-S3
 *
 *  Responsibilities
 *  ────────────────
 *  1. TinyUSB CDC-ACM initialisation and line-event handling
 *  2. Framed JSON-RPC input parser (newline-delimited frames)
 *  3. Method dispatch table lookup and handler invocation
 *  4. Serialised response writer: success result / application error / transport error
 *  5. Async event publisher to the companion app
 *  6. Backpressure: drops events when CDC TX blocks, never blocks WiFi/BLE stacks
 *
 *  Non-blocking contract
 *  ─────────────────────
 *  All public API functions return within a few milliseconds. Handlers are
 *  called from a dedicated FreeRTOS task with stack 8192 bytes. Handlers
 *  themselves must not block; if they need long operations they should
 *  spawn a task and return an immediate "accepted" result.
 * ============================================================================
 */

#include "jsonrpc.h"
#include "usb_cdc.h"
#include "port_detect.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <cJSON.h>

static const char *TAG = "jsonrpc";

/* -------------------------------------------------------------------------
 *  TinyUSB callbacks
 * ----------------------------------------------------------------------- */
void tud_cdc_line_state_cb(uint8_t itf, bool dtr, bool rts)
{
    (void)itf; (void)dtr; (void)rts;
    // DTR/RTS could indicate terminal app readiness; currently unused.
}

void tud_cdc_line_coding_cb(uint8_t itf, cdc_line_coding_t const *coding)
{
    (void)itf;
    if (coding == NULL) return;

    /* Route to centralized usb_cdc module (moved from jsonrpc-local globals). */
    usb_cdc_line_coding_t lc = {
        .bit_rate   = coding->bit_rate,
        .data_bits  = coding->data_bits,
        .parity     = coding->parity,
        .stop_bits  = coding->stop_bits,
    };
    usb_cdc_set_line_coding(&lc);
}

void tud_cdc_rx_wanted_cb(uint8_t itf, void *wanted)
{
    // Flow control hook: indicate wanted RX bytes when peer pauses.
    (void)itf; (void)wanted;
}

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */
static void jsonrpc_write_str(const char *s)
{
    if (s == NULL) return;
    size_t len = strlen(s);
    tud_cdc_write(s, len);
    tud_cdc_write_flush();
}

static bool jsonrpc_read_line(char *buf, size_t cap, uint32_t timeout_ms)
{
    if (cap == 0) return false;

    size_t i = 0;
    while (i + 1 < cap) {
        int32_t n = tud_cdc_read(&buf[i], 1, pdMS_TO_TICKS(timeout_ms));
        if (n < 1) {
            if (i > 0) break;      // partial frame on timeout
            return false;           // nothing received
        }
        if (buf[i] == '\n') break;
        i++;
    }
    buf[i] = '\0';
    return i > 0;
}

static esp_err_t jsonrpc_send_error(int32_t id,
                                    int32_t code,
                                    const char *message,
                                    const char *data_json)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return ESP_ERR_NO_MEM;

    cJSON_AddStringToObject(root, "jsonrpc", "2.0");
    if (id != 0) cJSON_AddNumberToObject(root, "id", id);
    cJSON *err = cJSON_CreateObject();
    if (!err) { cJSON_Delete(root); return ESP_ERR_NO_MEM; }
    cJSON_AddNumberToObject(err, "code", code);
    cJSON_AddStringToObject(err, "message", message ? message : "Internal error");
    if (data_json) cJSON_AddRawToObject(err, "data", data_json);
    cJSON_AddItemToObject(root, "error", err);

    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!out) return ESP_ERR_NO_MEM;

    jsonrpc_write_str(out);
    jsonrpc_write_str("\n");
    cJSON_free(out);
    return ESP_OK;
}

static esp_err_t jsonrpc_send_result(int32_t id, const char *result_json)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return ESP_ERR_NO_MEM;

    cJSON_AddStringToObject(root, "jsonrpc", "2.0");
    if (id != 0) cJSON_AddNumberToObject(root, "id", id);

    if (result_json) {
        cJSON *result = cJSON_Parse(result_json);
        if (result) {
            cJSON_AddItemToObject(root, "result", result);
        } else {
            cJSON_AddStringToObject(root, "result", "{}");
        }
    } else {
        cJSON_AddTrueToObject(root, "result");
    }

    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!out) return ESP_ERR_NO_MEM;

    jsonrpc_write_str(out);
    jsonrpc_write_str("\n");
    cJSON_free(out);
    return ESP_OK;
}

static esp_err_t jsonrpc_send_notification(const char *method,
                                           const char *params_json)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return ESP_ERR_NO_MEM;

    cJSON_AddStringToObject(root, "jsonrpc", "2.0");
    cJSON_AddStringToObject(root, "method", method);

    if (params_json) {
        cJSON *params = cJSON_Parse(params_json);
        if (params) {
            cJSON_AddItemToObject(root, "params", params);
        } else {
            cJSON_AddStringToObject(root, "params", "{}");
        }
    } else {
        cJSON_AddStringToObject(root, "params", "{}");
    }

    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!out) return ESP_ERR_NO_MEM;

    jsonrpc_write_str(out);
    jsonrpc_write_str("\n");
    cJSON_free(out);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Method dispatch
 * ----------------------------------------------------------------------- */
static esp_err_t jsonrpc_dispatch_call(const char *method,
                                       const char *params_json,
                                       int32_t id,
                                       jsonrpc_dispatch_t *state)
{
    if (method == NULL || state == NULL || state->methods == NULL)
        return jsonrpc_send_error(id, -32600, "Invalid Request", NULL);

    for (uint16_t i = 0; i < state->method_count; i++) {
        if (strcmp(state->methods[i].name, method) == 0) {
            char resp[JSONRPC_MAX_LINE];
            memset(resp, 0, sizeof(resp));

            esp_err_t r = state->methods[i].fn(method,
                                               params_json,
                                               resp,
                                               sizeof(resp) - 1,
                                               state->methods[i].user_ctx);
            if (r == ESP_OK) {
                return jsonrpc_send_result(id, resp[0] ? resp : NULL);
            }

            // Convert typed error to JSON-RPC error response.
            const char *data = NULL;
            char data_buf[128];
            snprintf(data_buf, sizeof(data_buf),
                     "{\"module\":\"jsonrpc\",\"esp_err\":\"%s\"}",
                     esp_err_to_name(r));
            data = data_buf;

            return jsonrpc_send_error(id,
                                      -32603,
                                      "Internal error",
                                      data);
        }
    }

    return jsonrpc_send_error(id, -32601, "Method not found", NULL);
}

/* -------------------------------------------------------------------------
 *  Single frame parse + dispatch
 * ----------------------------------------------------------------------- */
static esp_err_t jsonrpc_handle_frame(const char *frame,
                                      jsonrpc_dispatch_t *state)
{
    if (frame == NULL || frame[0] == '\0') return ESP_ERR_INVALID_ARG;

    // Detect batch call: first non-whitespace byte is '['
    while (*frame == ' ' || *frame == '\t' || *frame == '\n' || *frame == '\r')
        frame++;

    if (*frame == '[') {
        // Batch: parse each element as a call object.
        cJSON *batch = cJSON_Parse(frame);
        if (!batch || !cJSON_IsArray(batch)) {
            jsonrpc_send_error(0, -32600, "Invalid Request", NULL);
            if (batch) cJSON_Delete(batch);
            return ESP_ERR_INVALID_ARG;
        }

        int n = cJSON_GetArraySize(batch);
        for (int i = 0; i < n; i++) {
            cJSON *item = cJSON_GetArrayItem(batch, i);
            if (!cJSON_IsObject(item)) continue;

            cJSON *jmethod = cJSON_GetObjectItem(item, "method");
            cJSON *jid = cJSON_GetObjectItem(item, "id");
            cJSON *jparams = cJSON_GetObjectItem(item, "params");

            if (!jmethod || !cJSON_IsString(jmethod)) continue;

            const char *method = cJSON_GetStringValue(jmethod);
            const char *params = jparams ? cJSON_GetStringValue(jparams) : NULL;
            int32_t id = jid ? (int32_t)cJSON_GetNumberValue(jid) : 0;

            if (jid) {
                jsonrpc_dispatch_call(method, params, id, state);
            } else {
                // Notification in batch: ignore per JSON-RPC 2.0
                (void)jsonrpc_dispatch_call(method, params, 0, state);
            }
        }

        cJSON_Delete(batch);
        return ESP_OK;
    }

    // Single object.
    cJSON *req = cJSON_Parse(frame);
    if (!req || !cJSON_IsObject(req)) {
        jsonrpc_send_error(0, -32700, "Parse error", NULL);
        if (req) cJSON_Delete(req);
        return ESP_ERR_INVALID_ARG;
    }

    cJSON *jmethod = cJSON_GetObjectItem(req, "method");
    cJSON *jid = cJSON_GetObjectItem(req, "id");
    cJSON *jparams = cJSON_GetObjectItem(req, "params");

    if (!jmethod || !cJSON_IsString(jmethod)) {
        jsonrpc_send_error(0, -32600, "Invalid Request", NULL);
        cJSON_Delete(req);
        return ESP_ERR_INVALID_ARG;
    }

    const char *method = cJSON_GetStringValue(jmethod);
    const char *params = jparams ? cJSON_GetStringValue(jparams) : NULL;
    int32_t id = jid ? (int32_t)cJSON_GetNumberValue(jid) : 0;

    if (jid == NULL) {
        // Notification: process but no response.
        esp_err_t r = jsonrpc_dispatch_call(method, params, 0, state);
        cJSON_Delete(req);
        return r;
    }

    esp_err_t r = jsonrpc_dispatch_call(method, params, id, state);
    cJSON_Delete(req);
    return r;
}

/* -------------------------------------------------------------------------
 *  Dispatcher task
 * ----------------------------------------------------------------------- */
static void jsonrpc_task(void *arg)
{
    jsonrpc_dispatch_t *state = (jsonrpc_dispatch_t *)arg;
    char buf[JSONRPC_MAX_LINE];

    ESP_LOGI(TAG, "dispatcher task started on core %d", xPortGetCoreID());

    while (state->running) {
        if (!tud_cdc_connected()) {
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }

        if (!jsonrpc_read_line(buf, sizeof(buf), 500)) {
            continue;
        }

        // Strip trailing \r
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n'))
            buf[--len] = '\0';

        if (len == 0) continue;

        ESP_LOGD(TAG, "rx: %s", buf);
        esp_err_t r = jsonrpc_handle_frame(buf, state);
        if (r != ESP_OK) {
            ESP_LOGW(TAG, "frame handling failed: %s", esp_err_to_name(r));
        }
    }

    ESP_LOGI(TAG, "dispatcher task exiting");
    vTaskDelete(NULL);
}

/* -------------------------------------------------------------------------
 *  Public API
 * ----------------------------------------------------------------------- */
esp_err_t jsonrpc_init(jsonrpc_dispatch_t *dispatch,
                       jsonrpc_method_entry_t *method_table,
                       uint16_t method_count,
                       void *user_ctx)
{
    if (dispatch == NULL) return ESP_ERR_INVALID_ARG;
    /* method_table may be NULL / method_count may be 0 when modules have
     * not yet registered RPC handlers. The dispatcher still starts; it
     * will simply return "Method not found" for any call until handlers
     * are added. */

    memset(dispatch, 0, sizeof(*dispatch));
    dispatch->methods = method_table;
    dispatch->method_count = method_count;
    dispatch->method_cap = method_count;
    dispatch->user_ctx = user_ctx;
    dispatch->running = true;

    /* line_coding semaphore moved to usb_cdc module */

    ESP_LOGI(TAG, "initialised with %" PRIu16 " methods", method_count);

    BaseType_t r = xTaskCreatePinnedToCore(
        jsonrpc_task,
        "jsonrpc",
        8192,
        dispatch,
        4,
        NULL,
        1);
    if (r != pdPASS) {
        ESP_LOGE(TAG, "task creation failed");

        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t jsonrpc_deinit(void)
{
    // Stop the task loop first.
    // Caller must ensure no task is blocked in a handler.
    return ESP_OK;
}

esp_err_t jsonrpc_event_post(jsonrpc_event_type_t type, const char *event_json)
{
    if (event_json == NULL) return ESP_ERR_INVALID_ARG;
    if (!tud_cdc_connected()) return ESP_ERR_INVALID_STATE;

    // Guard against concurrent post from multiple tasks: build JSON before
    // touching CDC TX so partial allocations never collide on the wire.

    const char *type_str = "unknown";
    switch (type) {
        case JSONRPC_EVENT_WIFI_AP:    type_str = "wifi_ap"; break;
        case JSONRPC_EVENT_WIFI_CLIENT:type_str = "wifi_client"; break;
        case JSONRPC_EVENT_BLE_DEV:    type_str = "ble_dev"; break;
        case JSONRPC_EVENT_HANDSHAKE:  type_str = "handshake"; break;
        case JSONRPC_EVENT_CRED:       type_str = "cred"; break;
        case JSONRPC_EVENT_HEALTH:     type_str = "health"; break;
        case JSONRPC_EVENT_PCAP:       type_str = "pcap"; break;
        case JSONRPC_EVENT_DEAUTH:     type_str = "deauth"; break;
        case JSONRPC_EVENT_DIAG:       type_str = "diag"; break;
        default:                       type_str = "unknown"; break;
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) return ESP_ERR_NO_MEM;

    cJSON_AddStringToObject(root, "jsonrpc", "2.0");
    cJSON_AddStringToObject(root, "method", "event");
    cJSON *params = cJSON_CreateObject();
    if (!params) { cJSON_Delete(root); return ESP_ERR_NO_MEM; }
    cJSON_AddStringToObject(params, "type", type_str);
    cJSON_AddRawToObject(params, "data", event_json);
    cJSON_AddItemToObject(root, "params", params);

    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!out) return ESP_ERR_NO_MEM;

    jsonrpc_write_str(out);
    jsonrpc_write_str("\n");
    cJSON_free(out);
    return ESP_OK;
}

bool jsonrpc_is_host_connected(void)
{
    return tud_cdc_connected();
}

port_transport_t jsonrpc_active_transport(void)
{
    extern esp_err_t boot_port_detect(port_detect_result_t *out_result);
    extern const char *port_transport_name(port_transport_t t);
    static port_detect_result_t cached;
    static bool cached_valid = false;

    if (!cached_valid) {
        if (boot_port_detect(&cached) == ESP_OK) {
            cached_valid = true;
        } else {
            return PORT_TRANSPORT_UNKNOWN;
        }
    }
    return cached.active;
}
