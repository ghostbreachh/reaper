/*
 * ============================================================================
 *  jsonrpc.c  —  JSON-RPC 2.0 Engine (Transport Agnostic)
 * ============================================================================
 */

#include "jsonrpc.h"
#include "usb_cdc.h"
#include "cli_transport.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <cJSON.h>

static const char *TAG = "jsonrpc";

/* -------------------------------------------------------------------------
 *  TX Queue Architecture (Non-blocking, ISR-Safe)
 * ----------------------------------------------------------------------- */
typedef struct {
    char *data; /* malloc'd string, must be freed by TX task */
} jsonrpc_tx_msg_t;

static QueueHandle_t g_tx_queue = NULL;
static TaskHandle_t g_tx_task_handle = NULL;
static jsonrpc_dispatch_t *g_dispatch = NULL;

/* -------------------------------------------------------------------------
 *  TinyUSB Callbacks (Keep here or move to usb_cdc.c)
 * ----------------------------------------------------------------------- */
static bool g_dtr_prev = false;

void tud_cdc_line_state_cb(uint8_t itf, bool dtr, bool rts)
{
    (void)itf;
    if (g_dtr_prev && !dtr) {
        usb_cdc_break_signal();
    }
    g_dtr_prev = dtr;
    usb_cdc_set_dtr_rts(dtr, rts);
}

void tud_cdc_line_coding_cb(uint8_t itf, cdc_line_coding_t const *coding)
{
    (void)itf;
    if (coding == NULL) return;

    usb_cdc_line_coding_t lc = {
        .bit_rate   = coding->bit_rate,
        .data_bits  = coding->data_bits,
        .parity     = coding->parity,
        .stop_bits  = coding->stop_bits,
    };
    usb_cdc_set_line_coding(&lc);
}

/* -------------------------------------------------------------------------
 *  TX Task: Drains queue and writes to active transport
 * ----------------------------------------------------------------------- */
static void jsonrpc_tx_task(void *arg)
{
    jsonrpc_tx_msg_t msg;
    
    while (1) {
        if (xQueueReceive(g_tx_queue, &msg, portMAX_DELAY) == pdTRUE) {
            const cli_transport_t *t = cli_transport_get();
            if (t && t->connected()) {
                /* Write to transport. This may block if USB is backed up,
                 * but only this task blocks, not the Wi-Fi/BLE stacks. */
                t->write(msg.data, strlen(msg.data));
            }
            free(msg.data);
        }
    }
}

static esp_err_t queue_tx_message(const char *str)
{
    if (!g_tx_queue || !str) return ESP_ERR_INVALID_STATE;
    
    size_t len = strlen(str);
    char *copy = malloc(len + 2); /* +2 for \n and \0 */
    if (!copy) return ESP_ERR_NO_MEM;
    
    memcpy(copy, str, len);
    copy[len] = '\n';
    copy[len + 1] = '\0';
    
    jsonrpc_tx_msg_t msg = { .data = copy };
    
    /* Non-blocking send. If queue is full, drop the message (backpressure). */
    if (xQueueSend(g_tx_queue, &msg, 0) != pdTRUE) {
        free(copy);
        ESP_LOGW(TAG, "TX queue full, dropping message");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Response Builders
 * ----------------------------------------------------------------------- */
static esp_err_t jsonrpc_send_error(int32_t id, int32_t code, const char *message, const char *data_json)
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

    esp_err_t ret = queue_tx_message(out);
    cJSON_free(out);
    return ret;
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
            cJSON_AddStringToObject(root, "result", result_json); /* Fallback to raw string */
        }
    } else {
        cJSON_AddTrueToObject(root, "result");
    }

    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!out) return ESP_ERR_NO_MEM;

    esp_err_t ret = queue_tx_message(out);
    cJSON_free(out);
    return ret;
}

/* -------------------------------------------------------------------------
 *  Method Dispatch
 * ----------------------------------------------------------------------- */
static esp_err_t jsonrpc_dispatch_call(const char *method, const char *params_json, int32_t id)
{
    if (!g_dispatch || !g_dispatch->methods) {
        return jsonrpc_send_error(id, -32603, "Internal error", NULL);
    }

    for (uint16_t i = 0; i < g_dispatch->method_count; i++) {
        if (strcmp(g_dispatch->methods[i].name, method) == 0) {
            char resp[JSONRPC_MAX_LINE];
            memset(resp, 0, sizeof(resp));

            esp_err_t r = g_dispatch->methods[i].fn(method, params_json, resp, sizeof(resp) - 1, g_dispatch->methods[i].user_ctx);
            
            if (r == ESP_OK) {
                return jsonrpc_send_result(id, resp[0] ? resp : NULL);
            }

            char data_buf[128];
            snprintf(data_buf, sizeof(data_buf), "{\"module\":\"jsonrpc\",\"esp_err\":\"%s\"}", esp_err_to_name(r));
            return jsonrpc_send_error(id, -32603, "Internal error", data_buf);
        }
    }

    return jsonrpc_send_error(id, -32601, "Method not found", NULL);
}

/* -------------------------------------------------------------------------
 *  Frame Parser (Called by cli_transport)
 * ----------------------------------------------------------------------- */
void jsonrpc_handle_message(const char *frame)
{
    if (!frame || frame[0] == '\0') return;

    /* Skip leading whitespace */
    while (*frame == ' ' || *frame == '\t' || *frame == '\n' || *frame == '\r') frame++;

    cJSON *req = cJSON_Parse(frame);
    if (!req) {
        jsonrpc_send_error(0, -32700, "Parse error", NULL);
        return;
    }

    if (cJSON_IsArray(req)) {
        /* Batch processing */
        int n = cJSON_GetArraySize(req);
        for (int i = 0; i < n; i++) {
            cJSON *item = cJSON_GetArrayItem(req, i);
            if (!cJSON_IsObject(item)) continue;

            cJSON *jmethod = cJSON_GetObjectItem(item, "method");
            cJSON *jid = cJSON_GetObjectItem(item, "id");
            cJSON *jparams = cJSON_GetObjectItem(item, "params");

            if (!jmethod || !cJSON_IsString(jmethod)) continue;

            const char *method = cJSON_GetStringValue(jmethod);
            char *params_str = jparams ? cJSON_PrintUnformatted(jparams) : NULL;
            int32_t id = jid ? (int32_t)cJSON_GetNumberValue(jid) : 0;

            jsonrpc_dispatch_call(method, params_str, id);
            if (params_str) cJSON_free(params_str);
        }
    } else if (cJSON_IsObject(req)) {
        /* Single call */
        cJSON *jmethod = cJSON_GetObjectItem(req, "method");
        cJSON *jid = cJSON_GetObjectItem(req, "id");
        cJSON *jparams = cJSON_GetObjectItem(req, "params");

        if (!jmethod || !cJSON_IsString(jmethod)) {
            jsonrpc_send_error(0, -32600, "Invalid Request", NULL);
        } else {
            const char *method = cJSON_GetStringValue(jmethod);
            char *params_str = jparams ? cJSON_PrintUnformatted(jparams) : NULL;
            int32_t id = jid ? (int32_t)cJSON_GetNumberValue(jid) : 0;

            jsonrpc_dispatch_call(method, params_str, id);
            if (params_str) cJSON_free(params_str);
        }
    } else {
        jsonrpc_send_error(0, -32600, "Invalid Request", NULL);
    }

    cJSON_Delete(req);
}

/* -------------------------------------------------------------------------
 *  Public API
 * ----------------------------------------------------------------------- */
esp_err_t jsonrpc_init(jsonrpc_dispatch_t *dispatch, jsonrpc_method_entry_t *method_table, uint16_t method_count, void *user_ctx)
{
    if (!dispatch) return ESP_ERR_INVALID_ARG;

    g_dispatch = dispatch;
    memset(dispatch, 0, sizeof(*dispatch));
    dispatch->methods = method_table;
    dispatch->method_count = method_count;
    dispatch->method_cap = method_count;
    dispatch->user_ctx = user_ctx;
    dispatch->running = true;

    if (!g_tx_queue) {
        g_tx_queue = xQueueCreate(16, sizeof(jsonrpc_tx_msg_t));
        if (!g_tx_queue) return ESP_ERR_NO_MEM;
    }

    if (!g_tx_task_handle) {
        if (xTaskCreatePinnedToCore(jsonrpc_tx_task, "jsonrpc_tx", 4096, NULL, 4, &g_tx_task_handle, 1) != pdPASS) {
            return ESP_FAIL;
        }
    }

    ESP_LOGI(TAG, "initialised with %" PRIu16 " methods", method_count);
    return ESP_OK;
}

esp_err_t jsonrpc_deinit(void)
{
    if (g_dispatch) {
        g_dispatch->running = false;
    }
    
    if (g_tx_task_handle) {
        vTaskDelete(g_tx_task_handle);
        g_tx_task_handle = NULL;
    }
    
    if (g_tx_queue) {
        /* Drain queue before deleting */
        jsonrpc_tx_msg_t msg;
        while (xQueueReceive(g_tx_queue, &msg, 0) == pdTRUE) {
            free(msg.data);
        }
        vQueueDelete(g_tx_queue);
        g_tx_queue = NULL;
    }
    
    g_dispatch = NULL;
    return ESP_OK;
}

esp_err_t jsonrpc_event_post(jsonrpc_event_type_t type, const char *event_json)
{
    if (!event_json || !g_tx_queue) return ESP_ERR_INVALID_STATE;

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

    esp_err_t ret = queue_tx_message(out);
    cJSON_free(out);
    return ret;
}

bool jsonrpc_is_host_connected(void)
{
    const cli_transport_t *t = cli_transport_get();
    return t ? t->connected() : false;
}

port_transport_t jsonrpc_active_transport(void)
{
    /* Simple getter, assuming port_detect_get_active() exists */
    return port_detect_get_active(); 
}
