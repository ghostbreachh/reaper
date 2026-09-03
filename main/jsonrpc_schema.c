/*
 * ============================================================================
 *  jsonrpc_schema.c  —  JSON-RPC Schema v1: 7 method groups + async events
 * ============================================================================
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
 * ============================================================================
 */

#include <string.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "cJSON.h"

#include "jsonrpc.h"
#include "jsonrpc_schema.h"
#include "usb_cdc.h"
#include "health_telemetry.h"
#include "watchdog.h"
#include "structured_log.h"
#include "storage_spiffs.h"
#include "nvs_persist.h"
#include "wifi_sniffer.h"
#include "cli_transport.h"
#include "gps.h"
#include "coex.h"
#include "ai_model.h"
#include "ai_classifier.h"
#include "pcap_ring.h"

static const char *TAG = "jsonrpc_schema";

#define SCHEMA_VERSION "v1.0.0"

/*============================================================================*/
static esp_err_t rpc_gps_set_fix(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    gps_fix_t fix;
    memset(&fix, 0, sizeof(fix));

    cJSON *lat = cJSON_GetObjectItem(root, "lat");
    cJSON *lon = cJSON_GetObjectItem(root, "lon");
    cJSON *alt = cJSON_GetObjectItem(root, "alt");
    cJSON *sats = cJSON_GetObjectItem(root, "sats");
    cJSON *fix_q = cJSON_GetObjectItem(root, "fix");
    cJSON *ts = cJSON_GetObjectItem(root, "timestamp");

    if (cJSON_IsNumber(lat)) fix.latitude = cJSON_GetNumberValue(lat);
    if (cJSON_IsNumber(lon)) fix.longitude = cJSON_GetNumberValue(lon);
    if (cJSON_IsNumber(alt)) fix.altitude = cJSON_GetNumberValue(alt);
    if (cJSON_IsNumber(sats)) fix.sat_count = (uint8_t)cJSON_GetNumberValue(sats);
    if (cJSON_IsNumber(fix_q)) fix.fix_quality = (uint8_t)cJSON_GetNumberValue(fix_q);
    if (cJSON_IsNumber(ts)) fix.timestamp = (uint32_t)cJSON_GetNumberValue(ts);

    fix.valid = (fix.latitude != 0.0 || fix.longitude != 0.0) &&
                fix.fix_quality >= 1 && fix.sat_count >= 3;

    esp_err_t rc = gps_set_fix(&fix);
    cJSON_Delete(root);

    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "gps_set_fix failed", out, out_sz);
    }

    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

static esp_err_t rpc_gps_get_fix(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    gps_fix_t fix;
    bool valid = gps_get_fix(&fix);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "valid", valid);
    cJSON_AddNumberToObject(root, "lat", fix.latitude);
    cJSON_AddNumberToObject(root, "lon", fix.longitude);
    cJSON_AddNumberToObject(root, "alt", fix.altitude);
    cJSON_AddNumberToObject(root, "sats", fix.sat_count);
    cJSON_AddNumberToObject(root, "fix", fix.fix_quality);
    cJSON_AddNumberToObject(root, "timestamp", fix.timestamp);

    const char *json = cJSON_PrintUnformatted(root);
    esp_err_t rc = jsonrpc_send_result(-1, json, out, out_sz);
    cJSON_free((void *)json);
    cJSON_Delete(root);
    return rc;
}

static esp_err_t rpc_gps_status(const char *method, const char *params_json,
                                char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    cJSON *root = cJSON_CreateObject();

    bool valid = gps_is_valid();
    cJSON_AddBoolToObject(root, "valid", valid);
    cJSON_AddStringToObject(root, "source", valid ? "phone" : "none");
    cJSON_AddNumberToObject(root, "timestamp", gps_get_timestamp_us() / 1000000ULL);

    gps_fix_t fix;
    if (gps_get_fix(&fix)) {
        cJSON_AddNumberToObject(root, "lat", fix.latitude);
        cJSON_AddNumberToObject(root, "lon", fix.longitude);
    }

    const char *json = cJSON_PrintUnformatted(root);
    esp_err_t rc = jsonrpc_send_result(-1, json, out, out_sz);
    cJSON_free((void *)json);
    cJSON_Delete(root);
    return rc;
}

/*============================================================================*/
static esp_err_t rpc_coex_set_pref(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *pref = cJSON_GetObjectItem(root, "pref");
    if (pref == NULL) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing pref", out, out_sz);
    }

    const char *pref_str = cJSON_GetStringValue(pref);
    coex_pref_t p = COEX_PREF_BALANCE;
    if (pref_str && strcmp(pref_str, "wifi") == 0) p = COEX_PREF_WIFI;
    else if (pref_str && strcmp(pref_str, "ble") == 0) p = COEX_PREF_BLE;
    else if (pref_str && strcmp(pref_str, "balance") == 0) p = COEX_PREF_BALANCE;
    else {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "pref must be wifi|ble|balance", out, out_sz);
    }

    esp_err_t rc = coex_set_preference(p);
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "coex_set_preference failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

static esp_err_t rpc_coex_get_status(const char *method, const char *params_json,
                                    char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = coex_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "coex status failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

static esp_err_t rpc_coex_json(const char *method, const char *params_json,
                               char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = coex_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "coex json failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ai_load(const char *method, const char *params_json,
                             char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (name == NULL || !cJSON_IsString(name)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing name", out, out_sz);
    }

    esp_err_t rc = ai_model_zoo_load(cJSON_GetStringValue(name));
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "ai_model_zoo_load failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"loaded\"", out, out_sz);
}

static esp_err_t rpc_ai_unload(const char *method, const char *params_json,
                               char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (name == NULL || !cJSON_IsString(name)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing name", out, out_sz);
    }

    esp_err_t rc = ai_model_zoo_unload(cJSON_GetStringValue(name));
    cJSON_Delete(root);
    if (rc != ESP_OK && rc != ESP_ERR_NOT_FOUND) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "ai_model_zoo_unload failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"unloaded\"", out, out_sz);
}

static esp_err_t rpc_ai_infer(const char *method, const char *params_json,
                              char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    cJSON *input = cJSON_GetObjectItem(root, "input");
    if (name == NULL || !cJSON_IsString(name) ||
        input == NULL || !cJSON_IsString(input)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing name or input", out, out_sz);
    }

    const char *input_str = cJSON_GetStringValue(input);
    size_t input_len = strlen(input_str);
    uint8_t output[256];
    size_t out_len = 0;

    esp_err_t rc = ai_model_zoo_infer(cJSON_GetStringValue(name),
                                      input_str, input_len,
                                      output, sizeof(output), &out_len);
    cJSON_Delete(root);
    if (rc == ESP_ERR_NOT_SUPPORTED) {
        cJSON *r = cJSON_CreateObject();
        cJSON_AddStringToObject(r, "status", "stub");
        cJSON_AddStringToObject(r, "note", "link ESP-DL to enable inference");
        const char *json = cJSON_PrintUnformatted(r);
        esp_err_t r2 = jsonrpc_send_result(-1, json, out, out_sz);
        cJSON_free((void *)json);
        cJSON_Delete(r);
        return r2;
    }
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "inference failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

static esp_err_t rpc_ai_list(const char *method, const char *params_json,
                             char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[512];
    esp_err_t rc = ai_model_zoo_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "ai list failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ai_classify_test(const char *method, const char *params_json,
                                      char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *frame_hex = cJSON_GetObjectItem(root, "frame");
    if (frame_hex == NULL || !cJSON_IsString(frame_hex)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing frame hex", out, out_sz);
    }

    const char *hex = cJSON_GetStringValue(frame_hex);
    size_t hex_len = strlen(hex);
    uint8_t frame[AI_CLASSIFIER_INPUT_MAX];
    size_t frame_len = 0;
    for (size_t i = 0; i < hex_len && frame_len < sizeof(frame); i += 2) {
        unsigned int byte = 0;
        if (sscanf(hex + i, "%02x", &byte) == 1) {
            frame[frame_len++] = (uint8_t)byte;
        }
    }

    ai_classify_result_t res;
    esp_err_t rc = ai_classifier_predict(frame, frame_len, &res);
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "classify failed", out, out_sz);
    }

    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "class", ai_classifier_class_name(res.cls));
    cJSON_AddNumberToObject(r, "confidence", res.confidence);
    cJSON_AddNumberToObject(r, "inference_us", res.inference_us);
    cJSON_AddBoolToObject(r, "model_loaded", res.model_loaded);

    const char *json = cJSON_PrintUnformatted(r);
    esp_err_t r2 = jsonrpc_send_result(-1, json, out, out_sz);
    cJSON_free((void *)json);
    cJSON_Delete(r);
    return r2;
}

static esp_err_t rpc_ai_classify_stats(const char *method, const char *params_json,
                                       char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = ai_classifier_json(buf, sizeof(buf));
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "classify stats failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

static esp_err_t rpc_ai_classify_set_model(const char *method, const char *params_json,
                                           char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *root = cJSON_Parse(params_json);
    if (root == NULL) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "invalid JSON", out, out_sz);
    }

    cJSON *name = cJSON_GetObjectItem(root, "name");
    if (name == NULL || !cJSON_IsString(name)) {
        cJSON_Delete(root);
        return jsonrpc_send_error(-1, JSONRPC_CODE_INVALID_PARAMS,
                                  "missing name", out, out_sz);
    }

    esp_err_t rc = ai_classifier_set_model(cJSON_GetStringValue(name));
    cJSON_Delete(root);
    if (rc != ESP_OK) {
        return jsonrpc_send_error(-1, JSONRPC_CODE_INTERNAL_ERROR,
                                  "set_model failed", out, out_sz);
    }
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_system_ping(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "\"pong\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_system_info(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "schema_version", SCHEMA_VERSION);
    cJSON_AddStringToObject(root, "firmware", "REAPER");
    cJSON_AddStringToObject(root, "chip", "ESP32-S3");
    const char *json = cJSON_PrintUnformatted(root);
    esp_err_t rc = jsonrpc_send_result(-1, json, out, out_sz);
    cJSON_free((void *)json);
    cJSON_Delete(root);
    return rc;
}

/*============================================================================*/
static esp_err_t rpc_system_caps(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char caps[256];
    esp_err_t rc = usb_cdc_caps_to_json(caps, sizeof(caps));
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, caps, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_system_health(const char *method, const char *params_json,
                                   char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    health_metrics_t m;
    esp_err_t rc = health_telemetry_get(&m);
    if (rc != ESP_OK) return rc;
    char json[128];
    snprintf(json, sizeof(json),
        "{\"uptime_s\":%u,\"free_heap\":%u,\"free_psram\":%u,"
        "\"cpu_temp_c\":%.2f,\"min_free_heap\":%u}",
        m.uptime_s, m.free_heap, m.free_psram,
        (float)m.cpu_temp_c / 100.0f, m.min_free_heap);
    return jsonrpc_send_result(-1, json, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_system_crash(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[512];
    esp_err_t rc = watchdog_read_crash(buf, sizeof(buf));
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_wifi_scan(const char *method, const char *params_json,
                               char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "[]", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_wifi_start(const char *method, const char *params_json,
                                char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    wifi_sniffer_start();
    return jsonrpc_send_result(-1, "\"started\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_wifi_stop(const char *method, const char *params_json,
                               char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    wifi_sniffer_stop();
    return jsonrpc_send_result(-1, "\"stopped\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_wifi_channel(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *p = cJSON_Parse(params_json);
    if (!p) return jsonrpc_send_error(-1, -32600, "Invalid params", out, out_sz);
    cJSON *ch = cJSON_GetObjectItem(p, "channel");
    if (!cJSON_IsNumber(ch)) {
        cJSON_Delete(p);
        return jsonrpc_send_error(-1, -32600, "channel required", out, out_sz);
    }
    cJSON_Delete(p);
    return jsonrpc_send_result(-1, "\"ok\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_deauth_start(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "\"started\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_deauth_stop(const char *method, const char *params_json,
                                 char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "\"stopped\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_deauth_status(const char *method, const char *params_json,
                                   char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "{\"active\":false,\"sent\":0}", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_pcap_start(const char *method, const char *params_json,
                                char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = pcap_ring_start(0);
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, "\"started\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_pcap_stop(const char *method, const char *params_json,
                               char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    pcap_ring_stop();
    return jsonrpc_send_result(-1, "\"stopped\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_pcap_save(const char *method, const char *params_json,
                               char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    const char *path = "/spiffs/capture.pcap";
    if (params_json) {
        cJSON *p = cJSON_Parse(params_json);
        if (p) {
            cJSON *jpath = cJSON_GetObjectItem(p, "path");
            if (cJSON_IsString(jpath)) path = cJSON_GetStringValue(jpath);
            cJSON_Delete(p);
        }
    }
    esp_err_t rc = pcap_ring_save(path);
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, "{\"saved\":true}", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ble_scan(const char *method, const char *params_json,
                              char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "[]", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ble_stop(const char *method, const char *params_json,
                              char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "\"stopped\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ble_list(const char *method, const char *params_json,
                              char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    return jsonrpc_send_result(-1, "[]", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_storage_wordlist_list(const char *method, const char *params_json,
                                           char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    char buf[256];
    esp_err_t rc = storage_spiffs_list_wordlists_json(buf, sizeof(buf));
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, buf, out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_storage_wordlist_load(const char *method, const char *params_json,
                                           char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *p = cJSON_Parse(params_json);
    if (!p) return jsonrpc_send_error(-1, -32600, "Invalid params", out, out_sz);
    cJSON *jname = cJSON_GetObjectItem(p, "name");
    if (!cJSON_IsString(jname)) {
        cJSON_Delete(p);
        return jsonrpc_send_error(-1, -32600, "name required", out, out_sz);
    }
    const char *name = cJSON_GetStringValue(jname);
    esp_err_t rc = storage_spiffs_load_wordlist_meta(name);
    cJSON_Delete(p);
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, "{\"loaded\":true}", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_storage_nvs_reset(const char *method, const char *params_json,
                                       char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    esp_err_t rc = nvs_erase_all();
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, "\"reset\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ota_start(const char *method, const char *params_json,
                               char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)user_ctx;
    cJSON *p = cJSON_Parse(params_json);
    if (!p) return jsonrpc_send_error(-1, -32600, "Invalid params", out, out_sz);
    cJSON *jurl = cJSON_GetObjectItem(p, "url");
    if (!cJSON_IsString(jurl)) {
        cJSON_Delete(p);
        return jsonrpc_send_error(-1, -32600, "url required", out, out_sz);
    }
    const char *url = cJSON_GetStringValue(jurl);
    cJSON_Delete(p);
    esp_err_t rc = ota_http_start(url);
    if (rc != ESP_OK) return rc;
    return jsonrpc_send_result(-1, "\"started\"", out, out_sz);
}

/*============================================================================*/
static esp_err_t rpc_ota_progress(const char *method, const char *params_json,
                                  char *out, size_t out_sz, void *user_ctx)
{
    (void)method; (void)params_json; (void)user_ctx;
    int progress = ota_http_progress();
    char json[64];
    snprintf(json, sizeof(json), "{\"progress\":%d}", progress);
    return jsonrpc_send_result(-1, json, out, out_sz);
}

/*============================================================================*/
static uint16_t build_system_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 18) return 0;
    table[0].name = "system.ping";      table[0].fn = rpc_system_ping;      table[0].user_ctx = NULL;
    table[1].name = "system.info";      table[1].fn = rpc_system_info;      table[1].user_ctx = NULL;
    table[2].name = "system.caps";      table[2].fn = rpc_system_caps;      table[2].user_ctx = NULL;
    table[3].name = "system.health";    table[3].fn = rpc_system_health;    table[3].user_ctx = NULL;
    table[4].name = "system.crash";     table[4].fn = rpc_system_crash;     table[4].user_ctx = NULL;
    table[5].name = "gps.set_fix";      table[5].fn = rpc_gps_set_fix;      table[5].user_ctx = NULL;
    table[6].name = "gps.get_fix";      table[6].fn = rpc_gps_get_fix;      table[6].user_ctx = NULL;
    table[7].name = "gps.status";       table[7].fn = rpc_gps_status;       table[7].user_ctx = NULL;
    table[8].name = "coex.set_pref";    table[8].fn = rpc_coex_set_pref;    table[8].user_ctx = NULL;
    table[9].name = "coex.get_status";  table[9].fn = rpc_coex_get_status;  table[9].user_ctx = NULL;
    table[10].name = "coex.json";       table[10].fn = rpc_coex_json;       table[10].user_ctx = NULL;
    table[11].name = "ai.model.load";   table[11].fn = rpc_ai_load;         table[11].user_ctx = NULL;
    table[12].name = "ai.model.unload"; table[12].fn = rpc_ai_unload;       table[12].user_ctx = NULL;
    table[13].name = "ai.model.infer";  table[13].fn = rpc_ai_infer;        table[13].user_ctx = NULL;
    table[14].name = "ai.model.list";   table[14].fn = rpc_ai_list;         table[14].user_ctx = NULL;
    table[15].name = "ai.classify.test";table[15].fn = rpc_ai_classify_test;table[15].user_ctx = NULL;
    table[16].name = "ai.classify.stats";table[16].fn = rpc_ai_classify_stats;table[16].user_ctx = NULL;
    table[17].name = "ai.classify.set_model";table[17].fn = rpc_ai_classify_set_model;table[17].user_ctx = NULL;
    return 18;
}

static uint16_t build_wifi_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 4) return 0;
    table[0].name = "wifi.scan";      table[0].fn = rpc_wifi_scan;      table[0].user_ctx = NULL;
    table[1].name = "wifi.start";     table[1].fn = rpc_wifi_start;     table[1].user_ctx = NULL;
    table[2].name = "wifi.stop";      table[2].fn = rpc_wifi_stop;      table[2].user_ctx = NULL;
    table[3].name = "wifi.channel";   table[3].fn = rpc_wifi_channel;   table[3].user_ctx = NULL;
    return 4;
}

static uint16_t build_deauth_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 3) return 0;
    table[0].name = "deauth.start";   table[0].fn = rpc_deauth_start;   table[0].user_ctx = NULL;
    table[1].name = "deauth.stop";    table[1].fn = rpc_deauth_stop;    table[1].user_ctx = NULL;
    table[2].name = "deauth.status";  table[2].fn = rpc_deauth_status;  table[2].user_ctx = NULL;
    return 3;
}

static uint16_t build_pcap_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 3) return 0;
    table[0].name = "pcap.start";     table[0].fn = rpc_pcap_start;     table[0].user_ctx = NULL;
    table[1].name = "pcap.stop";      table[1].fn = rpc_pcap_stop;      table[1].user_ctx = NULL;
    table[2].name = "pcap.save";      table[2].fn = rpc_pcap_save;      table[2].user_ctx = NULL;
    return 3;
}

static uint16_t build_ble_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 3) return 0;
    table[0].name = "ble.scan";       table[0].fn = rpc_ble_scan;       table[0].user_ctx = NULL;
    table[1].name = "ble.stop";       table[1].fn = rpc_ble_stop;       table[1].user_ctx = NULL;
    table[2].name = "ble.list";       table[2].fn = rpc_ble_list;       table[2].user_ctx = NULL;
    return 3;
}

static uint16_t build_storage_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 3) return 0;
    table[0].name = "storage.wordlist.list";      table[0].fn = rpc_storage_wordlist_list;      table[0].user_ctx = NULL;
    table[1].name = "storage.wordlist.load";      table[1].fn = rpc_storage_wordlist_load;      table[1].user_ctx = NULL;
    table[2].name = "storage.nvs.factory_reset";  table[2].fn = rpc_storage_nvs_reset;          table[2].user_ctx = NULL;
    return 3;
}

static uint16_t build_ota_methods(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (cap < 2) return 0;
    table[0].name = "ota.start";      table[0].fn = rpc_ota_start;      table[0].user_ctx = NULL;
    table[1].name = "ota.progress";   table[1].fn = rpc_ota_progress;   table[1].user_ctx = NULL;
    return 2;
}

/*============================================================================*/
const char *jsonrpc_schema_version(void)
{
    return SCHEMA_VERSION;
}

/*============================================================================*/
uint16_t jsonrpc_schema_v1_build(jsonrpc_method_entry_t *table, uint16_t cap)
{
    if (table == NULL || cap == 0) {
        return 0;
    }

    uint16_t offset = 0;
    offset += build_system_methods(table + offset, cap - offset);
    offset += build_wifi_methods(table + offset, cap - offset);
    offset += build_deauth_methods(table + offset, cap - offset);
    offset += build_pcap_methods(table + offset, cap - offset);
    offset += build_ble_methods(table + offset, cap - offset);
    offset += build_storage_methods(table + offset, cap - offset);
    offset += build_ota_methods(table + offset, cap - offset);

    return offset;
}

/*============================================================================*/
esp_err_t jsonrpc_schema_event_post(jsonrpc_event_type_t type, const char *event_json)
{
    if (event_json == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return jsonrpc_event_post(type, event_json);
}
