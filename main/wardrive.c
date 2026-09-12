#include "wardrive.h"
#include "gps.h"
#include "storage_sd.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "wardrive";

#define WARDRIVE_FLUSH_INTERVAL 32

static wardrive_mode_t g_mode = WARDRIVE_MODE_OFF;
static FILE *g_file = NULL;
static SemaphoreHandle_t g_lock = NULL;

static uint32_t g_wifi_points = 0;
static uint32_t g_ble_points = 0;
static uint32_t g_geo_points = 0;
static uint32_t g_no_geo_points = 0;
static uint32_t g_since_flush = 0;
static bool g_first_point = true;

static uint64_t g_start_us = 0;
static char g_path[128] = {0};

static const char *mode_to_str(wardrive_mode_t mode)
{
    switch (mode) {
        case WARDRIVE_MODE_WIFI: return "wifi";
        case WARDRIVE_MODE_BLE:  return "ble";
        case WARDRIVE_MODE_BOTH: return "both";
        default:                 return "off";
    }
}

static void close_file_locked(void)
{
    if (g_file != NULL) {
        fclose(g_file);
        g_file = NULL;
    }
    g_since_flush = 0;
    g_first_point = true;
}

static size_t json_escape_string(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0) return 0;
    if (!src) { dst[0] = '\0'; return 0; }

    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 1 < dst_sz; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= dst_sz) break;
            dst[j++] = '\\';
            dst[j++] = (char)c;
        } else if (c < 0x20) {
            dst[j++] = ' ';
        } else {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
    return j;
}

static bool get_gps_coords(char *lat_str, size_t lat_sz,
                           char *lon_str, size_t lon_sz)
{
    gps_fix_t fix;
    if (gps_get_fix(&fix) == ESP_OK && fix.valid) {
        snprintf(lat_str, lat_sz, "%.6f", fix.latitude);
        snprintf(lon_str, lon_sz, "%.6f", fix.longitude);
        return true;
    }
    return false;
}

esp_err_t wardrive_init(void)
{
    if (g_lock != NULL) {
        return ESP_OK;
    }

    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }

    g_mode = WARDRIVE_MODE_OFF;
    g_wifi_points = 0;
    g_ble_points = 0;
    g_geo_points = 0;
    g_no_geo_points = 0;
    g_start_us = 0;
    g_since_flush = 0;
    g_first_point = true;
    memset(g_path, 0, sizeof(g_path));

    ESP_LOGI(TAG, "Wardrive module initialized");
    return ESP_OK;
}

esp_err_t wardrive_start(wardrive_mode_t mode)
{
    if (mode == WARDRIVE_MODE_OFF) {
        return wardrive_stop();
    }

    if (g_lock == NULL) {
        esp_err_t rc = wardrive_init();
        if (rc != ESP_OK) return rc;
    }

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    if (g_mode != WARDRIVE_MODE_OFF) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_STATE;
    }

    close_file_locked();
    
    g_wifi_points = 0;
    g_ble_points = 0;
    g_geo_points = 0;
    g_no_geo_points = 0;
    g_start_us = esp_timer_get_time();
    g_mode = mode;
    g_first_point = true;

    snprintf(g_path, sizeof(g_path), "/sd/wardrive_%" PRIu64 ".json", g_start_us);

    esp_err_t rc = storage_sd_mount(); 
    if (rc != ESP_OK && rc != ESP_ERR_INVALID_STATE) { 
        ESP_LOGE(TAG, "SD mount failed: %s", esp_err_to_name(rc));
        g_mode = WARDRIVE_MODE_OFF;
        xSemaphoreGive(g_lock);
        return rc;
    }

    g_file = fopen(g_path, "w");
    if (g_file == NULL) {
        ESP_LOGE(TAG, "Failed to open %s", g_path);
        g_mode = WARDRIVE_MODE_OFF;
        xSemaphoreGive(g_lock);
        return ESP_ERR_NO_MEM;
    }

    fprintf(g_file, "{\"mode\":\"%s\",\"start_us\":%" PRIu64 ",\"points\":[\n",
            mode_to_str(mode), g_start_us);
    
    ESP_LOGI(TAG, "Wardrive started: mode=%s path=%s", mode_to_str(mode), g_path);
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t wardrive_stop(void)
{
    if (g_lock == NULL) return ESP_OK;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    if (g_file != NULL) {
        uint64_t end_us = esp_timer_get_time();
        fprintf(g_file, "\n],\"end_us\":%" PRIu64 "}\n", end_us);
        fflush(g_file);
        close_file_locked();
    }

    wardrive_mode_t prev = g_mode;
    g_mode = WARDRIVE_MODE_OFF;
    
    ESP_LOGI(TAG, "Wardrive stopped: mode=%s wifi=%"PRIu32" ble=%"PRIu32" geo=%"PRIu32" no_geo=%"PRIu32,
             mode_to_str(prev), g_wifi_points, g_ble_points, g_geo_points, g_no_geo_points);
             
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

static void flush_if_needed_locked(void)
{
    if (g_file != NULL) {
        g_since_flush++;
        if (g_since_flush >= WARDRIVE_FLUSH_INTERVAL) {
            fflush(g_file);
            g_since_flush = 0;
        }
    }
}

esp_err_t wardrive_log_wifi(const char *bssid, const char *ssid,
                            int8_t rssi, uint8_t channel,
                            const char *security)
{
    if (g_mode != WARDRIVE_MODE_WIFI && g_mode != WARDRIVE_MODE_BOTH) {
        return ESP_OK;
    }
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    if (g_file == NULL) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_STATE;
    }

    char lat[32] = "null";
    char lon[32] = "null";
    bool geo = get_gps_coords(lat, sizeof(lat), lon, sizeof(lon));
    
    if (geo) g_geo_points++;
    else g_no_geo_points++;

    g_wifi_points++;

    char safe_ssid[65] = "";
    json_escape_string(safe_ssid, sizeof(safe_ssid), ssid);

    char safe_sec[32] = "";
    json_escape_string(safe_sec, sizeof(safe_sec), security);

    if (!g_first_point) {
        fprintf(g_file, ",\n");
    }
    g_first_point = false;

    fprintf(g_file,
            "{\"t\":\"w\",\"ts\":%" PRIu64 ",\"bssid\":\"%s\",\"ssid\":\"%s\","
            "\"rssi\":%d,\"ch\":%u,\"sec\":\"%s\","
            "\"lat\":%s,\"lon\":%s}",
            (uint64_t)esp_timer_get_time(),
            bssid ? bssid : "00:00:00:00:00:00",
            safe_ssid,
            (int)rssi, (unsigned)channel,
            safe_sec,
            lat, lon);
            
    flush_if_needed_locked();
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t wardrive_log_ble(const uint8_t *addr, const char *name,
                           int8_t rssi, uint8_t channel)
{
    if (g_mode != WARDRIVE_MODE_BLE && g_mode != WARDRIVE_MODE_BOTH) {
        return ESP_OK;
    }
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    if (g_file == NULL) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_STATE;
    }

    char lat[32] = "null";
    char lon[32] = "null";
    bool geo = get_gps_coords(lat, sizeof(lat), lon, sizeof(lon));
    
    if (geo) g_geo_points++;
    else g_no_geo_points++;

    g_ble_points++;

    char mac[18];
    if (addr != NULL) {
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    } else {
        snprintf(mac, sizeof(mac), "00:00:00:00:00:00");
    }

    char safe_name[65] = "";
    json_escape_string(safe_name, sizeof(safe_name), name);

    if (!g_first_point) {
        fprintf(g_file, ",\n");
    }
    g_first_point = false;

    fprintf(g_file,
            "{\"t\":\"b\",\"ts\":%" PRIu64 ",\"mac\":\"%s\",\"name\":\"%s\","
            "\"rssi\":%d,\"ch\":%u,\"lat\":%s,\"lon\":%s}",
            (uint64_t)esp_timer_get_time(),
            mac, safe_name,
            (int)rssi, (unsigned)channel,
            lat, lon);
            
    flush_if_needed_locked();
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t wardrive_get_stats(wardrive_stats_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    
    out->wifi_points = g_wifi_points;
    out->ble_points = g_ble_points;
    out->total_points = g_wifi_points + g_ble_points;
    out->start_us = g_start_us;
    out->end_us = (g_mode == WARDRIVE_MODE_OFF) ? esp_timer_get_time() : 0;
    out->geo_points = g_geo_points;
    out->no_geo_points = g_no_geo_points;
    snprintf(out->export_path, sizeof(out->export_path), "%s", g_path);
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t wardrive_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;
    
    wardrive_stats_t st;
    esp_err_t rc = wardrive_get_stats(&st);
    if (rc != ESP_OK) return rc;

    int n = snprintf(buf, bufsz,
                     "{\"mode\":\"%s\",\"wifi\":%"PRIu32",\"ble\":%"PRIu32",\"total\":%"PRIu32","
                     "\"geo\":%"PRIu32",\"no_geo\":%"PRIu32",\"path\":\"%s\"}",
                     mode_to_str(g_mode),
                     st.wifi_points, st.ble_points, st.total_points,
                     st.geo_points, st.no_geo_points,
                     st.export_path);
                     
    return (n < 0 || (size_t)n >= bufsz) ? ESP_ERR_NO_MEM : ESP_OK;
}

wardrive_mode_t wardrive_get_mode(void)
{
    return g_mode;
}

esp_err_t wardrive_deinit(void)
{
    wardrive_stop();
    if (g_lock != NULL) {
        vSemaphoreDelete(g_lock);
        g_lock = NULL;
    }
    return ESP_OK;
}
