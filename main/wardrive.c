#include "wardrive.h"
#include "gps.h"
#include "coex.h"
#include "wifi_sniffer.h"
#include "ble_scanner.h"
#include "ai_ble_profiler.h"
#include "storage_sd.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_timer.h"

static const char *TAG = "wardrive";

/* Current wardrive state. */
static wardrive_mode_t g_mode = WARDIRVE_MODE_OFF;
static FILE *g_file = NULL;
static SemaphoreHandle_t g_lock;
static uint32_t g_wifi_points;
static uint32_t g_ble_points;
static uint32_t g_geo_points;
static uint32_t g_skipped_no_geo;
static uint64_t g_start_us;
static char g_path[128];

static const char *mode_to_str(wardrive_mode_t mode)
{
    switch (mode) {
        case WARDIRVE_MODE_WIFI: return "wifi";
        case WARDIRVE_MODE_BLE: return "ble";
        case WARDIRVE_MODE_BOTH: return "both";
        default: return "off";
    }
}

static wardrive_mode_t str_to_mode(const char *s)
{
    if (strcmp(s, "wifi") == 0) return WARDIRVE_MODE_WIFI;
    if (strcmp(s, "ble") == 0) return WARDIRVE_MODE_BLE;
    if (strcmp(s, "both") == 0) return WARDIRVE_MODE_BOTH;
    return WARDIRVE_MODE_OFF;
}

static void close_file(void)
{
    if (g_file != NULL) {
        fclose(g_file);
        g_file = NULL;
    }
}

esp_err_t wardrive_init(void)
{
    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }
    g_mode = WARDIRVE_MODE_OFF;
    g_wifi_points = 0;
    g_ble_points = 0;
    g_geo_points = 0;
    g_skipped_no_geo = 0;
    g_start_us = 0;
    memset(g_path, 0, sizeof(g_path));
    ESP_LOGI(TAG, "wardrive init");
    return ESP_OK;
}

esp_err_t wardrive_start(wardrive_mode_t mode)
{
    if (mode == WARDIRVE_MODE_OFF) {
        return wardrive_stop();
    }

    esp_err_t rc = ESP_OK;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    close_file();
    g_wifi_points = 0;
    g_ble_points = 0;
    g_geo_points = 0;
    g_skipped_no_geo = 0;
    g_mode = mode;
    g_start_us = esp_timer_get_time();

    snprintf(g_path, sizeof(g_path), "/sd/wardrive_%" PRIu64 ".jsonl",
             g_start_us);

    rc = storage_sd_mount();
    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "SD mount failed: %s", esp_err_to_name(rc));
        g_mode = WARDIRVE_MODE_OFF;
        xSemaphoreGive(g_lock);
        return rc;
    }

    g_file = fopen(g_path, "w");
    if (g_file == NULL) {
        ESP_LOGE(TAG, "failed to open %s", g_path);
        g_mode = WARDIRVE_MODE_OFF;
        xSemaphoreGive(g_lock);
        return ESP_ERR_NO_MEM;
    }

    fprintf(g_file,
            "{\"mode\":\"%s\",\"start_us\":%" PRIu64 ",\"points\":[}\n",
            mode_to_str(mode), g_start_us);
    fflush(g_file);

    ESP_LOGI(TAG, "wardrive start mode=%s path=%s", mode_to_str(mode), g_path);
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t wardrive_stop(void)
{
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    if (g_file != NULL) {
        uint64_t end_us = esp_timer_get_time();
        fprintf(g_file, "],\"end_us\":%" PRIu64 "}\n", end_us);
        fflush(g_file);
        close_file();
    }

    wardrive_mode_t prev = g_mode;
    g_mode = WARDIRVE_MODE_OFF;
    ESP_LOGI(TAG, "wardrive stop mode=%s points wifi=%u ble=%u geo=%u skip=%u",
             mode_to_str(prev), g_wifi_points, g_ble_points,
             g_geo_points, g_skipped_no_geo);
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

static esp_err_t write_point(const char *json)
{
    if (g_file == NULL) return ESP_ERR_INVALID_STATE;
    if (g_wifi_points + g_ble_points == 0) {
        fprintf(g_file, "%s", json);
    } else {
        fprintf(g_file, ",%s", json);
    }
    fflush(g_file);
    return ESP_OK;
}

static bool have_gps(char *lat_str, size_t lat_sz,
                     char *lon_str, size_t lon_sz)
{
    gps_fix_t fix;
    if (!gps_get_fix(&fix) || !fix.valid) {
        return false;
    }
    snprintf(lat_str, lat_sz, "%.6f", fix.latitude);
    snprintf(lon_str, lon_sz, "%.6f", fix.longitude);
    return true;
}

esp_err_t wardrive_log_wifi(const char *bssid, const char *ssid,
                            int8_t rssi, uint8_t channel,
                            const char *security)
{
    if (g_mode != WARDIRVE_MODE_WIFI && g_mode != WARDIRVE_MODE_BOTH) {
        return ESP_OK;
    }
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    if (g_file == NULL) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_STATE;
    }

    char lat[32] = "";
    char lon[32] = "";
    bool geo = have_gps(lat, sizeof(lat), lon, sizeof(lon));
    if (!geo) {
        g_skipped_no_geo++;
        xSemaphoreGive(g_lock);
        return ESP_OK;
    }

    g_geo_points++;
    g_wifi_points++;

    char safe_ssid[64];
    safe_ssid[0] = '\0';
    if (ssid != NULL) {
        size_t i;
        for (i = 0; i < sizeof(safe_ssid) - 1 && ssid[i] != '\0'; i++) {
            if (ssid[i] == '"' || ssid[i] == '\\') {
                safe_ssid[i] = '\\';
            } else {
                safe_ssid[i] = ssid[i];
            }
        }
        safe_ssid[i] = '\0';
    }

    char safe_sec[32];
    safe_sec[0] = '\0';
    if (security != NULL) {
        strncpy(safe_sec, security, sizeof(safe_sec) - 1);
        safe_sec[sizeof(safe_sec) - 1] = '\0';
    }

    fprintf(g_file,
            "{\"t\":\"w\",\"ts\":%" PRIu64 ",\"bssid\":\"%s\",\"ssid\":\"%s\","
            "\"rssi\":%d,\"ch\":%u,\"sec\":\"%s\","
            "\"lat\":%s,\"lon\":%s}\n",
            (uint64_t)esp_timer_get_time(),
            bssid ? bssid : "",
            safe_ssid,
            (int)rssi, (unsigned)channel,
            safe_sec,
            lat, lon);
    fflush(g_file);
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t wardrive_log_ble(const uint8_t *addr, const char *name,
                           int8_t rssi, uint8_t channel)
{
    if (g_mode != WARDIRVE_MODE_BLE && g_mode != WARDIRVE_MODE_BOTH) {
        return ESP_OK;
    }
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    if (g_file == NULL) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_STATE;
    }

    char lat[32] = "";
    char lon[32] = "";
    bool geo = have_gps(lat, sizeof(lat), lon, sizeof(lon));
    if (!geo) {
        g_skipped_no_geo++;
        xSemaphoreGive(g_lock);
        return ESP_OK;
    }

    g_geo_points++;
    g_ble_points++;

    char mac[18];
    if (addr != NULL) {
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    } else {
        snprintf(mac, sizeof(mac), "00:00:00:00:00:00");
    }

    char safe_name[64];
    safe_name[0] = '\0';
    if (name != NULL) {
        size_t i;
        for (i = 0; i < sizeof(safe_name) - 1 && name[i] != '\0'; i++) {
            if (name[i] == '"' || name[i] == '\\') {
                safe_name[i] = '\\';
            } else {
                safe_name[i] = name[i];
            }
        }
        safe_name[i] = '\0';
    }

    fprintf(g_file,
            "{\"t\":\"b\",\"ts\":%" PRIu64 ",\"mac\":\"%s\",\"name\":\"%s\","
            "\"rssi\":%d,\"ch\":%u,\"lat\":%s,\"lon\":%s}\n",
            (uint64_t)esp_timer_get_time(),
            mac, safe_name,
            (int)rssi, (unsigned)channel,
            lat, lon);
    fflush(g_file);
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t wardrive_get_stats(wardrive_stats_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    out->wifi_points = g_wifi_points;
    out->ble_points = g_ble_points;
    out->total_points = g_wifi_points + g_ble_points;
    out->start_us = g_start_us;
    out->end_us = g_mode == WARDIRVE_MODE_OFF ? esp_timer_get_time() : 0;
    out->geo_points = g_geo_points;
    out->skipped_no_geo = g_skipped_no_geo;
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
                     "{\"mode\":\"%s\",\"wifi\":%u,\"ble\":%u,\"total\":%u,"
                     "\"geo\":%u,\"skip\":%u,\"path\":\"%s\"}",
                     mode_to_str(g_mode),
                     st.wifi_points, st.ble_points, st.total_points,
                     st.geo_points, st.skipped_no_geo,
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
