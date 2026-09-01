/*
 * ============================================================================
 *  GPS TIMESTAMP CORRELATION
 * ============================================================================
 *
 *  Branch A — UART GPS only, no external input
 *    Decision: REJECTED. Phone GPS via JSON-RPC is primary; ESP has no GPS.
 *  Branch B — Phone-first GPS via JSON-RPC, optional UART fallback
 *    Decision: ACCEPTED. Phone provides fix via RPC; UART GPS still works
 *              if module attached. One unified gps_fix_t store.
 *  Branch C — External GPS library
 *    Decision: REJECTED. No external dependency policy; keep it inline.
 */

#include "gps.h"
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "driver/uart.h"
#include "soc/uart_struct.h"
#include <math.h>

static const char *TAG = "gps";

#define GPS_UART_NUM        UART_NUM_1
#define GPS_BAUD_RATE       9600
#define GPS_RX_BUF_SIZE     1024
#define GPS_TASK_STACK      3072
#define GPS_TASK_PRIO       5
#define GPS_TASK_CORE       1

static SemaphoreHandle_t g_gps_mutex = NULL;
static gps_fix_t g_gps_fix = {0};
static uint64_t g_gps_epoch_offset_us = 0;
static bool g_gps_init_done = false;
static TaskHandle_t g_gps_task = NULL;
static atomic_bool g_gps_running = ATOMIC_VAR_INIT(false);

static uint32_t nmea_checksum(const char *sentence)
{
    uint32_t sum = 0;
    for (const char *p = sentence + 1; *p && *p != '*'; p++) {
        sum ^= (uint8_t)*p;
    }
    return sum;
}

static bool nmea_parse_ggga(const char *line, gps_fix_t *out)
{
    if (line == NULL || out == NULL) return false;
    memset(out, 0, sizeof(*out));

    /* Skip "$GPGGA," */
    const char *p = line;
    if (*p != '$') return false;
    p++;
    if (strncmp(p, "GPGGA,", 6) != 0) return false;
    p += 6;

    /* Field 1: UTC time HHMMSS.sss */
    char utc_str[16] = {0};
    size_t len = 0;
    while (*p && *p != ',' && len < sizeof(utc_str) - 1) {
        utc_str[len++] = *p++;
    }
    if (*p != ',') return false;
    p++;

    /* Field 2: latitude */
    char lat_str[16] = {0};
    len = 0;
    while (*p && *p != ',' && len < sizeof(lat_str) - 1) {
        lat_str[len++] = *p++;
    }
    if (*p != ',') return false;
    p++;

    /* Field 3: N/S */
    char ns = *p;
    if (*p != ',') p++;

    /* Field 4: longitude */
    char lon_str[16] = {0};
    len = 0;
    while (*p && *p != ',' && len < sizeof(lon_str) - 1) {
        lon_str[len++] = *p++;
    }
    if (*p != ',') return false;
    p++;

    /* Field 5: E/W */
    char ew = *p;
    if (*p != ',') p++;

    /* Field 6: fix quality */
    if (*p != ',') return false;
    p++;
    char fix_q = *p;
    if (*p != ',') p++;

    /* Field 7: satellites */
    if (*p != ',') return false;
    p++;
    char sat_str[8] = {0};
    len = 0;
    while (*p && *p != ',' && len < sizeof(sat_str) - 1) {
        sat_str[len++] = *p++;
    }

    out->fix_quality = (fix_q >= '0' && fix_q <= '9') ? (fix_q - '0') : 0;
    out->sat_count = (uint8_t)atoi(sat_str);
    out->valid = (out->fix_quality >= 1 && out->sat_count >= 3);

    /* Convert DDMM.MMMM to decimal degrees */
    if (lat_str[0]) {
        double lat = atof(lat_str);
        double deg = floor(lat / 100.0);
        double min = lat - (deg * 100.0);
        out->latitude = deg + (min / 60.0);
        if (ns == 'S') out->latitude = -out->latitude;
    }

    if (lon_str[0]) {
        double lon = atof(lon_str);
        double deg = floor(lon / 100.0);
        double min = lon - (deg * 100.0);
        out->longitude = deg + (min / 60.0);
        if (ew == 'W') out->longitude = -out->longitude;
    }

    return true;
}

static void gps_task(void *arg)
{
    (void)arg;
    uint8_t buf[GPS_RX_BUF_SIZE];
    char line[128];
    size_t line_pos = 0;

    while (atomic_load(&g_gps_running)) {
        int len = uart_read_bytes(GPS_UART_NUM, buf, sizeof(buf), pdMS_TO_TICKS(100));
        if (len <= 0) continue;

        for (int i = 0; i < len; i++) {
            char c = (char)buf[i];
            if (c == '\n' || c == '\r') {
                if (line_pos > 0 && line_pos < sizeof(line) - 1) {
                    line[line_pos] = '\0';
                    gps_fix_t fix;
                    if (nmea_parse_ggga(line, &fix)) {
                        xSemaphoreTake(g_gps_mutex, portMAX_DELAY);
                        g_gps_fix = fix;
                        xSemaphoreGive(g_gps_mutex);
                    }
                }
                line_pos = 0;
            } else if (line_pos < sizeof(line) - 1) {
                line[line_pos++] = c;
            }
        }
    }

    vTaskDelete(NULL);
}

esp_err_t gps_init(void)
{
    if (g_gps_init_done) return ESP_OK;

    g_gps_mutex = xSemaphoreCreateMutex();
    if (g_gps_mutex == NULL) return ESP_ERR_NO_MEM;

    g_gps_init_done = true;
    ESP_LOGI(TAG, "GPS subsystem initialized (UART optional)");
    return ESP_OK;
}

esp_err_t gps_start(void)
{
    if (!g_gps_init_done) return ESP_ERR_INVALID_STATE;
    if (atomic_load(&g_gps_running)) return ESP_OK;

    /* Try optional UART GPS module; fail soft if no hardware */
    uart_config_t uart_cfg = {
        .baud_rate = GPS_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    esp_err_t ret = uart_param_config(GPS_UART_NUM, &uart_cfg);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "No UART GPS hardware; phone GPS via RPC only");
        return ESP_OK;
    }

    ret = uart_set_pin(GPS_UART_NUM, UART_PIN_NO_CHANGE, GPIO_NUM_19, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "UART GPS pins unavailable; phone GPS via RPC only");
        return ESP_OK;
    }

    ret = uart_driver_install(GPS_UART_NUM, GPS_RX_BUF_SIZE, 0, 0, NULL, 0);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "UART GPS driver failed; phone GPS via RPC only");
        return ESP_OK;
    }

    atomic_store(&g_gps_running, true);
    BaseType_t rc = xTaskCreatePinnedToCore(gps_task, "gps_task", GPS_TASK_STACK, NULL, GPS_TASK_PRIO, &g_gps_task, GPS_TASK_CORE);
    if (rc != pdPASS) {
        atomic_store(&g_gps_running, false);
        g_gps_task = NULL;
        uart_driver_delete(GPS_UART_NUM);
        ESP_LOGW(TAG, "GPS task create failed; phone GPS via RPC only");
        return ESP_OK;
    }

    ESP_LOGI(TAG, "GPS UART task started on UART%d", GPS_UART_NUM);
    return ESP_OK;
}

esp_err_t gps_stop(void)
{
    if (!atomic_load(&g_gps_running)) return ESP_OK;

    atomic_store(&g_gps_running, false);
    if (g_gps_task != NULL) {
        vTaskDelay(pdMS_TO_TICKS(100));
        g_gps_task = NULL;
    }

    /* UART driver may not be installed if no GPS module was present */
    uart_driver_delete(GPS_UART_NUM);
    ESP_LOGI(TAG, "GPS task stopped");
    return ESP_OK;
}

bool gps_get_fix(gps_fix_t *out)
{
    if (out == NULL || g_gps_mutex == NULL) return false;

    xSemaphoreTake(g_gps_mutex, portMAX_DELAY);
    *out = g_gps_fix;
    xSemaphoreGive(g_gps_mutex);
    return out->valid;
}

uint64_t gps_get_timestamp_us(void)
{
    if (g_gps_mutex == NULL) return 0;

    xSemaphoreTake(g_gps_mutex, portMAX_DELAY);
    uint64_t ts = g_gps_fix.timestamp;
    xSemaphoreGive(g_gps_mutex);
    return ts * 1000000ULL;
}

bool gps_is_valid(void)
{
    if (g_gps_mutex == NULL) return false;

    xSemaphoreTake(g_gps_mutex, portMAX_DELAY);
    bool valid = g_gps_fix.valid;
    xSemaphoreGive(g_gps_mutex);
    return valid;
}

esp_err_t gps_set_fix(const gps_fix_t *fix)
{
    if (fix == NULL || g_gps_mutex == NULL) return ESP_ERR_INVALID_ARG;

    xSemaphoreTake(g_gps_mutex, portMAX_DELAY);
    g_gps_fix = *fix;
    xSemaphoreGive(g_gps_mutex);
    return ESP_OK;
}

int gps_format_coords(char *buf, size_t bufsz, const gps_fix_t *fix)
{
    if (buf == NULL || bufsz == 0 || fix == NULL) return 0;

    if (!fix->valid) {
        return snprintf(buf, bufsz, "NO FIX");
    }

    char lat_s[16], lon_s[16];
    snprintf(lat_s, sizeof(lat_s), "%.6f", fix->latitude);
    snprintf(lon_s, sizeof(lon_s), "%.6f", fix->longitude);

    return snprintf(buf, bufsz, "%s,%s alt=%.1fm sats=%d",
                    lat_s, lon_s, fix->altitude, fix->sat_count);
}
