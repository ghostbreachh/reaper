/*
 * ============================================================================
 *  GPS TIMESTAMP CORRELATION & NMEA PARSER
 * ============================================================================
 */

#include "gps.h"

#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_system.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "driver/uart.h"
#include "driver/gpio.h"

/* Fallback for older ESP-IDF versions */
#ifndef UART_SCLK_DEFAULT
#define UART_SCLK_DEFAULT UART_SCLK_APB
#endif

static const char *TAG = "gps";

#define GPS_UART_NUM        UART_NUM_1
#define GPS_BAUD_RATE       9600
#define GPS_RX_BUF_SIZE     1024
#define GPS_TASK_STACK      3072
#define GPS_TASK_PRIO       5
#define GPS_TASK_CORE       1
#define GPS_RX_PIN          19  /* Adjust based on your hardware wiring */

static SemaphoreHandle_t g_gps_mutex = NULL;
static gps_fix_t g_gps_fix = {0};
static bool g_gps_init_done = false;
static TaskHandle_t g_gps_task = NULL;
static atomic_bool g_gps_running = ATOMIC_VAR_INIT(false);

/* -------------------------------------------------------------------------
 *  Robust NMEA Parser
 * ----------------------------------------------------------------------- */

static uint8_t nmea_checksum(const char *sentence)
{
    uint8_t sum = 0;
    if (*sentence == '$') sentence++;
    for (; *sentence && *sentence != '*'; sentence++) {
        sum ^= (uint8_t)*sentence;
    }
    return sum;
}

static int nmea_split(char *sentence, char **fields, int max_fields)
{
    int count = 0;
    char *p = sentence;
    
    /* Terminate at '*' to ignore checksum during splitting */
    char *star = strchr(sentence, '*');
    if (star) *star = '\0';
    
    while (count < max_fields) {
        fields[count++] = p;
        char *comma = strchr(p, ',');
        if (!comma) break;
        *comma = '\0';
        p = comma + 1;
    }
    return count;
}

static bool nmea_parse(const char *line, gps_fix_t *out)
{
    if (!line || !out) return false;
    if (line[0] != '$') return false;
    
    /* 1. Verify Checksum */
    const char *star = strchr(line, '*');
    if (star && strlen(star) >= 3) {
        uint8_t calc = nmea_checksum(line);
        unsigned int recv = 0;
        if (sscanf(star + 1, "%2x", &recv) == 1) {
            if (calc != (uint8_t)recv) {
                return false; /* Checksum mismatch */
            }
        }
    }
    
    char buf[128];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    
    char *fields[16];
    int count = nmea_split(buf, fields, 16);
    if (count < 2 || strlen(fields[0]) < 5) return false;
    
    /* Identify sentence type (skip $GP, $GN, $GL, etc.) */
    const char *type = fields[0] + 2; 
    
    /* 2. Parse GGA (Position & Fix Quality) */
    if (strcmp(type, "GGA") == 0 && count >= 10) {
        out->fix_quality = (uint8_t)atoi(fields[6]);
        out->sat_count = (uint8_t)atoi(fields[7]);
        out->valid = (out->fix_quality > 0 && out->sat_count >= 3);
        
        if (fields[2][0] && fields[3][0]) {
            double lat = strtod(fields[2], NULL);
            double deg = floor(lat / 100.0);
            double min = lat - (deg * 100.0);
            out->latitude = deg + (min / 60.0);
            if (fields[3][0] == 'S') out->latitude = -out->latitude;
        }
        
        if (fields[4][0] && fields[5][0]) {
            double lon = strtod(fields[4], NULL);
            double deg = floor(lon / 100.0);
            double min = lon - (deg * 100.0);
            out->longitude = deg + (min / 60.0);
            if (fields[5][0] == 'W') out->longitude = -out->longitude;
        }
        
        if (fields[9][0]) {
            out->altitude = strtof(fields[9], NULL);
        }
        return true;
    } 
    /* 3. Parse RMC (Date & Time for Unix Epoch) */
    else if (strcmp(type, "RMC") == 0 && count >= 10) {
        if (fields[2][0] == 'A' && fields[1][0] && fields[9][0]) {
            struct tm t = {0};
            /* Date: DDMMYY */
            t.tm_mday = (fields[9][0] - '0') * 10 + (fields[9][1] - '0');
            t.tm_mon  = (fields[9][2] - '0') * 10 + (fields[9][3] - '0') - 1;
            t.tm_year = (fields[9][4] - '0') * 10 + (fields[9][5] - '0') + 100; /* 2000+ */
            
            /* Time: HHMMSS.ss */
            t.tm_hour = (fields[1][0] - '0') * 10 + (fields[1][1] - '0');
            t.tm_min  = (fields[1][2] - '0') * 10 + (fields[1][3] - '0');
            t.tm_sec  = (fields[1][4] - '0') * 10 + (fields[1][5] - '0');
            
            /* mktime uses local time. If TZ is not set, ESP-IDF assumes UTC. */
            out->timestamp = mktime(&t);
        }
        return true;
    }
    
    return false;
}

/* -------------------------------------------------------------------------
 *  Background Task
 * ----------------------------------------------------------------------- */

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
                    
                    gps_fix_t parsed_fix;
                    /* Preserve existing timestamp if this is a GGA sentence */
                    xSemaphoreTake(g_gps_mutex, portMAX_DELAY);
                    parsed_fix = g_gps_fix; 
                    xSemaphoreGive(g_gps_mutex);
                    
                    if (nmea_parse(line, &parsed_fix)) {
                        xSemaphoreTake(g_gps_mutex, portMAX_DELAY);
                        if (strstr(line, "GGA")) {
                            g_gps_fix.latitude = parsed_fix.latitude;
                            g_gps_fix.longitude = parsed_fix.longitude;
                            g_gps_fix.altitude = parsed_fix.altitude;
                            g_gps_fix.sat_count = parsed_fix.sat_count;
                            g_gps_fix.fix_quality = parsed_fix.fix_quality;
                            g_gps_fix.valid = parsed_fix.valid;
                        } else if (strstr(line, "RMC")) {
                            g_gps_fix.timestamp = parsed_fix.timestamp;
                        }
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

/* -------------------------------------------------------------------------
 *  Public API
 * ----------------------------------------------------------------------- */

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

    ret = uart_set_pin(GPS_UART_NUM, UART_PIN_NO_CHANGE, GPS_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
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
        /* Wait longer than the UART read timeout to ensure clean exit */
        vTaskDelay(pdMS_TO_TICKS(200)); 
        g_gps_task = NULL;
    }

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
    time_t ts = g_gps_fix.timestamp;
    xSemaphoreGive(g_gps_mutex);
    return (uint64_t)ts * 1000000ULL;
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

    return snprintf(buf, bufsz, "%.6f,%.6f alt=%.1fm sats=%d",
                    fix->latitude, fix->longitude, fix->altitude, fix->sat_count);
}
