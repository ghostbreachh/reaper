/*
 * ============================================================================
 *  watchdog.c  —  Watchdog supervisor and post-mortem crash logging
 * ============================================================================
 */

#include "watchdog.h"
#include "storage_spiffs.h"

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdatomic.h>
#include <time.h>

#include "esp_system.h"
#include "esp_log.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "watchdog";
static const char *CRASH_PATH = "/spiffs/crash.log";

/* ── Internal Helpers ─────────────────────────────────────────────────── */

static const char* reset_reason_to_str(esp_reset_reason_t reason)
{
    switch (reason) {
        case ESP_RST_POWERON:   return "POWERON";
        case ESP_RST_EXT:       return "EXT";
        case ESP_RST_SW:        return "SW";
        case ESP_RST_PANIC:     return "PANIC";
        case ESP_RST_INT_WDT:   return "INT_WDT";
        case ESP_RST_TASK_WDT:  return "TASK_WDT";
        case ESP_RST_WDT:       return "WDT";
        case ESP_RST_DEEPSLEEP: return "DEEPSLEEP";
        case ESP_RST_BROWNOUT:  return "BROWNOUT";
        case ESP_RST_SDIO:      return "SDIO";
        default:                return "UNKNOWN";
    }
}

static void write_crash_log_to_spiffs(esp_reset_reason_t reason)
{
    if (!storage_spiffs_is_ready()) {
        ESP_LOGW(TAG, "SPIFFS not ready; cannot persist crash log");
        return;
    }

    FILE *f = fopen(CRASH_PATH, "w");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open crash log for writing");
        return;
    }

    time_t now = time(NULL);
    struct tm timeinfo;
    char time_str[32] = "unknown";
    if (localtime_r(&now, &timeinfo) != NULL) {
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &timeinfo);
    }

    fprintf(f, "=== REAPER CRASH LOG ===\n");
    fprintf(f, "Boot Time: %s\n", time_str);
    fprintf(f, "Reset Reason: %s (%d)\n", reset_reason_to_str(reason), (int)reason);
    fprintf(f, "Free Heap at Boot: %u bytes\n", (unsigned)esp_get_free_heap_size());
    fprintf(f, "Min Free Heap: %u bytes\n", (unsigned)esp_get_minimum_free_heap_size());
    fprintf(f, "Uptime (us): %llu\n", (unsigned long long)esp_timer_get_time());
    fprintf(f, "\nNote: Full register state requires a coredump partition.\n");

    fclose(f);
    ESP_LOGW(TAG, "Crash log persisted to %s", CRASH_PATH);
}

/* ── Public API ───────────────────────────────────────────────────────── */

esp_err_t watchdog_init(void)
{
    esp_reset_reason_t reason = esp_reset_reason();

    /* 
     * SAFE CRASH LOGGING:
     * Instead of trying to write to SPIFFS while the system is actively 
     * crashing (which causes hangs/secondary panics), we detect the panic 
     * on the *next boot* and write the log from a safe task context.
     */
    if (reason == ESP_RST_PANIC || 
        reason == ESP_RST_TASK_WDT || 
        reason == ESP_RST_INT_WDT || 
        reason == ESP_RST_WDT) {
        
        ESP_LOGW(TAG, "Detected abnormal reset reason: %s", reset_reason_to_str(reason));
        write_crash_log_to_spiffs(reason);
    }

    ESP_LOGI(TAG, "Watchdog supervisor initialized");
    return ESP_OK;
}

void watchdog_task_refresh(const char *task_name)
{
    (void)task_name; /* Used only for logging if needed */

    TaskHandle_t handle = xTaskGetCurrentTaskHandle();
    if (handle == NULL) return;

    esp_err_t r = esp_task_wdt_reset();
    
    if (r == ESP_ERR_NOT_FOUND) {
        /* Task wasn't subscribed yet; subscribe it now */
        if (esp_task_wdt_add(handle) == ESP_OK) {
            esp_task_wdt_reset();
        }
    }
}

void watchdog_test_panic(void)
{
    ESP_LOGE(TAG, "Initiating test panic via abort()");
    abort();
}

esp_err_t watchdog_read_crash(char *out, size_t out_len)
{
    if (!out || !out_len) return ESP_ERR_INVALID_ARG;
    out[0] = '\0';

    FILE *f = fopen(CRASH_PATH, "r");
    if (!f) {
        snprintf(out, out_len, "No crash log found.");
        return ESP_ERR_NOT_FOUND;
    }

    size_t rd = fread(out, 1, out_len - 1, f);
    out[rd] = '\0';
    fclose(f);
    
    return ESP_OK;
}

void watchdog_clear_crash(void)
{
    if (remove(CRASH_PATH) == 0) {
        ESP_LOGI(TAG, "Crash log cleared");
    } else {
        ESP_LOGD(TAG, "No crash log to clear");
    }
}

bool watchdog_has_crash_log(void)
{
    FILE *f = fopen(CRASH_PATH, "r");
    if (f) {
        fclose(f);
        return true;
    }
    return false;
}
