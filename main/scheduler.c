#include "scheduler.h"
#include "wifi_sniffer.h"
#include "stealth.h"
#include "wardrive.h"
#include "ai_training.h"

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdatomic.h>
#include <ctype.h>
#include <inttypes.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "scheduler";

#define NVS_NS "sched"
#define NVS_KEY "entries"

/* Require time to be at least Jan 1, 2024 to consider it valid */
#define MIN_VALID_EPOCH 1704067200 

static sched_entry_t g_entries[SCHED_MAX_ENTRIES];
static SemaphoreHandle_t g_lock = NULL;
static SemaphoreHandle_t g_stop_sem = NULL;
static TaskHandle_t g_task = NULL;
static atomic_bool g_running = false;

static uint32_t g_fire_count = 0;
static uint64_t g_last_fire_us = 0;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static void sanitize_string(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0) return;
    if (!src) { dst[0] = '\0'; return; }

    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 1 < dst_sz; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\' || c < 0x20) {
            dst[j++] = '_';
        } else {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
}

static void save_to_nvs_locked(void)
{
    nvs_handle_t nvs;
    if (nvs_open(NVS_NS, NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_set_blob(nvs, NVS_KEY, g_entries, sizeof(g_entries));
        nvs_commit(nvs);
        nvs_close(nvs);
    }
}

static bool is_match(const sched_entry_t *e)
{
    time_t now_s = time(NULL);
    
    /* Prevent firing if SNTP hasn't synced yet */
    if (now_s < MIN_VALID_EPOCH) {
        return false; 
    }

    struct tm tm;
    localtime_r(&now_s, &tm);

    if (e->minute != 0xFF && tm.tm_min != (int)e->minute) return false;
    if (e->hour != 0xFF && tm.tm_hour != (int)e->hour) return false;
    
    if (!(e->day_of_week & 0x80)) {
        /* tm_wday: 0=Sunday ... 6=Saturday. Map to 0=Monday ... 6=Sunday */
        int dow = (tm.tm_wday + 6) % 7; 
        if (!(e->day_of_week & (1 << dow))) return false;
    }
    
    return true;
}

static void execute_action(const sched_entry_t *e)
{
    switch (e->action) {
        case SCHED_ACTION_WIFI_START:
            wifi_sniffer_start(0);
            break;
        case SCHED_ACTION_WIFI_STOP:
            wifi_sniffer_stop();
            break;
        case SCHED_ACTION_STEALTH_SET_MODE: {
            stealth_mode_t mode = STEALTH_MODE_OFF;
            if (strcmp(e->params, "passive") == 0) mode = STEALTH_MODE_PASSIVE;
            else if (strcmp(e->params, "active") == 0) mode = STEALTH_MODE_ACTIVE;
            stealth_set_mode(mode);
            break;
        }
        case SCHED_ACTION_WARDRIVE_START: {
            wardrive_mode_t mode = WARDRIVE_MODE_OFF;
            if (strcmp(e->params, "wifi") == 0) mode = WARDRIVE_MODE_WIFI;
            else if (strcmp(e->params, "ble") == 0) mode = WARDRIVE_MODE_BLE;
            else if (strcmp(e->params, "both") == 0) mode = WARDRIVE_MODE_BOTH;
            wardrive_start(mode);
            break;
        }
        case SCHED_ACTION_WARDRIVE_STOP:
            wardrive_stop();
            break;
        case SCHED_ACTION_AI_TRAIN_START: {
            ai_train_mode_t mode = AI_TRAIN_MODE_OFF;
            if (strcmp(e->params, "wifi") == 0) mode = AI_TRAIN_MODE_WIFI;
            else if (strcmp(e->params, "ble") == 0) mode = AI_TRAIN_MODE_BLE;
            else if (strcmp(e->params, "both") == 0) mode = AI_TRAIN_MODE_BOTH;
            ai_train_start(mode);
            break;
        }
        case SCHED_ACTION_AI_TRAIN_STOP:
            ai_train_stop();
            break;
        case SCHED_ACTION_CUSTOM_JSONRPC:
            /* Future: dispatch through JSON-RPC internal handler */
            break;
        default:
            break;
    }
}

/* -------------------------------------------------------------------------
 *  Task
 * ----------------------------------------------------------------------- */

static void scheduler_task(void *arg)
{
    (void)arg;
    bool last_minute[SCHED_MAX_ENTRIES];
    memset(last_minute, 0, sizeof(last_minute));

    while (atomic_load(&g_running)) {
        if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(500)) != pdTRUE) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        for (int i = 0; i < SCHED_MAX_ENTRIES; i++) {
            const sched_entry_t *e = &g_entries[i];
            if (!e->enabled) {
                last_minute[i] = false;
                continue;
            }
            
            if (!is_match(e)) {
                last_minute[i] = false;
                continue;
            }
            
            if (!last_minute[i]) {
                execute_action(e);
                g_fire_count++;
                g_last_fire_us = esp_timer_get_time();
                ESP_LOGI(TAG, "Fired entry %d action=%d", i, e->action);
                last_minute[i] = true;
            }
        }

        xSemaphoreGive(g_lock);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    if (g_stop_sem != NULL) {
        xSemaphoreGive(g_stop_sem);
    }
    vTaskDelete(NULL);
}

/* -------------------------------------------------------------------------
 *  Public API
 * ----------------------------------------------------------------------- */

esp_err_t scheduler_init(void)
{
    if (g_lock != NULL) return ESP_OK;

    g_lock = xSemaphoreCreateMutex();
    g_stop_sem = xSemaphoreCreateBinary();
    
    if (g_lock == NULL || g_stop_sem == NULL) {
        return ESP_ERR_NO_MEM;
    }

    memset(g_entries, 0, sizeof(g_entries));
    g_fire_count = 0;
    g_last_fire_us = 0;

    /* Restore from NVS if present */
    nvs_handle_t nvs;
    if (nvs_open(NVS_NS, NVS_READONLY, &nvs) == ESP_OK) {
        size_t sz = sizeof(g_entries);
        if (nvs_get_blob(nvs, NVS_KEY, g_entries, &sz) == ESP_OK && sz == sizeof(g_entries)) {
            ESP_LOGI(TAG, "Restored %u entries from NVS", SCHED_MAX_ENTRIES);
        }
        nvs_close(nvs);
    }

    atomic_store(&g_running, true);

    if (xTaskCreatePinnedToCore(scheduler_task, "scheduler", 4096, NULL, 3, &g_task, 0) != pdPASS) {
        atomic_store(&g_running, false);
        return ESP_ERR_NO_MEM;
    }
    
    ESP_LOGI(TAG, "Scheduler initialized");
    return ESP_OK;
}

int scheduler_add(const sched_entry_t *entry)
{
    if (entry == NULL || g_lock == NULL) return -1;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return -2;
    
    for (int i = 0; i < SCHED_MAX_ENTRIES; i++) {
        if (!g_entries[i].enabled) {
            memcpy(&g_entries[i], entry, sizeof(sched_entry_t));
            sanitize_string(g_entries[i].params, sizeof(g_entries[i].params), entry->params);
            save_to_nvs_locked();
            xSemaphoreGive(g_lock);
            return i;
        }
    }
    
    xSemaphoreGive(g_lock);
    return -3; /* Full */
}

esp_err_t scheduler_remove(uint8_t index)
{
    if (index >= SCHED_MAX_ENTRIES || g_lock == NULL) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    memset(&g_entries[index], 0, sizeof(sched_entry_t));
    save_to_nvs_locked();
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t scheduler_update(uint8_t index, const sched_entry_t *entry)
{
    if (index >= SCHED_MAX_ENTRIES || entry == NULL || g_lock == NULL) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    memcpy(&g_entries[index], entry, sizeof(sched_entry_t));
    sanitize_string(g_entries[index].params, sizeof(g_entries[index].params), entry->params);
    save_to_nvs_locked();
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t scheduler_get(uint8_t index, sched_entry_t *out)
{
    if (index >= SCHED_MAX_ENTRIES || out == NULL || g_lock == NULL) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    memcpy(out, &g_entries[index], sizeof(sched_entry_t));
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t scheduler_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0 || g_lock == NULL) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    int n = snprintf(buf, bufsz, "[");
    if (n < 0 || (size_t)n >= bufsz) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_NO_MEM;
    }

    bool first = true;
    for (int i = 0; i < SCHED_MAX_ENTRIES; i++) {
        const sched_entry_t *e = &g_entries[i];
        if (!e->enabled) continue;
        
        if (!first) {
            int c = snprintf(buf + n, bufsz - (size_t)n, ",");
            if (c < 0 || (size_t)(n + c) >= bufsz) break;
            n += c;
        }
        
        int c = snprintf(buf + n, bufsz - (size_t)n,
                         "{\"i\":%d,\"min\":%u,\"hr\":%u,\"dow\":%u,"
                         "\"action\":%d,\"params\":\"%s\"}",
                         i, e->minute, e->hour, e->day_of_week,
                         e->action, e->params);
                         
        if (c < 0 || (size_t)(n + c) >= bufsz) break;
        n += c;
        first = false;
    }
    
    if ((size_t)n + 1 < bufsz) {
        n += snprintf(buf + n, bufsz - (size_t)n, "]");
    }
    
    xSemaphoreGive(g_lock);
    return ((size_t)n >= bufsz) ? ESP_ERR_NO_MEM : ESP_OK;
}

esp_err_t scheduler_get_stats(sched_stats_t *out)
{
    if (out == NULL || g_lock == NULL) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    uint32_t enabled = 0;
    for (int i = 0; i < SCHED_MAX_ENTRIES; i++) {
        if (g_entries[i].enabled) enabled++;
    }
    
    out->total_entries = SCHED_MAX_ENTRIES;
    out->enabled_entries = enabled;
    out->last_fire_count = g_fire_count;
    out->last_fire_us = g_last_fire_us;
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t scheduler_save(void)
{
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return ESP_ERR_TIMEOUT;
    save_to_nvs_locked();
    xSemaphoreGive(g_lock);
    
    return ESP_OK;
}

esp_err_t scheduler_deinit(void)
{
    if (g_lock == NULL) return ESP_OK;

    atomic_store(&g_running, false);
    
    if (g_task != NULL && g_stop_sem != NULL) {
        xSemaphoreTake(g_stop_sem, pdMS_TO_TICKS(2000));
        g_task = NULL;
    }
    
    scheduler_save();
    
    vSemaphoreDelete(g_lock);
    g_lock = NULL;
    
    if (g_stop_sem != NULL) {
        vSemaphoreDelete(g_stop_sem);
        g_stop_sem = NULL;
    }
    
    return ESP_OK;
}
