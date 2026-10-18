/*
 * ============================================================================
 *  structured_log.c  —  Ring-buffer structured logging + JSON export
 * ============================================================================
 */

#include "structured_log.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "cJSON.h"

static const char *TAG = "slog";

#define LOG_CAPACITY 1024
#define LOG_MSG_MAX  160

typedef struct {
    uint64_t    timestamp_us;
    char        tag[24];
    log_level_t level;
    char        message[LOG_MSG_MAX];
} log_entry_t;

static log_entry_t *g_ring = NULL;
static uint32_t g_head = 0;
static atomic_bool g_initialized = ATOMIC_VAR_INIT(false);

static SemaphoreHandle_t g_lock = NULL;

static bool g_filter_set = false;
static char g_filter_tag[48] = {0};
static log_level_t g_filter_min = LOG_LEVEL_VERBOSE;

static inline uint32_t ring_index(uint32_t seq)
{
    return seq % LOG_CAPACITY;
}

/* Must be called while holding g_lock */
static inline bool matches_filter_locked(const char *tag, log_level_t level)
{
    if (!g_filter_set) return true;
    if (level < g_filter_min) return false;
    if (g_filter_tag[0] == '\0') return true;
    if (tag == NULL) return false;
    return strstr(tag, g_filter_tag) != NULL;
}

esp_err_t structured_log_init(void)
{
    if (atomic_load(&g_initialized)) return ESP_OK;

    if (g_lock == NULL) {
        g_lock = xSemaphoreCreateMutex();
        if (g_lock == NULL) return ESP_ERR_NO_MEM;
    }

    if (g_ring == NULL) {
        g_ring = heap_caps_malloc(LOG_CAPACITY * sizeof(log_entry_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!g_ring) {
            ESP_LOGE(TAG, "PSRAM allocation failed for log ring");
            return ESP_ERR_NO_MEM;
        }
    }

    memset(g_ring, 0, LOG_CAPACITY * sizeof(log_entry_t));
    g_head = 0;
    g_filter_set = false;
    g_filter_tag[0] = '\0';
    g_filter_min = LOG_LEVEL_VERBOSE;
    
    atomic_store(&g_initialized, true);

    ESP_LOGI(TAG, "Structured log ready: %u entries, PSRAM", LOG_CAPACITY);
    return ESP_OK;
}

void structured_log_write(const char *tag, log_level_t level, const char *fmt, ...)
{
    if (!atomic_load(&g_initialized) || !g_ring || !fmt) return;

    /* 
     * Non-blocking lock acquisition. 
     * If the system is heavily contended or a task is deadlocked holding 
     * the log lock, we drop the log message rather than hanging the caller.
     */
    if (xSemaphoreTake(g_lock, 0) != pdTRUE) {
        return; 
    }

    if (!matches_filter_locked(tag, level)) {
        xSemaphoreGive(g_lock);
        return;
    }

    uint32_t seq = g_head++;
    uint32_t idx = ring_index(seq);

    log_entry_t *e = &g_ring[idx];
    e->timestamp_us = esp_timer_get_time();
    e->level = level;

    if (tag) {
        snprintf(e->tag, sizeof(e->tag), "%s", tag);
    } else {
        snprintf(e->tag, sizeof(e->tag), "?");
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->message, sizeof(e->message), fmt, ap);
    va_end(ap);

    xSemaphoreGive(g_lock);
}

void structured_log_set_filter(const char *tag_substr, log_level_t min_level)
{
    if (g_lock == NULL) return;

    xSemaphoreTake(g_lock, portMAX_DELAY);
    g_filter_set = true;
    g_filter_min = min_level;
    if (tag_substr) {
        snprintf(g_filter_tag, sizeof(g_filter_tag), "%s", tag_substr);
    } else {
        g_filter_tag[0] = '\0';
    }
    xSemaphoreGive(g_lock);
}

static cJSON *entry_to_json(const log_entry_t *e)
{
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;

    cJSON_AddNumberToObject(obj, "ts", (double)e->timestamp_us / 1000000.0);
    cJSON_AddStringToObject(obj, "tag", e->tag);
    cJSON_AddNumberToObject(obj, "level", (int)e->level);

    cJSON *msg = cJSON_CreateString(e->message);
    if (!msg) { 
        cJSON_Delete(obj); 
        return NULL; 
    }
    cJSON_AddItemToObject(obj, "msg", msg);

    return obj;
}

esp_err_t structured_log_export_json(const char *path)
{
    if (!atomic_load(&g_initialized) || !g_ring || !path) return ESP_ERR_INVALID_STATE;

    FILE *f = fopen(path, "w");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open %s for log export", path);
        return ESP_ERR_NOT_FOUND;
    }

    fprintf(f, "[\n");

    uint32_t total = 0;
    uint32_t start = 0;

    xSemaphoreTake(g_lock, portMAX_DELAY);
    total = g_head;
    start = (total > LOG_CAPACITY) ? (total - LOG_CAPACITY) : 0;
    xSemaphoreGive(g_lock);

    bool first = true;
    uint32_t exported_count = 0;

    for (uint32_t i = start; i < total; i++) {
        log_entry_t local_e;

        xSemaphoreTake(g_lock, portMAX_DELAY);
        memcpy(&local_e, &g_ring[ring_index(i)], sizeof(log_entry_t));
        xSemaphoreGive(g_lock);

        if (local_e.message[0] == '\0') continue;

        cJSON *obj = entry_to_json(&local_e);
        if (!obj) continue;

        char *out = cJSON_PrintUnformatted(obj);
        cJSON_Delete(obj);

        if (out) {
            if (!first) {
                fprintf(f, ",\n");
            }
            fprintf(f, "%s", out);
            cJSON_free(out);
            first = false;
            exported_count++;
        }
    }

    fprintf(f, "\n]\n");
    fclose(f);

    ESP_LOGI(TAG, "Exported %u entries to %s", (unsigned)exported_count, path);
    return ESP_OK;
}

void structured_log_clear(void)
{
    if (!atomic_load(&g_initialized) || !g_ring || !g_lock) return;
    
    xSemaphoreTake(g_lock, portMAX_DELAY);
    memset(g_ring, 0, LOG_CAPACITY * sizeof(log_entry_t));
    g_head = 0;
    xSemaphoreGive(g_lock);
    
    ESP_LOGI(TAG, "Log ring cleared");
}

size_t structured_log_count(void)
{
    if (!atomic_load(&g_initialized)) return 0;
    
    uint32_t total = 0;
    if (g_lock) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        total = g_head;
        xSemaphoreGive(g_lock);
    }
    return (total > LOG_CAPACITY) ? LOG_CAPACITY : total;
}

size_t structured_log_capacity(void)
{
    return LOG_CAPACITY;
}
