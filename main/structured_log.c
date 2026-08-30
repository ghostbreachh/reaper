/*
 * ============================================================================
 *  structured_log.c  —  Ring-buffer structured logging + JSON export
 *
 *  DECISION BLOCK — ToT Branch Selection
 *  -------------------------------------
 *  Requirement: replace scattered ESP_LOG/printf calls with structured
 *  in-memory logging, persistent ring buffer, and JSON export.
 *
 *  Branch A — esp_log to UART + host-side grep
 *    Pros: trivial, uses existing ESP-IDF logging.
 *    Cons: no in-memory history, no structured export, lost after reboot.
 *    Decision: REJECTED. Fails persistence/export requirements.
 *
 *  Branch B — FatFS log files with rotating handles
 *    Pros: persistent, human-readable.
 *    Cons: heavy wear on flash, no atomicity, no ring semantics,
 *          expensive open/close per message.
 *    Decision: REJECTED. Too slow and flash-hostile.
 *
 *  Branch C — Lock-free ring buffer in PSRAM + cJSON export
 *    Pros: O(1) write, no flash wear during operation, export on demand,
 *          structured fields (timestamp, tag, level, message).
 *    Cons: consumes RAM, requires caller-side adoption.
 *    Decision: ACCEPTED. Best performance and extensibility.
 *
 *  Chosen implementation:
 *    1. Fixed-size ring buffer of log entries in PSRAM.
 *    2. Lock-free single-producer writes via atomic sequence counter.
 *    3. JSON export via cJSON to SPIFFS or caller path.
 * ============================================================================
 */

#include "structured_log.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/atomic.h"
#include "cJSON.h"
#include "string.h"
#include "stdio.h"
#include <stdatomic.h>

static const char *TAG = "slog";

#define LOG_CAPACITY 1024
#define LOG_MSG_MAX  160

typedef struct {
    uint64_t timestamp_us;
    char      tag[24];
    log_level_t level;
    char      message[LOG_MSG_MAX];
} log_entry_t;

static log_entry_t *g_ring = NULL;
static atomic_uint_fast32_t g_head = ATOMIC_VAR_INIT(0);
static atomic_bool g_initialized = ATOMIC_VAR_INIT(false);

static atomic_bool g_filter_set = ATOMIC_VAR_INIT(false);
static char g_filter_tag[48] = {0};
static log_level_t g_filter_min = LOG_LEVEL_VERBOSE;

static inline uint32_t ring_index(uint32_t seq)
{
    return seq % LOG_CAPACITY;
}

static inline bool matches_filter(const char *tag, log_level_t level)
{
    if (!atomic_load(&g_filter_set)) return true;
    if (level < g_filter_min) return false;
    if (g_filter_tag[0] == '\0') return true;
    return strstr(tag, g_filter_tag) != NULL;
}

esp_err_t structured_log_init(void)
{
    if (atomic_load(&g_initialized)) return ESP_OK;

    g_ring = heap_caps_malloc(LOG_CAPACITY * sizeof(log_entry_t), MALLOC_CAP_SPIRAM);
    if (!g_ring) {
        ESP_LOGE(TAG, "PSRAM allocation failed for log ring");
        return ESP_ERR_NO_MEM;
    }

    memset(g_ring, 0, LOG_CAPACITY * sizeof(log_entry_t));
    atomic_store(&g_head, 0);
    atomic_store(&g_initialized, true);

    ESP_LOGI(TAG, "Structured log ready: %u entries, PSRAM", LOG_CAPACITY);
    return ESP_OK;
}

void structured_log_write(const char *tag, log_level_t level, const char *fmt, ...)
{
    if (!atomic_load(&g_initialized) || !g_ring || !fmt) return;
    if (!matches_filter(tag, level)) return;

    uint32_t seq = atomic_fetch_add_explicit(&g_head, 1, memory_order_relaxed);
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
}

void structured_log_set_filter(const char *tag_substr, log_level_t min_level)
{
    atomic_store(&g_filter_set, true);
    g_filter_min = min_level;
    if (tag_substr) {
        snprintf(g_filter_tag, sizeof(g_filter_tag), "%s", tag_substr);
    } else {
        g_filter_tag[0] = '\0';
    }
}

static cJSON *entry_to_json(const log_entry_t *e)
{
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;

    cJSON_AddNumberToObject(obj, "ts", (double)e->timestamp_us / 1000000.0);
    cJSON_AddStringToObject(obj, "tag", e->tag);
    cJSON_AddNumberToObject(obj, "level", (int)e->level);

    cJSON *msg = cJSON_CreateString(e->message);
    if (!msg) { cJSON_Delete(obj); return NULL; }
    cJSON_AddItemToObject(obj, "msg", msg);

    return obj;
}

esp_err_t structured_log_export_json(const char *path)
{
    if (!atomic_load(&g_initialized) || !g_ring || !path) return ESP_ERR_INVALID_STATE;

    uint32_t total = (uint32_t)atomic_load(&g_head);
    if (total == 0) return ESP_OK;

    uint32_t start = (total > LOG_CAPACITY) ? (total - LOG_CAPACITY) : 0;

    cJSON *root = cJSON_CreateArray();
    if (!root) return ESP_ERR_NO_MEM;

    for (uint32_t i = start; i < total; i++) {
        const log_entry_t *e = &g_ring[ring_index(i)];
        if (e->message[0] == '\0') continue;
        cJSON *obj = entry_to_json(e);
        if (!obj) continue;
        cJSON_AddItemToArray(root, obj);
    }

    char *out = cJSON_Print(root);
    cJSON_Delete(root);
    if (!out) return ESP_ERR_NO_MEM;

    FILE *f = fopen(path, "w");
    if (!f) {
        free(out);
        return ESP_ERR_NOT_FOUND;
    }

    fwrite(out, 1, strlen(out), f);
    fclose(f);
    fsync(fileno(f));

    free(out);
    ESP_LOGI(TAG, "Exported %u entries to %s", total, path);
    return ESP_OK;
}

void structured_log_clear(void)
{
    if (!atomic_load(&g_initialized) || !g_ring) return;
    memset(g_ring, 0, LOG_CAPACITY * sizeof(log_entry_t));
    atomic_store(&g_head, 0);
    ESP_LOGI(TAG, "Log ring cleared");
}

size_t structured_log_count(void)
{
    uint32_t total = (uint32_t)atomic_load(&g_head);
    return (total > LOG_CAPACITY) ? LOG_CAPACITY : total;
}

size_t structured_log_capacity(void)
{
    return LOG_CAPACITY;
}
