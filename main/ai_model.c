#include "ai_model.h"
#include "storage_spiffs.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include <inttypes.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "ai_model";

typedef struct {
    char              name[AI_MODEL_NAME_MAX];
    ai_model_format_t format;
    size_t            model_size;
    void             *model_data;

    uint32_t          loaded_at;

    bool              is_loaded;
    bool              is_loading;
    bool              is_quantized;

    /*
     * Inference stub warning should only be printed once per model.
     */
    bool              stub_warned;

    /*
     * Number of active inference users.
     * A model cannot be unloaded while this is non-zero.
     */
    uint8_t           in_use;
} ai_model_entry_t;

static ai_model_entry_t g_zoo[AI_MODEL_ZOO_CAPACITY];
static bool g_zoo_init_done = false;

static SemaphoreHandle_t g_lock = NULL;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static bool model_name_valid(const char *name)
{
    if (name == NULL) {
        return false;
    }

    size_t len = strlen(name);

    if (len == 0 || len >= AI_MODEL_NAME_MAX) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];

        if (!isalnum(c) && c != '_' && c != '-') {
            return false;
        }
    }

    return true;
}

static ai_model_entry_t *find_entry_by_name_locked(const char *name)
{
    for (int i = 0; i < AI_MODEL_ZOO_CAPACITY; i++) {
        if ((g_zoo[i].is_loaded || g_zoo[i].is_loading) &&
            strcmp(g_zoo[i].name, name) == 0) {
            return &g_zoo[i];
        }
    }

    return NULL;
}

static ai_model_entry_t *find_free_slot_locked(void)
{
    for (int i = 0; i < AI_MODEL_ZOO_CAPACITY; i++) {
        if (!g_zoo[i].is_loaded && !g_zoo[i].is_loading) {
            return &g_zoo[i];
        }
    }

    return NULL;
}

static void clear_slot_locked(ai_model_entry_t *slot)
{
    memset(slot, 0, sizeof(*slot));
    slot->format = AI_MODEL_FMT_UNKNOWN;
}

static bool str_ends_with(const char *s, const char *suffix)
{
    if (s == NULL || suffix == NULL) {
        return false;
    }

    size_t s_len = strlen(s);
    size_t suffix_len = strlen(suffix);

    if (suffix_len > s_len) {
        return false;
    }

    return strcmp(s + s_len - suffix_len, suffix) == 0;
}

static bool is_model_file(const char *path)
{
    if (path == NULL) {
        return false;
    }

    const char *base = strrchr(path, '/');
    base = (base != NULL) ? (base + 1) : path;

    return str_ends_with(base, ".bin") || str_ends_with(base, ".tflite");
}

static bool json_append(char *buf, size_t bufsz, size_t *off, const char *fmt, ...)
{
    if (buf == NULL || bufsz == 0 || off == NULL || *off >= bufsz) {
        return false;
    }

    va_list args;
    va_start(args, fmt);

    int n = vsnprintf(buf + *off, bufsz - *off, fmt, args);

    va_end(args);

    if (n < 0) {
        return false;
    }

    if ((size_t)n >= bufsz - *off) {
        *off = bufsz - 1;
        return false;
    }

    *off += (size_t)n;
    return true;
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t ai_model_zoo_init(void)
{
    if (g_zoo_init_done) {
        return ESP_OK;
    }

    if (g_lock == NULL) {
        g_lock = xSemaphoreCreateMutex();
        if (g_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_zoo, 0, sizeof(g_zoo));

    for (int i = 0; i < AI_MODEL_ZOO_CAPACITY; i++) {
        g_zoo[i].format = AI_MODEL_FMT_UNKNOWN;
    }

    g_zoo_init_done = true;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Model zoo initialized (capacity=%d)", AI_MODEL_ZOO_CAPACITY);
    return ESP_OK;
}

void ai_model_zoo_deinit(void)
{
    if (!g_zoo_init_done || g_lock == NULL) {
        return;
    }

    for (int i = 0; i < AI_MODEL_ZOO_CAPACITY; i++) {
        char name[AI_MODEL_NAME_MAX];

        xSemaphoreTake(g_lock, portMAX_DELAY);

        if (g_zoo[i].is_loaded) {
            snprintf(name, sizeof(name), "%s", g_zoo[i].name);
        } else {
            name[0] = '\0';
        }

        xSemaphoreGive(g_lock);

        if (name[0] != '\0') {
            esp_err_t rc = ai_model_zoo_unload(name);

            if (rc != ESP_OK) {
                ESP_LOGW(TAG, "Failed to unload model '%s' during deinit: %s",
                         name, esp_err_to_name(rc));
            }
        }
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    g_zoo_init_done = false;
    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Model zoo deinitialized");
}

/* -------------------------------------------------------------------------
 *  Load / unload
 * ----------------------------------------------------------------------- */

esp_err_t ai_model_zoo_load(const char *name)
{
    if (!model_name_valid(name)) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!g_zoo_init_done || g_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (!storage_spiffs_is_ready()) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    ai_model_entry_t *existing = find_entry_by_name_locked(name);

    if (existing != NULL && existing->is_loaded) {
        xSemaphoreGive(g_lock);
        ESP_LOGI(TAG, "Model '%s' already loaded", name);
        return ESP_OK;
    }

    if (existing != NULL && existing->is_loading) {
        xSemaphoreGive(g_lock);
        ESP_LOGW(TAG, "Model '%s' is already loading", name);
        return ESP_ERR_INVALID_STATE;
    }

    ai_model_entry_t *slot = find_free_slot_locked();

    if (slot == NULL) {
        xSemaphoreGive(g_lock);
        ESP_LOGE(TAG, "Model zoo full");
        return ESP_ERR_NO_MEM;
    }

    clear_slot_locked(slot);
    snprintf(slot->name, sizeof(slot->name), "%s", name);
    slot->is_loading = true;

    xSemaphoreGive(g_lock);

    void *data = NULL;
    size_t len = 0;
    ai_model_format_t format = AI_MODEL_FMT_UNKNOWN;

    char path[128];

    snprintf(path, sizeof(path), "/spiffs/models/%s.bin", name);

    esp_err_t rc = storage_spiffs_load_wordlist(path, &data, &len);

    if (rc == ESP_OK && data != NULL && len > 0) {
        format = AI_MODEL_FMT_ESPDL;
    } else {
        if (data != NULL) {
            storage_spiffs_free_buffer(data);
            data = NULL;
        }

        len = 0;

        snprintf(path, sizeof(path), "/spiffs/models/%s.tflite", name);

        rc = storage_spiffs_load_wordlist(path, &data, &len);

        if (rc == ESP_OK && data != NULL && len > 0) {
            format = AI_MODEL_FMT_TFLITE;
        }
    }

    if (rc != ESP_OK || data == NULL || len == 0) {
        if (data != NULL) {
            storage_spiffs_free_buffer(data);
        }

        xSemaphoreTake(g_lock, portMAX_DELAY);

        slot = find_entry_by_name_locked(name);
        if (slot != NULL && slot->is_loading) {
            clear_slot_locked(slot);
        }

        xSemaphoreGive(g_lock);

        ESP_LOGE(TAG, "Failed to load model '%s'", name);
        return (rc == ESP_OK) ? ESP_ERR_INVALID_SIZE : rc;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    slot = find_entry_by_name_locked(name);

    if (slot == NULL || !slot->is_loading) {
        xSemaphoreGive(g_lock);
        storage_spiffs_free_buffer(data);
        ESP_LOGE(TAG, "Model slot disappeared while loading '%s'", name);
        return ESP_ERR_NOT_FOUND;
    }

    slot->model_data = data;
    slot->model_size = len;
    slot->format = format;
    slot->loaded_at = (uint32_t)time(NULL);
    slot->is_loaded = true;
    slot->is_loading = false;
    slot->is_quantized = true;
    slot->stub_warned = false;
    slot->in_use = 0;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Model '%s' loaded (%zu bytes, format=%d)",
             name, len, (int)format);

    return ESP_OK;
}

esp_err_t ai_model_zoo_unload(const char *name)
{
    if (!model_name_valid(name)) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!g_zoo_init_done || g_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    ai_model_entry_t *slot = find_entry_by_name_locked(name);

    if (slot == NULL || (!slot->is_loaded && !slot->is_loading)) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_NOT_FOUND;
    }

    if (slot->is_loading) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_STATE;
    }

    if (slot->in_use > 0) {
        xSemaphoreGive(g_lock);
        ESP_LOGW(TAG, "Model '%s' is busy and cannot be unloaded", name);
        return ESP_ERR_INVALID_STATE;
    }

    void *data = slot->model_data;

    clear_slot_locked(slot);

    xSemaphoreGive(g_lock);

    if (data != NULL) {
        storage_spiffs_free_buffer(data);
    }

    ESP_LOGI(TAG, "Model '%s' unloaded", name);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Inference
 * ----------------------------------------------------------------------- */

esp_err_t ai_model_zoo_infer(const char *name,
                             const void *input,
                             size_t input_len,
                             void *output,
                             size_t output_len,
                             size_t *out_len)
{
    if (!model_name_valid(name) ||
        input == NULL ||
        input_len == 0 ||
        output == NULL ||
        output_len == 0 ||
        out_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!g_zoo_init_done || g_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    ai_model_entry_t *slot = find_entry_by_name_locked(name);

    if (slot == NULL || !slot->is_loaded || slot->is_loading ||
        slot->model_data == NULL) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_NOT_FOUND;
    }

    slot->in_use++;

    bool should_warn = !slot->stub_warned;
    if (should_warn) {
        slot->stub_warned = true;
    }

    xSemaphoreGive(g_lock);

    /*
     * Real inference integration point.
     *
     * If ESP-DL or TFLite Micro is linked, dispatch here using:
     *
     *   slot->model_data
     *   slot->model_size
     *   input / input_len
     *   output / output_len
     *
     * For now this is a safe stub.
     */

    if (should_warn) {
        ESP_LOGW(TAG, "Model '%s' inference stub active; returning ESP_ERR_NOT_SUPPORTED",
                 name);
    }

    memset(output, 0, output_len);
    *out_len = 0;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    slot = find_entry_by_name_locked(name);

    if (slot != NULL && slot->in_use > 0) {
        slot->in_use--;
    }

    xSemaphoreGive(g_lock);

    return ESP_ERR_NOT_SUPPORTED;
}

/* -------------------------------------------------------------------------
 *  Model listing
 * ----------------------------------------------------------------------- */

esp_err_t ai_model_zoo_list(char ***names, size_t *count)
{
    if (names == NULL || count == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    *names = NULL;
    *count = 0;

    if (!g_zoo_init_done || g_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (!storage_spiffs_is_ready()) {
        return ESP_ERR_INVALID_STATE;
    }

    char **spiffs_names = NULL;
    size_t spiffs_count = 0;

    esp_err_t rc = storage_spiffs_list_wordlists(&spiffs_names, &spiffs_count);

    if (rc != ESP_OK) {
        return rc;
    }

    if (spiffs_count == 0 || spiffs_names == NULL) {
        return ESP_OK;
    }

    char **model_names = calloc(spiffs_count, sizeof(char *));

    if (model_names == NULL) {
        for (size_t i = 0; i < spiffs_count; i++) {
            free(spiffs_names[i]);
        }

        free(spiffs_names);

        return ESP_ERR_NO_MEM;
    }

    size_t model_count = 0;

    for (size_t i = 0; i < spiffs_count; i++) {
        const char *path = spiffs_names[i];

        if (!is_model_file(path)) {
            continue;
        }

        const char *base = strrchr(path, '/');
        base = (base != NULL) ? (base + 1) : path;

        const char *dot = strrchr(base, '.');

        size_t name_len = (dot != NULL)
                              ? (size_t)(dot - base)
                              : strlen(base);

        if (name_len == 0 || name_len >= AI_MODEL_NAME_MAX) {
            continue;
        }

        char *copy = malloc(name_len + 1);

        if (copy == NULL) {
            goto cleanup;
        }

        memcpy(copy, base, name_len);
        copy[name_len] = '\0';

        model_names[model_count++] = copy;
    }

    for (size_t i = 0; i < spiffs_count; i++) {
        free(spiffs_names[i]);
    }

    free(spiffs_names);

    if (model_count == 0) {
        free(model_names);
        *names = NULL;
        *count = 0;
        return ESP_OK;
    }

    if (model_count < spiffs_count) {
        char **shrunk = realloc(model_names, model_count * sizeof(char *));

        if (shrunk != NULL) {
            model_names = shrunk;
        }
    }

    *names = model_names;
    *count = model_count;

    return ESP_OK;

cleanup:
    for (size_t i = 0; i < model_count; i++) {
        free(model_names[i]);
    }

    free(model_names);

    for (size_t i = 0; i < spiffs_count; i++) {
        free(spiffs_names[i]);
    }

    free(spiffs_names);

    return ESP_ERR_NO_MEM;
}

void ai_model_zoo_free_list(char **names, size_t count)
{
    if (names == NULL) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        free(names[i]);
    }

    free(names);
}

/* -------------------------------------------------------------------------
 *  Metadata / JSON
 * ----------------------------------------------------------------------- */

esp_err_t ai_model_zoo_get_info(const char *name, ai_model_info_t *out_info)
{
    if (!model_name_valid(name) || out_info == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!g_zoo_init_done || g_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    ai_model_entry_t *slot = find_entry_by_name_locked(name);

    if (slot == NULL || !slot->is_loaded) {
        xSemaphoreGive(g_lock);

        memset(out_info, 0, sizeof(*out_info));
        snprintf(out_info->name, sizeof(out_info->name), "%s", name);
        out_info->format = AI_MODEL_FMT_UNKNOWN;

        return ESP_ERR_NOT_FOUND;
    }

    memset(out_info, 0, sizeof(*out_info));

    snprintf(out_info->name, sizeof(out_info->name), "%s", slot->name);
    out_info->format = slot->format;
    out_info->model_size = slot->model_size;
    out_info->loaded_at = slot->loaded_at;
    out_info->is_loaded = slot->is_loaded;
    out_info->is_quantized = slot->is_quantized;

    xSemaphoreGive(g_lock);

    return ESP_OK;
}

esp_err_t ai_model_zoo_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!g_zoo_init_done || g_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    ai_model_entry_t snapshot[AI_MODEL_ZOO_CAPACITY];
    size_t snapshot_count = 0;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    for (int i = 0; i < AI_MODEL_ZOO_CAPACITY; i++) {
        if (g_zoo[i].is_loaded) {
            snapshot[snapshot_count++] = g_zoo[i];
        }
    }

    xSemaphoreGive(g_lock);

    size_t off = 0;

    if (!json_append(buf, bufsz, &off, "[")) {
        return ESP_ERR_INVALID_SIZE;
    }

    for (size_t i = 0; i < snapshot_count; i++) {
        const char *fmt = "unknown";

        switch (snapshot[i].format) {
            case AI_MODEL_FMT_ESPDL:
                fmt = "esdl";
                break;

            case AI_MODEL_FMT_TFLITE:
                fmt = "tflite";
                break;

            default:
                fmt = "unknown";
                break;
        }

        if (i > 0) {
            if (!json_append(buf, bufsz, &off, ",")) {
                return ESP_ERR_INVALID_SIZE;
            }
        }

        if (!json_append(buf, bufsz, &off,
                         "{\"name\":\"%s\","
                         "\"format\":\"%s\","
                         "\"size\":%zu,"
                         "\"quantized\":%s,"
                         "\"loaded\":true,"
                         "\"loaded_at\":%" PRIu32 "}",
                         snapshot[i].name,
                         fmt,
                         snapshot[i].model_size,
                         snapshot[i].is_quantized ? "true" : "false",
                         snapshot[i].loaded_at)) {
            return ESP_ERR_INVALID_SIZE;
        }
    }

    if (!json_append(buf, bufsz, &off, "]")) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}
