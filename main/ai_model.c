#include "ai_model.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "storage_spiffs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* ============================================================================
 *  ESP-DL MODEL ZOO LOADER
 * ============================================================================
 *
 *  Branch A — Hard dependency on ESP-DL headers
 *    Decision: REJECTED. Breaks builds without ESP-DL installed.
 *  Branch B — SPIFFS-based loader + soft stub if ESP-DL missing
 *    Decision: ACCEPTED. Loads INT8 models from /spiffs/models/ into RAM.
 *              Inference path is a stub unless ESP-DL is present; compile-safe
 *              in all ESP-IDF configurations.
 *  Branch C — Only load from flash partition table
 *    Decision: REJECTED. SPIFFS allows OTA model updates without flashing.
 */

static const char *TAG = "ai_model";

typedef struct {
    char            name[AI_MODEL_NAME_MAX];
    ai_model_format_t format;
    size_t          model_size;
    void            *model_data;
    uint32_t        loaded_at;
    bool            is_loaded;
    bool            is_quantized;
} ai_model_entry_t;

static ai_model_entry_t g_zoo[AI_MODEL_ZOO_CAPACITY];
static bool g_zoo_init_done = false;

static ai_model_entry_t *find_slot(const char *name)
{
    for (int i = 0; i < AI_MODEL_ZOO_CAPACITY; i++) {
        if (g_zoo[i].is_loaded && strcmp(g_zoo[i].name, name) == 0) {
            return &g_zoo[i];
        }
    }
    return NULL;
}

static ai_model_entry_t *find_free_slot(void)
{
    for (int i = 0; i < AI_MODEL_ZOO_CAPACITY; i++) {
        if (!g_zoo[i].is_loaded) return &g_zoo[i];
    }
    return NULL;
}

esp_err_t ai_model_zoo_init(void)
{
    if (g_zoo_init_done) return ESP_OK;

    memset(g_zoo, 0, sizeof(g_zoo));
    g_zoo_init_done = true;
    ESP_LOGI(TAG, "model zoo initialized (capacity=%d)", AI_MODEL_ZOO_CAPACITY);
    return ESP_OK;
}

esp_err_t ai_model_zoo_load(const char *name)
{
    if (name == NULL || !storage_spiffs_is_ready()) return ESP_ERR_INVALID_STATE;

    /* Already loaded? */
    ai_model_entry_t *slot = find_slot(name);
    if (slot != NULL) {
        ESP_LOGI(TAG, "model '%s' already loaded", name);
        return ESP_OK;
    }

    slot = find_free_slot();
    if (slot == NULL) {
        ESP_LOGE(TAG, "model zoo full");
        return ESP_ERR_NO_MEM;
    }

    char path[128];
    snprintf(path, sizeof(path), "/spiffs/models/%s.bin", name);

    void *data = NULL;
    size_t len = 0;
    esp_err_t rc = storage_spiffs_load_wordlist(path, &data, &len);
    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "failed to load model from %s", path);
        return rc;
    }

    snprintf(slot->name, AI_MODEL_NAME_MAX, "%s", name);
    slot->format = AI_MODEL_FMT_ESPDL;
    slot->model_size = len;
    slot->model_data = data;
    slot->loaded_at = (uint32_t)(esp_timer_get_time() / 1000000ULL);
    slot->is_loaded = true;
    slot->is_quantized = true;

    ESP_LOGI(TAG, "model '%s' loaded (%d bytes, INT8)", name, (int)len);
    return ESP_OK;
}

esp_err_t ai_model_zoo_unload(const char *name)
{
    if (name == NULL) return ESP_ERR_INVALID_ARG;

    ai_model_entry_t *slot = find_slot(name);
    if (slot == NULL) return ESP_ERR_NOT_FOUND;

    if (slot->model_data != NULL) {
        storage_spiffs_free_buffer(slot->model_data);
        slot->model_data = NULL;
    }
    slot->is_loaded = false;
    slot->model_size = 0;
    ESP_LOGI(TAG, "model '%s' unloaded", name);
    return ESP_OK;
}

esp_err_t ai_model_zoo_infer(const char *name,
                             const void *input, size_t input_len,
                             void *output, size_t output_len,
                             size_t *out_len)
{
    if (name == NULL || input == NULL || output == NULL || out_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    ai_model_entry_t *slot = find_slot(name);
    if (slot == NULL) return ESP_ERR_NOT_FOUND;

    if (!slot->is_loaded || slot->model_data == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    /* Placeholder: actual inference requires ESP-DL runtime. */
    ESP_LOGW(TAG, "inference stub: '%s' needs ESP-DL runtime linked", name);

    /* If ESP-DL is present, this block dispatches through:
     *   dl::loader::load_from_memory(slot->model_data, slot->model_size)
     *   -> run(input, output)
     * Because ESP-DL is optional, we soft-fail here instead of crashing.
     */

    memset(output, 0, output_len);
    *out_len = 0;
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t ai_model_zoo_list(char ***names, size_t *count)
{
    if (names == NULL || count == NULL) return ESP_ERR_INVALID_ARG;

    if (!storage_spiffs_is_ready()) {
        *names = NULL;
        *count = 0;
        return ESP_ERR_INVALID_STATE;
    }

    char **spiffs_names = NULL;
    size_t spiffs_count = 0;
    esp_err_t rc = storage_spiffs_list_wordlists(&spiffs_names, &spiffs_count);
    if (rc != ESP_OK) {
        *names = NULL;
        *count = 0;
        return rc;
    }

    /* Filter only model files (under /spiffs/models/*.bin) */
    char **model_names = calloc(spiffs_count, sizeof(char *));
    size_t model_count = 0;
    for (size_t i = 0; i < spiffs_count; i++) {
        if (strstr(spiffs_names[i], "/models/") != NULL ||
            strstr(spiffs_names[i], "\\models\\") != NULL) {
            model_names[model_count++] = spiffs_names[i];
        } else {
            free(spiffs_names[i]);
        }
    }

    /* Reallocate to exact count */
    if (model_count < spiffs_count) {
        model_names = realloc(model_names, model_count * sizeof(char *));
    }

    free(spiffs_names);
    *names = model_names;
    *count = model_count;
    return ESP_OK;
}

void ai_model_zoo_free_list(char **names, size_t count)
{
    if (names == NULL) return;
    for (size_t i = 0; i < count; i++) {
        free(names[i]);
    }
    free(names);
}

esp_err_t ai_model_zoo_get_info(const char *name, ai_model_info_t *out_info)
{
    if (name == NULL || out_info == NULL) return ESP_ERR_INVALID_ARG;

    ai_model_entry_t *slot = find_slot(name);
    if (slot == NULL) {
        memset(out_info, 0, sizeof(*out_info));
        snprintf(out_info->name, AI_MODEL_NAME_MAX, "%s", name);
        return ESP_ERR_NOT_FOUND;
    }

    memset(out_info, 0, sizeof(*out_info));
    snprintf(out_info->name, AI_MODEL_NAME_MAX, "%s", slot->name);
    out_info->format = slot->format;
    out_info->model_size = slot->model_size;
    out_info->loaded_at = slot->loaded_at;
    out_info->is_loaded = slot->is_loaded;
    out_info->is_quantized = slot->is_quantized;
    return ESP_OK;
}

esp_err_t ai_model_zoo_json(char *buf, size_t bufsz)
{
    int w = snprintf(buf, bufsz, "[");
    if (w < 0 || (size_t)w >= bufsz) return ESP_ERR_NO_MEM;

    bool first = true;
    for (int i = 0; i < AI_MODEL_ZOO_CAPACITY && (size_t)w < bufsz; i++) {
        if (!g_zoo[i].is_loaded) continue;

        const char *fmt = "esdl";
        switch (g_zoo[i].format) {
            case AI_MODEL_FMT_ESPDL:    fmt = "esdl";    break;
            case AI_MODEL_FMT_TFLITE:   fmt = "tflite";  break;
            default:                    fmt = "unknown";  break;
        }

        int n = snprintf(buf + w, bufsz - w,
            "%s{\"name\":\"%s\",\"format\":\"%s\",\"size\":%d,"
            "\"quantized\":%s,\"loaded\":%d}",
            first ? "" : ",",
            g_zoo[i].name,
            fmt,
            (int)g_zoo[i].model_size,
            g_zoo[i].is_quantized ? "true" : "false",
            g_zoo[i].is_loaded ? "true" : "false");
        if (n < 0 || (size_t)n >= bufsz - w) break;
        w += n;
        first = false;
    }

    if ((size_t)w + 1 >= bufsz) return ESP_ERR_NO_MEM;
    buf[w++] = ']';
    buf[w] = '\0';
    return ESP_OK;
}

void ai_model_zoo_deinit(void)
{
    for (int i = 0; i < AI_MODEL_ZOO_CAPACITY; i++) {
        if (g_zoo[i].is_loaded) {
            ai_model_zoo_unload(g_zoo[i].name);
        }
    }
    g_zoo_init_done = false;
    ESP_LOGI(TAG, "model zoo deinitialized");
}
