#include "platform_plugins.h"

#include <string.h>
#include <ctype.h>

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static plugin_slot_t s_slots[PLUGIN_MAX_SLOTS];
static bool s_init = false;
static SemaphoreHandle_t s_lock = NULL;
static const char *TAG = "plugins";

static bool is_valid_plugin_name(const char *name)
{
    if (!name) return false;
    
    size_t len = strlen(name);
    if (len == 0 || len >= PLUGIN_NAME_LEN) return false;
    
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!isalnum(c) && c != '_' && c != '-') {
            return false;
        }
    }
    return true;
}

esp_err_t platform_plugins_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
        if (s_lock == NULL) return ESP_ERR_NO_MEM;
    }
    
    xSemaphoreTake(s_lock, portMAX_DELAY);
    memset(s_slots, 0, sizeof(s_slots));
    s_init = true;
    xSemaphoreGive(s_lock);
    
    ESP_LOGI(TAG, "Plugin registry initialized, max slots=%d", PLUGIN_MAX_SLOTS);
    return ESP_OK;
}

size_t platform_plugins_list(plugin_slot_t *out, size_t max)
{
    if (!out || !max || !s_init || s_lock == NULL) return 0;
    
    xSemaphoreTake(s_lock, portMAX_DELAY);
    size_t n = PLUGIN_MAX_SLOTS < max ? PLUGIN_MAX_SLOTS : max;
    memcpy(out, s_slots, n * sizeof(plugin_slot_t));
    xSemaphoreGive(s_lock);
    
    return n;
}

esp_err_t platform_plugin_load(const char *name)
{
    if (!s_init || s_lock == NULL || !is_valid_plugin_name(name)) {
        return ESP_ERR_INVALID_ARG;
    }
    
    xSemaphoreTake(s_lock, portMAX_DELAY);
    
    /* Check if already loaded to prevent duplicate entries */
    for (size_t i = 0; i < PLUGIN_MAX_SLOTS; i++) {
        if (s_slots[i].loaded && strcmp(s_slots[i].name, name) == 0) {
            xSemaphoreGive(s_lock);
            ESP_LOGW(TAG, "Plugin already loaded: %s", name);
            return ESP_ERR_INVALID_STATE;
        }
    }
    
    for (size_t i = 0; i < PLUGIN_MAX_SLOTS; i++) {
        if (!s_slots[i].loaded) {
            snprintf(s_slots[i].name, PLUGIN_NAME_LEN, "%s", name);
            s_slots[i].loaded = true;
            s_slots[i].size = 0;
            xSemaphoreGive(s_lock);
            ESP_LOGI(TAG, "Plugin loaded: %s", name);
            return ESP_OK;
        }
    }
    
    xSemaphoreGive(s_lock);
    return ESP_ERR_NO_MEM;
}

esp_err_t platform_plugin_unload(const char *name)
{
    if (!s_init || s_lock == NULL || !is_valid_plugin_name(name)) {
        return ESP_ERR_INVALID_ARG;
    }
    
    xSemaphoreTake(s_lock, portMAX_DELAY);
    
    for (size_t i = 0; i < PLUGIN_MAX_SLOTS; i++) {
        if (s_slots[i].loaded && strcmp(s_slots[i].name, name) == 0) {
            memset(&s_slots[i], 0, sizeof(s_slots[i]));
            xSemaphoreGive(s_lock);
            ESP_LOGI(TAG, "Plugin unloaded: %s", name);
            return ESP_OK;
        }
    }
    
    xSemaphoreGive(s_lock);
    return ESP_ERR_NOT_FOUND;
}
