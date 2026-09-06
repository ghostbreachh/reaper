#include "platform_plugins.h"
#include "esp_log.h"
#include <string.h>

static plugin_slot_t s_slots[PLUGIN_MAX_SLOTS];
static bool s_init = false;
static const char *TAG = "plugins";

esp_err_t platform_plugins_init(void)
{
    memset(s_slots, 0, sizeof(s_slots));
    s_init = true;
    ESP_LOGI(TAG, "Plugin registry initialized, max slots=%d", PLUGIN_MAX_SLOTS);
    return ESP_OK;
}

size_t platform_plugins_list(plugin_slot_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = PLUGIN_MAX_SLOTS < max ? PLUGIN_MAX_SLOTS : max;
    memcpy(out, s_slots, n * sizeof(plugin_slot_t));
    return n;
}

esp_err_t platform_plugin_load(const char *name)
{
    if (!s_init || !name) return ESP_ERR_INVALID_ARG;
    for (size_t i = 0; i < PLUGIN_MAX_SLOTS; i++) {
        if (!s_slots[i].loaded) {
            snprintf(s_slots[i].name, PLUGIN_NAME_LEN, "%s", name);
            s_slots[i].loaded = true;
            s_slots[i].size = 0;
            ESP_LOGI(TAG, "Plugin loaded: %s", name);
            return ESP_OK;
        }
    }
    return ESP_ERR_NO_MEM;
}

esp_err_t platform_plugin_unload(const char *name)
{
    if (!s_init || !name) return ESP_ERR_INVALID_ARG;
    for (size_t i = 0; i < PLUGIN_MAX_SLOTS; i++) {
        if (s_slots[i].loaded && strcmp(s_slots[i].name, name) == 0) {
            memset(&s_slots[i], 0, sizeof(s_slots[i]));
            ESP_LOGI(TAG, "Plugin unloaded: %s", name);
            return ESP_OK;
        }
    }
    return ESP_ERR_NOT_FOUND;
}
