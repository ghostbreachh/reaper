#include "platform_fleet.h"

#include <string.h>
#include <stdatomic.h>

#include "esp_log.h"

#include "nvs_flash.h"
#include "nvs.h"

static atomic_bool s_enabled = ATOMIC_VAR_INIT(false);
static const char *TAG = "fleet";

static const char *NVS_NAMESPACE = "fleet";
static const char *NVS_KEY = "enabled";

esp_err_t platform_fleet_init(void)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        uint8_t en = 0;
        if (nvs_get_u8(nvs, NVS_KEY, &en) == ESP_OK) {
            atomic_store(&s_enabled, en != 0);
        }
        nvs_close(nvs);
    }
    
    ESP_LOGI(TAG, "Fleet management initialized (%s)", 
             atomic_load(&s_enabled) ? "enabled" : "disabled");
    return ESP_OK;
}

esp_err_t platform_fleet_set_enabled(bool enable)
{
    atomic_store(&s_enabled, enable);
    
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        nvs_set_u8(nvs, NVS_KEY, enable ? 1 : 0);
        nvs_commit(nvs);
        nvs_close(nvs);
    } else {
        ESP_LOGE(TAG, "Failed to persist fleet state: %s", esp_err_to_name(err));
    }
    
    ESP_LOGI(TAG, "Fleet management %s", enable ? "enabled" : "disabled");
    return ESP_OK;
}

esp_err_t platform_fleet_report(void)
{
    if (!atomic_load(&s_enabled)) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    
    ESP_LOGI(TAG, "Fleet report queued");
    /* 
     * TODO: Implement actual HTTP/MQTT reporting here.
     * This should gather device stats, GPS location, and captured AP/BLE counts,
     * then POST them to the configured fleet server.
     */
    return ESP_OK;
}

bool platform_fleet_is_enabled(void)
{
    return atomic_load(&s_enabled);
}
