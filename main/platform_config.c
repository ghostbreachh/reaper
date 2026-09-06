#include "platform_config.h"
#include "esp_log.h"
#include "nvs.h"
#include <string.h>

static config_profile_t s_profile = CONFIG_PROFILE_PENTEST;
static const char *TAG = "platform_config";
static const char *NVS_NS = "platform";
static const char *NVS_KEY = "profile";

static const char *profile_name(config_profile_t p)
{
    switch (p) {
        case CONFIG_PROFILE_PENTEST: return "pentest";
        case CONFIG_PROFILE_WARDIRVE: return "wardrive";
        case CONFIG_PROFILE_RESEARCH: return "research";
        case CONFIG_PROFILE_STEALTH: return "stealth";
        default: return "unknown";
    }
}

esp_err_t platform_config_init(void)
{
    s_profile = CONFIG_PROFILE_PENTEST;
    nvs_handle_t h = 0;
    esp_err_t rc = nvs_open(NVS_NS, NVS_READONLY, &h);
    if (rc == ESP_OK) {
        uint8_t v = 0;
        size_t len = sizeof(v);
        rc = nvs_get_u8(h, NVS_KEY, &v);
        if (rc == ESP_OK && v < CONFIG_PROFILE_COUNT) {
            s_profile = (config_profile_t)v;
        }
        nvs_close(h);
    }
    ESP_LOGI(TAG, "Config profile: %s", profile_name(s_profile));
    return ESP_OK;
}

esp_err_t platform_config_apply(config_profile_t profile)
{
    if (profile >= CONFIG_PROFILE_COUNT) return ESP_ERR_INVALID_ARG;
    s_profile = profile;
    ESP_LOGI(TAG, "Config profile applied: %s", profile_name(s_profile));
    return ESP_OK;
}

config_profile_t platform_config_get(void)
{
    return s_profile;
}

esp_err_t platform_config_save(void)
{
    nvs_handle_t h = 0;
    esp_err_t rc = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (rc != ESP_OK) return rc;
    rc = nvs_set_u8(h, NVS_KEY, (uint8_t)s_profile);
    if (rc == ESP_OK) rc = nvs_commit(h);
    nvs_close(h);
    return rc;
}

esp_err_t platform_config_reset(void)
{
    s_profile = CONFIG_PROFILE_PENTEST;
    return platform_config_save();
}
