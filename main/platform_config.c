#include "platform_config.h"
#include "stealth.h"
#include "wardrive.h"
#include "ai_training.h"

#include <string.h>
#include <stdatomic.h>

#include "esp_log.h"

#include "nvs.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static atomic_int s_profile = CONFIG_PROFILE_PENTEST;
static SemaphoreHandle_t s_lock = NULL;
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
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
        if (s_lock == NULL) return ESP_ERR_NO_MEM;
    }

    config_profile_t loaded = CONFIG_PROFILE_PENTEST;
    
    nvs_handle_t h = 0;
    esp_err_t rc = nvs_open(NVS_NS, NVS_READONLY, &h);
    if (rc == ESP_OK) {
        uint8_t v = 0;
        if (nvs_get_u8(h, NVS_KEY, &v) == ESP_OK && v < CONFIG_PROFILE_COUNT) {
            loaded = (config_profile_t)v;
        }
        nvs_close(h);
    }
    
    atomic_store(&s_profile, loaded);
    ESP_LOGI(TAG, "Config profile initialized: %s", profile_name(loaded));
    return ESP_OK;
}

esp_err_t platform_config_apply(config_profile_t profile)
{
    if (profile >= CONFIG_PROFILE_COUNT) return ESP_ERR_INVALID_ARG;
    
    if (s_lock == NULL) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    atomic_store(&s_profile, profile);
    
    /* Apply profile-specific system settings */
    switch (profile) {
        case CONFIG_PROFILE_STEALTH:
            stealth_set_mode(STEALTH_MODE_PASSIVE);
            /* Stealth mode typically means passive listening only */
            break;
            
        case CONFIG_PROFILE_PENTEST:
            stealth_set_mode(STEALTH_MODE_OFF);
            /* Active scanning and attacks allowed */
            break;
            
        case CONFIG_PROFILE_WARDIRVE:
            stealth_set_mode(STEALTH_MODE_OFF);
            /* Start wardrive if GPS is available */
            wardrive_start(WARDRIVE_MODE_BOTH);
            break;
            
        case CONFIG_PROFILE_RESEARCH:
            stealth_set_mode(STEALTH_MODE_OFF);
            /* Enable packet capture and AI training */
            ai_train_start(AI_TRAIN_MODE_BOTH);
            break;
            
        default:
            break;
    }
    
    xSemaphoreGive(s_lock);
    ESP_LOGI(TAG, "Config profile applied: %s", profile_name(profile));
    return ESP_OK;
}

config_profile_t platform_config_get(void)
{
    return (config_profile_t)atomic_load(&s_profile);
}

esp_err_t platform_config_save(void)
{
    if (s_lock == NULL) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    config_profile_t current = (config_profile_t)atomic_load(&s_profile);
    xSemaphoreGive(s_lock);

    nvs_handle_t h = 0;
    esp_err_t rc = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (rc != ESP_OK) return rc;
    
    rc = nvs_set_u8(h, NVS_KEY, (uint8_t)current);
    if (rc == ESP_OK) rc = nvs_commit(h);
    nvs_close(h);
    
    return rc;
}

esp_err_t platform_config_reset(void)
{
    if (s_lock == NULL) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    atomic_store(&s_profile, CONFIG_PROFILE_PENTEST);
    xSemaphoreGive(s_lock);
    
    return platform_config_save();
}
