#include "matter_commissioner.h"

#include <stdatomic.h>
#include <stdio.h>

#include "esp_log.h"

static const char *TAG = "matter_comm";

static atomic_bool s_active = false;
static atomic_bool s_warned = false;

esp_err_t matter_commissioner_init(void)
{
    atomic_store(&s_active, false);
    atomic_store(&s_warned, false);
    
    ESP_LOGI(TAG, "Matter commissioner stub initialized "
                  "(requires Thread-capable hardware)");
    return ESP_OK;
}

esp_err_t matter_commissioner_start(const char *setup_payload)
{
    (void)setup_payload;

    if (atomic_load(&s_active)) {
        return ESP_ERR_INVALID_STATE;
    }

    /* Only log the missing hardware warning once per boot to prevent console spam */
    if (!atomic_exchange(&s_warned, true)) {
        ESP_LOGW(TAG, "Matter commissioner start requested "
                      "(no Thread radio on ESP32-S3)");
    }

    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t matter_commissioner_stop(void)
{
    /* Idempotent: do nothing if already stopped */
    if (!atomic_load(&s_active)) {
        return ESP_OK;
    }

    atomic_store(&s_active, false);
    ESP_LOGI(TAG, "Matter commissioner stopped");
    return ESP_OK;
}

bool matter_commissioner_is_active(void)
{
    return atomic_load(&s_active);
}

esp_err_t matter_commissioner_get_devices(char *out, size_t max_len)
{
    if (!out || max_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    
    /* Return an empty JSON array as a stub response */
    snprintf(out, max_len, "[]");
    return ESP_ERR_NOT_SUPPORTED;
}
