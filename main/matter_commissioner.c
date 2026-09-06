#include "matter_commissioner.h"
#include "esp_log.h"

static bool s_active = false;
static const char *TAG = "matter_comm";

esp_err_t matter_commissioner_init(void)
{
    s_active = false;
    ESP_LOGI(TAG, "Matter commissioner stub initialized "
                  "(requires Thread-capable hardware)");
    return ESP_OK;
}

esp_err_t matter_commissioner_start(const char *setup_payload)
{
    if (s_active) return ESP_ERR_INVALID_STATE;
    (void)setup_payload;
    ESP_LOGI(TAG, "Matter commissioner start requested "
                  "(no Thread radio on ESP32-S3)");
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t matter_commissioner_stop(void)
{
    s_active = false;
    ESP_LOGI(TAG, "Matter commissioner stopped");
    return ESP_OK;
}

bool matter_commissioner_is_active(void)
{
    return s_active;
}

esp_err_t matter_commissioner_get_devices(char *out, size_t max_len)
{
    if (!out || max_len == 0) return ESP_ERR_INVALID_ARG;
    snprintf(out, max_len, "[]");
    return ESP_ERR_NOT_SUPPORTED;
}
