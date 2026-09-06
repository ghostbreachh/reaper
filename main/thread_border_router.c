#include "thread_border_router.h"
#include "esp_log.h"

static bool s_active = false;
static const char *TAG = "thread_br";

esp_err_t thread_br_init(void)
{
    s_active = false;
    ESP_LOGI(TAG, "Thread Border Router stub initialized "
                  "(requires ESP32-H2/C6 hardware)");
    return ESP_OK;
}

esp_err_t thread_br_start(void)
{
    if (s_active) return ESP_ERR_INVALID_STATE;
    ESP_LOGI(TAG, "Thread Border Router start requested "
                  "(no 802.15.4 radio on ESP32-S3)");
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t thread_br_stop(void)
{
    s_active = false;
    ESP_LOGI(TAG, "Thread Border Router stopped");
    return ESP_OK;
}

bool thread_br_is_active(void)
{
    return s_active;
}

esp_err_t thread_br_get_dataset(char *out, size_t max_len)
{
    if (!out || max_len == 0) return ESP_ERR_INVALID_ARG;
    snprintf(out, max_len, "{}");
    return ESP_ERR_NOT_SUPPORTED;
}
