#include "platform_fleet.h"
#include "esp_log.h"
#include "esp_timer.h"

static bool s_enabled = false;
static const char *TAG = "fleet";

esp_err_t platform_fleet_init(void)
{
    s_enabled = false;
    ESP_LOGI(TAG, "Fleet management initialized (opt-in)");
    return ESP_OK;
}

esp_err_t platform_fleet_report(void)
{
    if (!s_enabled) return ESP_ERR_NOT_SUPPORTED;
    ESP_LOGI(TAG, "Fleet report queued");
    return ESP_OK;
}

bool platform_fleet_is_enabled(void)
{
    return s_enabled;
}
