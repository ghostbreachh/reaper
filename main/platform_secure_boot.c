#include "platform_secure_boot.h"
#include "esp_log.h"
#include "esp_secure_boot.h"

static bool s_enabled = false;
static const char *TAG = "secure_boot";

esp_err_t platform_secure_boot_init(void)
{
    s_enabled = false;
#if CONFIG_SECURE_BOOT_ENABLED
    s_enabled = true;
    ESP_LOGI(TAG, "Secure boot enabled");
#else
    ESP_LOGW(TAG, "Secure boot disabled; enable via menuconfig "
                   "CONFIG_SECURE_BOOT_ENABLED");
#endif
    return ESP_OK;
}

bool platform_secure_boot_is_enabled(void)
{
    return s_enabled;
}

esp_err_t platform_secure_boot_get_fingerprint(char *out, size_t max_len)
{
    if (!out || max_len == 0) return ESP_ERR_INVALID_ARG;
    if (!s_enabled) {
        snprintf(out, max_len, "{}");
        return ESP_ERR_NOT_SUPPORTED;
    }
    snprintf(out, max_len, "{}");
    return ESP_OK;
}
