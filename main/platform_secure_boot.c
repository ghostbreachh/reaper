#include "platform_secure_boot.h"

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#if __has_include("esp_secure_boot.h")
#include "esp_secure_boot.h"
#else
static inline bool esp_secure_boot_enabled(void) { return false; }
#endif
#include "esp_ota_ops.h"
#if __has_include("esp_app_desc.h")
#include "esp_app_desc.h"
#endif

static bool s_enabled = false;
static const char *TAG = "secure_boot";

esp_err_t platform_secure_boot_init(void)
{
    /* 
     * Check the actual hardware eFuse state, not just the Kconfig compile flag.
     * A device might be compiled with secure boot support, but the eFuses 
     * haven't been burned yet.
     */
    s_enabled = esp_secure_boot_enabled();
    
    if (s_enabled) {
        ESP_LOGI(TAG, "Secure boot is enabled in hardware");
    } else {
#if CONFIG_SECURE_BOOT_ENABLED
        ESP_LOGW(TAG, "Secure boot compiled in, but not enabled in eFuses yet");
#else
        ESP_LOGW(TAG, "Secure boot disabled in Kconfig");
#endif
    }
    
    return ESP_OK;
}

bool platform_secure_boot_is_enabled(void)
{
    return s_enabled;
}

esp_err_t platform_secure_boot_get_fingerprint(char *out, size_t max_len)
{
    if (!out || max_len == 0) return ESP_ERR_INVALID_ARG;
    
    const esp_app_desc_t *app = esp_app_get_description();
    char sha_hex[17];
    for (int i = 0; i < 8; i++) {
        snprintf(sha_hex + (i * 2), 3, "%02x", app->app_elf_sha256[i]);
    }
    sha_hex[16] = '\0';

    int n = snprintf(out, max_len, 
                     "{\"secure_boot\":%s,\"app_version\":\"%s\",\"app_sha\":\"%s\"}",
                     s_enabled ? "true" : "false",
                     app->version,
                     sha_hex);
                     
    return (n < 0 || (size_t)n >= max_len) ? ESP_ERR_NO_MEM : ESP_OK;
}
