#include "platform_antitamper.h"

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_partition.h"
#if __has_include("esp_secure_boot.h")
#include "esp_secure_boot.h"
#else
static inline bool esp_secure_boot_enabled(void) { return false; }
#endif
#if __has_include("esp_flash_encrypt.h")
#include "esp_flash_encrypt.h"
#else
static inline bool esp_flash_encryption_enabled(void) { return false; }
#endif
#if __has_include("esp_efuse.h")
#include "esp_efuse.h"
#endif

#include "nvs.h"

static atomic_bool s_ok = ATOMIC_VAR_INIT(true);
static atomic_bool s_nvs_ok = ATOMIC_VAR_INIT(true);
static atomic_bool s_secure_boot_ok = ATOMIC_VAR_INIT(false);
static atomic_bool s_flash_enc_ok = ATOMIC_VAR_INIT(false);
static const char *TAG = "antitamper";

esp_err_t platform_antitamper_init(void)
{
    atomic_store(&s_ok, true);
    atomic_store(&s_nvs_ok, true);
    atomic_store(&s_secure_boot_ok, esp_secure_boot_enabled());
    #if __has_include("esp_efuse.h")
    atomic_store(&s_flash_enc_ok, esp_efuse_is_flash_encryption_enabled());
#else
    atomic_store(&s_flash_enc_ok, esp_flash_encryption_enabled());
#endif
    
    ESP_LOGI(TAG, "Anti-tamper checks initialized (SB:%d, FE:%d)", 
             atomic_load(&s_secure_boot_ok), atomic_load(&s_flash_enc_ok));
    return ESP_OK;
}

bool platform_antitamper_check(void)
{
    bool ok = true;
    
    /* 1. Verify NVS partition is readable */
    nvs_handle_t h = 0;
    esp_err_t rc = nvs_open("storage", NVS_READONLY, &h);
    if (rc != ESP_OK) {
        ESP_LOGW(TAG, "NVS read failed: 0x%x", rc);
        atomic_store(&s_nvs_ok, false);
        ok = false;
    } else {
        nvs_close(h);
        atomic_store(&s_nvs_ok, true);
    }
    
    /* 2. Verify Secure Boot (if expected) */
    if (!atomic_load(&s_secure_boot_ok)) {
        ESP_LOGW(TAG, "Secure boot is not enabled");
        /* Depending on your security policy, you might want to set ok = false here */
    }
    
    /* 3. Verify Flash Encryption */
    if (!atomic_load(&s_flash_enc_ok)) {
        ESP_LOGW(TAG, "Flash encryption is not enabled");
    }
    
    atomic_store(&s_ok, ok);
    return ok;
}

esp_err_t platform_antitamper_get_report(char *out, size_t max_len)
{
    if (!out || max_len == 0) return ESP_ERR_INVALID_ARG;
    
    int n = snprintf(out, max_len,
                     "{\"nvs_ok\":%s,\"secure_boot\":%s,\"flash_encryption\":%s}", 
                     atomic_load(&s_nvs_ok) ? "true" : "false",
                     atomic_load(&s_secure_boot_ok) ? "true" : "false",
                     atomic_load(&s_flash_enc_ok) ? "true" : "false");
                     
    return (n < 0 || (size_t)n >= max_len) ? ESP_ERR_NO_MEM : ESP_OK;
}
