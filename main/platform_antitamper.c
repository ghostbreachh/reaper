#include "platform_antitamper.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "nvs.h"

static bool s_ok = true;
static const char *TAG = "antitamper";

esp_err_t platform_antitamper_init(void)
{
    s_ok = true;
    ESP_LOGI(TAG, "Anti-tamper checks initialized");
    return ESP_OK;
}

bool platform_antitamper_check(void)
{
    /* Verify NVS partition is readable and not factory-erased. */
    nvs_handle_t h = 0;
    esp_err_t rc = nvs_open("storage", NVS_READONLY, &h);
    if (rc != ESP_OK) {
        ESP_LOGW(TAG, "NVS read failed: 0x%x", rc);
        s_ok = false;
        return false;
    }
    nvs_close(h);
    s_ok = true;
    return true;
}

esp_err_t platform_antitamper_get_report(char *out, size_t max_len)
{
    if (!out || max_len == 0) return ESP_ERR_INVALID_ARG;
    snprintf(out, max_len,
             "{\"nvs_ok\":%s}", s_ok ? "true" : "false");
    return ESP_OK;
}
