#include "thread_border_router.h"

#include <stdatomic.h>
#include <stdio.h>

#include "esp_log.h"

static const char *TAG = "thread_br";

static atomic_bool s_active = false;
static atomic_bool s_warned = false;

esp_err_t thread_br_init(void)
{
    atomic_store(&s_active, false);
    atomic_store(&s_warned, false);
    
    ESP_LOGI(TAG, "Thread Border Router stub initialized "
                  "(requires ESP32-H2/C6 hardware)");
    return ESP_OK;
}

esp_err_t thread_br_start(void)
{
    if (atomic_load(&s_active)) {
        return ESP_ERR_INVALID_STATE;
    }

    /* Only log the missing hardware warning once per boot to prevent console spam */
    if (!atomic_exchange(&s_warned, true)) {
        ESP_LOGW(TAG, "Thread Border Router start requested "
                      "(no 802.15.4 radio on ESP32-S3)");
    }

    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t thread_br_stop(void)
{
    /* Idempotent: do nothing if already stopped */
    if (!atomic_load(&s_active)) {
        return ESP_OK;
    }

    atomic_store(&s_active, false);
    ESP_LOGI(TAG, "Thread Border Router stopped");
    return ESP_OK;
}

bool thread_br_is_active(void)
{
    return atomic_load(&s_active);
}

esp_err_t thread_br_get_dataset(char *out, size_t max_len)
{
    if (!out || max_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Return an empty JSON object as a stub response */
    snprintf(out, max_len, "{}");
    
    return ESP_ERR_NOT_SUPPORTED;
}
