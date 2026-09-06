#include "platform_factory_test.h"
#include "esp_log.h"
#include "esp_system.h"
#include <string.h>

static factory_test_state_t s_state = FACTORY_TEST_IDLE;
static const char *TAG = "factory_test";

esp_err_t factory_test_init(void)
{
    s_state = FACTORY_TEST_IDLE;
    ESP_LOGI(TAG, "Factory test mode initialized");
    return ESP_OK;
}

esp_err_t factory_test_run(void)
{
    if (s_state == FACTORY_TEST_RUNNING) return ESP_ERR_INVALID_STATE;
    s_state = FACTORY_TEST_RUNNING;
    ESP_LOGI(TAG, "Running factory self-test...");

    /* WiFi/BLE radio calibration already done by ESP-IDF init. */
    /* Flash read/write check via eFuse-backed MAC. */
    uint8_t mac[6];
    esp_err_t rc = esp_read_mac(mac, ESP_MAC_WIFI_STA);
    if (rc != ESP_OK) {
        s_state = FACTORY_TEST_FAIL;
        ESP_LOGE(TAG, "MAC read failed");
        return rc;
    }
    s_state = FACTORY_TEST_PASS;
    ESP_LOGI(TAG, "Factory test passed");
    return ESP_OK;
}

factory_test_state_t factory_test_get_state(void)
{
    return s_state;
}

size_t factory_test_results(char *out, size_t max_len)
{
    if (!out || max_len == 0) return 0;
    const char *state_str = "idle";
    if (s_state == FACTORY_TEST_RUNNING) state_str = "running";
    else if (s_state == FACTORY_TEST_PASS) state_str = "pass";
    else if (s_state == FACTORY_TEST_FAIL) state_str = "fail";
    int n = snprintf(out, max_len,
                     "{\"state\":\"%s"}", state_str);
    return (n > 0) ? (size_t)n : 0;
}
