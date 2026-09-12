#include "platform_factory_test.h"

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_mac.h"

static atomic_int s_state = FACTORY_TEST_IDLE;
static const char *TAG = "factory_test";

esp_err_t factory_test_init(void)
{
    atomic_store(&s_state, FACTORY_TEST_IDLE);
    ESP_LOGI(TAG, "Factory test mode initialized");
    return ESP_OK;
}

esp_err_t factory_test_run(void)
{
    if (atomic_load(&s_state) == FACTORY_TEST_RUNNING) {
        return ESP_ERR_INVALID_STATE;
    }
    
    atomic_store(&s_state, FACTORY_TEST_RUNNING);
    ESP_LOGI(TAG, "Running factory self-test...");

    bool pass = true;
    char fail_reason[64] = "";

    /* 1. Check Chip Info */
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    if (chip_info.cores == 0) {
        pass = false;
        snprintf(fail_reason, sizeof(fail_reason), "Chip info read failed");
    }

    /* 2. Check Flash Size */
    uint32_t flash_size = 0;
    if (esp_flash_get_size(NULL, &flash_size) != ESP_OK || flash_size == 0) {
        pass = false;
        snprintf(fail_reason, sizeof(fail_reason), "Flash size read failed");
    }

    /* 3. Check PSRAM (ESP32-S3 N16R8 should have 8MB, but we just check presence) */
    size_t psram_size = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    if (psram_size == 0) {
        ESP_LOGW(TAG, "PSRAM not detected or disabled");
        /* Not necessarily a hard fail depending on target, but log it */
    }

    /* 4. Check MAC Address */
    uint8_t mac[6];
    if (esp_read_mac(mac, ESP_MAC_WIFI_STA) != ESP_OK) {
        pass = false;
        snprintf(fail_reason, sizeof(fail_reason), "MAC read failed");
    }

    if (pass) {
        atomic_store(&s_state, FACTORY_TEST_PASS);
        ESP_LOGI(TAG, "Factory test passed");
        return ESP_OK;
    } else {
        atomic_store(&s_state, FACTORY_TEST_FAIL);
        ESP_LOGE(TAG, "Factory test failed: %s", fail_reason);
        return ESP_FAIL;
    }
}

factory_test_state_t factory_test_get_state(void)
{
    return (factory_test_state_t)atomic_load(&s_state);
}

size_t factory_test_results(char *out, size_t max_len)
{
    if (!out || max_len == 0) return 0;
    
    const char *state_str = "idle";
    factory_test_state_t st = factory_test_get_state();
    
    if (st == FACTORY_TEST_RUNNING) state_str = "running";
    else if (st == FACTORY_TEST_PASS) state_str = "pass";
    else if (st == FACTORY_TEST_FAIL) state_str = "fail";
    
    /* Fixed JSON format string */
    int n = snprintf(out, max_len, "{\"state\":\"%s\"}", state_str);
    
    return (n > 0 && (size_t)n < max_len) ? (size_t)n : 0;
}
