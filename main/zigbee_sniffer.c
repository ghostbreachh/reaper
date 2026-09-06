#include "zigbee_sniffer.h"
#include "esp_log.h"

static bool s_active = false;
static uint8_t s_channel = 11;
static const char *TAG = "zigbee_sniffer";

esp_err_t zigbee_sniffer_init(void)
{
    s_active = false;
    s_channel = 11;
    ESP_LOGI(TAG, "Zigbee sniffer stub initialized "
                  "(requires 802.15.4 radio, e.g. ESP32-H2/C6)");
    return ESP_OK;
}

esp_err_t zigbee_sniffer_start(uint8_t channel)
{
    if (s_active) return ESP_ERR_INVALID_STATE;
    s_channel = channel;
    ESP_LOGI(TAG, "Zigbee sniffer start requested on channel %d "
                  "(no 802.15.4 radio on ESP32-S3)", channel);
    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t zigbee_sniffer_stop(void)
{
    s_active = false;
    ESP_LOGI(TAG, "Zigbee sniffer stopped");
    return ESP_OK;
}

bool zigbee_sniffer_is_active(void)
{
    return s_active;
}

size_t zigbee_sniffer_get_packets(uint8_t *out, size_t max)
{
    (void)out; (void)max;
    return 0;
}

void zigbee_sniffer_clear(void)
{
    s_active = false;
}
