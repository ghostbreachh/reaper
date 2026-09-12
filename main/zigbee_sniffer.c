#include "zigbee_sniffer.h"

#include <stdatomic.h>

#include "esp_log.h"

static const char *TAG = "zigbee_sniffer";

static atomic_bool s_active = false;
static atomic_uint s_channel = 11;
static atomic_uint s_packet_count = 0;

esp_err_t zigbee_sniffer_init(void)
{
    atomic_store(&s_active, false);
    atomic_store(&s_channel, 11);
    atomic_store(&s_packet_count, 0);

    ESP_LOGI(TAG,
             "Zigbee sniffer stub initialized "
             "(requires 802.15.4 radio, e.g. ESP32-H2/C6)");

    return ESP_OK;
}

esp_err_t zigbee_sniffer_start(uint8_t channel)
{
    if (channel < ZIGBEE_SNIFFER_MIN_CHANNEL ||
        channel > ZIGBEE_SNIFFER_MAX_CHANNEL) {
        ESP_LOGW(TAG, "Invalid Zigbee channel: %u", (unsigned)channel);
        return ESP_ERR_INVALID_ARG;
    }

    if (atomic_load(&s_active)) {
        return ESP_ERR_INVALID_STATE;
    }

    atomic_store(&s_channel, channel);

    ESP_LOGI(TAG,
             "Zigbee sniffer start requested on channel %u "
             "(no 802.15.4 radio on ESP32-S3)",
             (unsigned)channel);

    return ESP_ERR_NOT_SUPPORTED;
}

esp_err_t zigbee_sniffer_stop(void)
{
    if (!atomic_load(&s_active)) {
        return ESP_OK;
    }

    atomic_store(&s_active, false);

    ESP_LOGI(TAG, "Zigbee sniffer stopped");
    return ESP_OK;
}

bool zigbee_sniffer_is_active(void)
{
    return atomic_load(&s_active);
}

size_t zigbee_sniffer_get_packets(uint8_t *out, size_t max)
{
    (void)out;
    (void)max;

    /*
     * No 802.15.4 hardware on ESP32-S3.
     * Future implementation should copy queued 802.15.4 frames here.
     */
    return 0;
}

void zigbee_sniffer_clear(void)
{
    atomic_store(&s_packet_count, 0);

    /*
     * Future implementation should clear the packet queue here.
     * Clearing should not stop capture; use zigbee_sniffer_stop() for that.
     */
}
