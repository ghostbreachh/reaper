#include "sae_sidechannel.h"
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_timer.h"

static sae_sample_t s_samples[SAE_SAMPLES_MAX];
static size_t s_count = 0;
static bool s_init = false;
static const char *TAG = "sae_sc";

esp_err_t sae_sidechannel_init(void)
{
    memset(s_samples, 0, sizeof(s_samples));
    s_count = 0;
    s_init = true;
    ESP_LOGI(TAG, "SAE side-channel collector initialized");
    return ESP_OK;
}

void sae_sidechannel_record(uint32_t t_us, bool commit)
{
    if (!s_init || s_count >= SAE_SAMPLES_MAX) return;
    s_samples[s_count].t_us = t_us;
    s_samples[s_count].commit = commit;
    s_samples[s_count].rssi = 0;
    s_samples[s_count].ts_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);
    s_count++;
}

size_t sae_sidechannel_collect(sae_sample_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_count < max ? s_count : max;
    memcpy(out, s_samples, n * sizeof(sae_sample_t));
    return n;
}

float sae_sidechannel_entropy(void)
{
    if (s_count < 4) return 0.0f;
    uint32_t sum = 0;
    for (size_t i = 0; i < s_count; i++) sum += s_samples[i].t_us;
    float mean = (float)sum / (float)s_count;
    float var = 0.0f;
    for (size_t i = 0; i < s_count; i++) {
        float d = (float)s_samples[i].t_us - mean;
        var += d * d;
    }
    return var / (float)s_count;
}

void sae_sidechannel_clear(void)
{
    memset(s_samples, 0, sizeof(s_samples));
    s_count = 0;
}
