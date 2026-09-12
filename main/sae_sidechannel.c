#include "sae_sidechannel.h"

#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <math.h>

#include "esp_log.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "sae_sc";

static sae_sample_t s_samples[SAE_SAMPLES_MAX];
static size_t s_count = 0;
static atomic_bool s_init = ATOMIC_VAR_INIT(false);
static SemaphoreHandle_t s_lock = NULL;

esp_err_t sae_sidechannel_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
        if (s_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    memset(s_samples, 0, sizeof(s_samples));
    s_count = 0;
    xSemaphoreGive(s_lock);

    atomic_store(&s_init, true);
    ESP_LOGI(TAG, "SAE side-channel collector initialized");
    return ESP_OK;
}

void sae_sidechannel_record(uint32_t t_us, bool commit)
{
    if (!atomic_load(&s_init) || s_lock == NULL) return;

    /* Non-blocking: drop sample if lock is contended to avoid stalling the sniffer */
    if (xSemaphoreTake(s_lock, 0) != pdTRUE) return;

    if (s_count >= SAE_SAMPLES_MAX) {
        xSemaphoreGive(s_lock);
        return;
    }

    s_samples[s_count].t_us = t_us;
    s_samples[s_count].commit = commit;
    s_samples[s_count].rssi = 0;
    s_samples[s_count].ts_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);
    s_count++;

    xSemaphoreGive(s_lock);
}

size_t sae_sidechannel_collect(sae_sample_t *out, size_t max)
{
    if (!out || max == 0 || !atomic_load(&s_init) || s_lock == NULL) return 0;

    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE) return 0;

    size_t n = (s_count < max) ? s_count : max;
    memcpy(out, s_samples, n * sizeof(sae_sample_t));

    xSemaphoreGive(s_lock);
    return n;
}

float sae_sidechannel_entropy(void)
{
    if (!atomic_load(&s_init) || s_lock == NULL) return 0.0f;

    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE) return 0.0f;

    size_t count = s_count;
    if (count < 2) {
        xSemaphoreGive(s_lock);
        return 0.0f;
    }

    /* Copy samples to stack to release lock quickly */
    sae_sample_t local_samples[SAE_SAMPLES_MAX];
    memcpy(local_samples, s_samples, count * sizeof(sae_sample_t));
    xSemaphoreGive(s_lock);

    /* 
     * Calculate variance of inter-arrival deltas.
     * This measures timing jitter, which is the relevant side-channel metric.
     */
    uint32_t deltas[SAE_SAMPLES_MAX - 1];
    for (size_t i = 1; i < count; i++) {
        deltas[i - 1] = local_samples[i].t_us - local_samples[i - 1].t_us;
    }

    size_t delta_count = count - 1;
    uint32_t sum = 0;
    for (size_t i = 0; i < delta_count; i++) {
        sum += deltas[i];
    }

    float mean = (float)sum / (float)delta_count;
    float var = 0.0f;

    for (size_t i = 0; i < delta_count; i++) {
        float d = (float)deltas[i] - mean;
        var += d * d;
    }

    return var / (float)delta_count;
}

void sae_sidechannel_clear(void)
{
    if (!atomic_load(&s_init) || s_lock == NULL) return;

    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE) return;

    memset(s_samples, 0, sizeof(s_samples));
    s_count = 0;

    xSemaphoreGive(s_lock);
}
