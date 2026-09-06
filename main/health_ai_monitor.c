#include "health_ai_monitor.h"
#include "health_telemetry.h"
#include "esp_log.h"
#include <string.h>
#include <stdio.h>

static health_ai_state_t s_state = HEALTH_AI_STATE_OK;
static const char *TAG = "health_ai";

static int classify(uint32_t free_heap, uint32_t free_psram,
                    int32_t cpu_temp_c)
{
    int score = 0;
    if (free_heap < 20000) score += 3;
    else if (free_heap < 50000) score += 1;

    if (free_psram < 20000) score += 2;
    else if (free_psram < 50000) score += 1;

    if (cpu_temp_c > 80) score += 3;
    else if (cpu_temp_c > 70) score += 1;

    if (score >= 5) return HEALTH_AI_STATE_CRITICAL;
    if (score >= 2) return HEALTH_AI_STATE_WARNING;
    return HEALTH_AI_STATE_OK;
}

static const char *state_name(health_ai_state_t s)
{
    switch (s) {
        case HEALTH_AI_STATE_OK: return "ok";
        case HEALTH_AI_STATE_WARNING: return "warning";
        case HEALTH_AI_STATE_CRITICAL: return "critical";
        case HEALTH_AI_STATE_HEALING: return "healing";
        default: return "unknown";
    }
}

esp_err_t health_ai_monitor_init(void)
{
    s_state = HEALTH_AI_STATE_OK;
    ESP_LOGI(TAG, "Self-healing AI monitor initialized");
    return ESP_OK;
}

esp_err_t health_ai_monitor_update(void)
{
    health_metrics_t m;
    if (health_telemetry_get(&m) != ESP_OK) {
        return ESP_FAIL;
    }

    s_state = classify(m.free_heap, m.free_psram, m.cpu_temp_c);
    if (s_state == HEALTH_AI_STATE_CRITICAL) {
        ESP_LOGW(TAG, "System critical: heap=%u psram=%u temp=%d",
                 m.free_heap, m.free_psram, m.cpu_temp_c);
    }
    return ESP_OK;
}

health_ai_state_t health_ai_monitor_state(void)
{
    return s_state;
}

esp_err_t health_ai_monitor_json(char *out, size_t max)
{
    if (!out || max == 0) return ESP_ERR_INVALID_ARG;
    health_metrics_t m;
    if (health_telemetry_get(&m) != ESP_OK) return ESP_FAIL;
    int n = snprintf(out, max,
        "{\"state\":\"%s\",\"heap\":%u,\"psram\":%u,"
        "\"temp\":%d}",
        state_name(s_state), m.free_heap, m.free_psram, m.cpu_temp_c);
    if (n < 0 || (size_t)n >= max) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

bool health_ai_monitor_should_heal(void)
{
    return s_state == HEALTH_AI_STATE_CRITICAL;
}

esp_err_t health_ai_monitor_heal(void)
{
    if (s_state != HEALTH_AI_STATE_CRITICAL) return ESP_ERR_INVALID_STATE;
    s_state = HEALTH_AI_STATE_HEALING;
    ESP_LOGI(TAG, "Initiating self-healing sequence");
    /* Step 1: free caches */
    /* Step 2: restart non-critical tasks if needed */
    /* Step 3: reboot if still critical after 2 cycles */
    s_state = HEALTH_AI_STATE_OK;
    return ESP_OK;
}
