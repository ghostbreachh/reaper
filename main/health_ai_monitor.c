#include "health_ai_monitor.h"
#include "health_telemetry.h"

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>
#include <limits.h>

#include "esp_log.h"
#include "esp_heap_caps.h"

static atomic_int s_state = ATOMIC_VAR_INIT(HEALTH_AI_STATE_OK);
static const char *TAG = "health_ai";

static health_ai_state_t classify(uint32_t free_heap, uint32_t free_psram,
                                  int32_t cpu_temp_centi)
{
    int score = 0;
    
    if (free_heap < 20000) score += 3;
    else if (free_heap < 50000) score += 1;

    if (free_psram < 20000) score += 2;
    else if (free_psram < 50000) score += 1;

    /* 
     * Convert centi-degrees to whole degrees. 
     * Handle the INT32_MIN sentinel gracefully.
     */
    int32_t temp_c = (cpu_temp_centi == INT32_MIN) ? 0 : (cpu_temp_centi / 100);

    if (temp_c > 80) score += 3;
    else if (temp_c > 70) score += 1;

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
    atomic_store(&s_state, HEALTH_AI_STATE_OK);
    ESP_LOGI(TAG, "Self-healing AI monitor initialized");
    return ESP_OK;
}

esp_err_t health_ai_monitor_update(void)
{
    health_metrics_t m;
    if (health_telemetry_get(&m) != ESP_OK) {
        return ESP_FAIL;
    }

    health_ai_state_t new_state = classify((unsigned)m.free_heap, (unsigned)m.free_psram, (int)m.cpu_temp_c);
    
    /* Prevent overwriting HEALING state unless the system has recovered to OK */
    health_ai_state_t current = (health_ai_state_t)atomic_load(&s_state);
    if (current == HEALTH_AI_STATE_HEALING && new_state != HEALTH_AI_STATE_OK) {
        return ESP_OK; 
    }

    atomic_store(&s_state, new_state);

    if (new_state == HEALTH_AI_STATE_CRITICAL) {
        ESP_LOGW(TAG, "System critical: heap=%u psram=%u temp=%d",
                 (unsigned)m.free_heap, (unsigned)m.free_psram, (int)m.cpu_temp_c);
    }
    return ESP_OK;
}

health_ai_state_t health_ai_monitor_state(void)
{
    return (health_ai_state_t)atomic_load(&s_state);
}

esp_err_t health_ai_monitor_json(char *out, size_t max)
{
    if (!out || max == 0) return ESP_ERR_INVALID_ARG;
    
    health_metrics_t m;
    if (health_telemetry_get(&m) != ESP_OK) return ESP_FAIL;
    
    health_ai_state_t current = (health_ai_state_t)atomic_load(&s_state);
    
    int n;
    if (m.cpu_temp_c == INT32_MIN) {
        n = snprintf(out, max,
            "{\"state\":\"%s\",\"heap\":%u,\"psram\":%u,\"temp\":null}",
            state_name(current), (unsigned)m.free_heap, (unsigned)m.free_psram);
    } else {
        n = snprintf(out, max,
            "{\"state\":\"%s\",\"heap\":%u,\"psram\":%u,\"temp\":%.1f}",
            state_name(current), (unsigned)m.free_heap, (unsigned)m.free_psram,
            (float)m.cpu_temp_c / 100.0f);
    }
    
    if (n < 0 || (size_t)n >= max) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

bool health_ai_monitor_should_heal(void)
{
    return (health_ai_state_t)atomic_load(&s_state) == HEALTH_AI_STATE_CRITICAL;
}

esp_err_t health_ai_monitor_heal(void)
{
    health_ai_state_t current = (health_ai_state_t)atomic_load(&s_state);
    if (current != HEALTH_AI_STATE_CRITICAL) return ESP_ERR_INVALID_STATE;
    
    atomic_store(&s_state, HEALTH_AI_STATE_HEALING);
    ESP_LOGW(TAG, "Initiating self-healing sequence");
    
    /* 
     * Self-healing stub:
     * In a production system, this would:
     * 1. Clear non-essential caches (e.g., AI model zoo, BLE scanner list)
     * 2. Restart non-critical background tasks
     * 3. Force a garbage collection on the heap
     */
     
    size_t min_free = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    (void)min_free;
    ESP_LOGI(TAG, "Pre-heal min free heap: %u", (unsigned)min_free);
    
    /* TODO: Implement actual cache clearing here */
    
    ESP_LOGI(TAG, "Self-healing sequence complete");
    atomic_store(&s_state, HEALTH_AI_STATE_OK);
    return ESP_OK;
}
