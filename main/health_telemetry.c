/*
 * ============================================================================
 *  health_telemetry.c  —  Health telemetry: heap, PSRAM, CPU temp, uptime
 * ============================================================================
 */

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>
#include <limits.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_cpu.h"
#include "esp_timer.h"
#include "esp_log.h"

/* CPU temp sensor requires esp_driver_tsens; gracefully disable if missing. */
#if __has_include("driver/temperature_sensor.h")
#include "driver/temperature_sensor.h"
#define HEALTH_HAS_TSENS 1
#else
#define HEALTH_HAS_TSENS 0
#endif

#include "health_telemetry.h"

static const char *TAG = "health";

/* Internal mutable state, updated by sample_once(). */
static atomic_uint g_uptime_s   = ATOMIC_VAR_INIT(0);
static atomic_uint g_free_heap  = ATOMIC_VAR_INIT(0);
static atomic_uint g_free_psram = ATOMIC_VAR_INIT(0);
static atomic_int  g_cpu_temp   = ATOMIC_VAR_INIT(INT32_MIN);   /* sentinel: unread */
static atomic_uint g_min_heap   = ATOMIC_VAR_INIT(UINT32_MAX);

#if HEALTH_HAS_TSENS
static temperature_sensor_handle_t g_tsens_handle = NULL;
#endif

/*============================================================================*/
static void health_snapshot(health_metrics_t *out)
{
    out->uptime_s      = atomic_load(&g_uptime_s);
    out->free_heap     = atomic_load(&g_free_heap);
    out->free_psram    = atomic_load(&g_free_psram);
    out->cpu_temp_c    = atomic_load(&g_cpu_temp);
    out->min_free_heap = atomic_load(&g_min_heap);
}

/*============================================================================*/
static void sample_once(void)
{
    atomic_store(&g_uptime_s, (unsigned)(esp_timer_get_time() / 1000000ULL));
    atomic_store(&g_free_heap, (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    atomic_store(&g_free_psram, (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

#if HEALTH_HAS_TSENS
    if (g_tsens_handle != NULL) {
        float tsens_val = 0.0f;
        esp_err_t rc = temperature_sensor_get_celsius(g_tsens_handle, &tsens_val);
        if (rc == ESP_OK) {
            atomic_store(&g_cpu_temp, (int)(tsens_val * 100.0f));
        }
    }
#endif

    unsigned free = atomic_load(&g_free_heap);
    unsigned prev = atomic_load(&g_min_heap);
    if (free < prev) {
        atomic_store(&g_min_heap, free);
    }
}

/*============================================================================*/
esp_err_t health_telemetry_init(void)
{
#if HEALTH_HAS_TSENS
    if (g_tsens_handle == NULL) {
        temperature_sensor_config_t tsens_config = {
            .range_min = 20,
            .range_max = 100,
        };
        
        esp_err_t rc = temperature_sensor_install(&tsens_config, &g_tsens_handle);
        if (rc == ESP_OK && g_tsens_handle != NULL) {
            temperature_sensor_enable(g_tsens_handle);
            ESP_LOGI(TAG, "Temperature sensor installed and enabled");
        } else {
            ESP_LOGW(TAG, "Failed to install temperature sensor: %s", esp_err_to_name(rc));
            g_tsens_handle = NULL;
        }
    }
#endif

    sample_once();
    atomic_store(&g_min_heap, atomic_load(&g_free_heap));

    ESP_LOGI(TAG, "init ok  heap=%u PSRAM=%u",
             atomic_load(&g_free_heap),
             atomic_load(&g_free_psram));
    return ESP_OK;
}

/*============================================================================*/
void health_telemetry_task_refresh(void)
{
    sample_once();
}

/*============================================================================*/
esp_err_t health_telemetry_get(health_metrics_t *out)
{
    if (!out) {
        return ESP_ERR_INVALID_ARG;
    }
    sample_once();
    health_snapshot(out);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t health_telemetry_json_export(char *buf, size_t bufsz)
{
    if (!buf || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    health_metrics_t m;
    sample_once();
    health_snapshot(&m);

    int n;
    if (m.cpu_temp_c == INT32_MIN) {
        n = snprintf(buf, bufsz,
            "{\"uptime_s\":%u,\"free_heap\":%u,\"free_psram\":%u,"
            "\"cpu_temp_c\":null,\"min_free_heap\":%u}",
            m.uptime_s, m.free_heap, m.free_psram, m.min_free_heap);
    } else {
        n = snprintf(buf, bufsz,
            "{\"uptime_s\":%u,\"free_heap\":%u,\"free_psram\":%u,"
            "\"cpu_temp_c\":%.2f,\"min_free_heap\":%u}",
            m.uptime_s, m.free_heap, m.free_psram,
            (float)m.cpu_temp_c / 100.0f, m.min_free_heap);
    }

    if (n < 0 || (size_t)n >= bufsz) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
