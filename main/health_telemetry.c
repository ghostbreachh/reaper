/*
 * ============================================================================
 *  health_telemetry.c  —  Health telemetry: heap, PSRAM, CPU temp, uptime
 * ============================================================================
 *
 *  Provides periodic health metrics collection and export for the ESP32-S3.
 *
 *  T2T Step 3.2 — Research & Brainstorming
 *
 *  Branch A — Pull from ESP-IDF helpers on demand (heap_caps_get_free_size,
 *             esp_cpu_system_get_time_since_boot, temp_sensor)
 *    Pros: no background task, minimal overhead
 *    Cons: CPU temp is read-time only; no historical tracking; caller must
 *          invoke multiple IDF APIs
 *
 *  Branch B — Background task sampling + JSON export
 *    Pros: can track min-free-heap over time, decoupled from caller
 *    Cons: extra task stack, more RAM for history
 *
 *  Branch C — Module-local atomic state + on-demand JSON export
 *    Pros: no background task needed; atomic read path is lock-free; caller
 *          pulls metrics whenever needed; supports JSON export in one call
 *    Cons: no automatic alerting (that's a future feature)
 *
 *  Decision: ACCEPTED — Branch C
 * ============================================================================
 */

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>

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

/* Internal mutable state, updated by health_telemetry_refresh(). */
static _Atomic uint32_t g_uptime_s   = 0;
static _Atomic uint32_t g_free_heap  = 0;
static _Atomic uint32_t g_free_psram = 0;
static _Atomic int32_t  g_cpu_temp   = -128;   /* sentinel: unread */
static _Atomic uint32_t g_min_heap   = UINT32_MAX;

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
    atomic_store(&g_uptime_s,
                 (uint32_t)(esp_timer_get_time() / 1000000ULL));
    atomic_store(&g_free_heap, heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    atomic_store(&g_free_psram,
                 heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

#if HEALTH_HAS_TSENS
    temperature_sensor_handle_t h = NULL;
    esp_err_t rc = temperature_sensor_install(
        TEMPERATURE_SENSOR_USE_INTERNAL, &h);
    if (rc == ESP_OK && h != NULL) {
        float tsens_val = 0.0f;
        rc = temperature_sensor_get_celsius(h, &tsens_val);
        if (rc == ESP_OK) {
            atomic_store(&g_cpu_temp, (int32_t)(tsens_val * 100));
        } else {
            atomic_store(&g_cpu_temp, (int32_t)-128);
        }
        temperature_sensor_uninstall(h);
    } else {
        atomic_store(&g_cpu_temp, (int32_t)-128);
    }
#else
    atomic_store(&g_cpu_temp, (int32_t)-128);
#endif

    uint32_t free = atomic_load(&g_free_heap);
    uint32_t prev = atomic_load(&g_min_heap);
    if (free < prev) {
        atomic_store(&g_min_heap, free);
    }
}

/*============================================================================*/
esp_err_t health_telemetry_init(void)
{
    sample_once();
    atomic_store(&g_min_heap, atomic_load(&g_free_heap));

    ESP_LOGI(TAG, "init ok  heap=%u PSRAM=%u",
             (unsigned)atomic_load(&g_free_heap),
             (unsigned)atomic_load(&g_free_psram));
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

    int n = snprintf(buf, bufsz,
        "{\"uptime_s\":%u,\"free_heap\":%u,\"free_psram\":%u,"
        "\"cpu_temp_c\":%.2f,\"min_free_heap\":%u}",
        m.uptime_s, m.free_heap, m.free_psram,
        (float)m.cpu_temp / 100.0f, m.min_free_heap);

    if (n < 0 || (size_t)n >= bufsz) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
