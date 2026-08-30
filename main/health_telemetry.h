#ifndef HEALTH_TELEMETRY_H
#define HEALTH_TELEMETRY_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t uptime_s;
    uint32_t free_heap;
    uint32_t free_psram;
    int32_t  cpu_temp_c;
    uint32_t min_free_heap;
} health_metrics_t;

esp_err_t health_telemetry_init(void);
esp_err_t health_telemetry_get(health_metrics_t *out);
esp_err_t health_telemetry_json_export(char *buf, size_t bufsz);
void      health_telemetry_task_refresh(void);

#ifdef __cplusplus
}
#endif

#endif /* HEALTH_TELEMETRY_H */
