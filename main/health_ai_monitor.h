#ifndef HEALTH_AI_MONITOR_H
#define HEALTH_AI_MONITOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HEALTH_AI_STATE_OK = 0,
    HEALTH_AI_STATE_WARNING,
    HEALTH_AI_STATE_CRITICAL,
    HEALTH_AI_STATE_HEALING
} health_ai_state_t;

typedef struct {
    uint32_t free_heap;
    uint32_t free_psram;
    int32_t cpu_temp_c;
    uint32_t uptime_s;
    uint32_t wifi_task_load;
    uint32_t ble_task_load;
    health_ai_state_t state;
    char reason[64];
} health_ai_metrics_t;

esp_err_t health_ai_monitor_init(void);
esp_err_t health_ai_monitor_update(void);
health_ai_state_t health_ai_monitor_state(void);
esp_err_t health_ai_monitor_json(char *out, size_t max);
bool health_ai_monitor_should_heal(void);
esp_err_t health_ai_monitor_heal(void);

#ifdef __cplusplus
}
#endif
#endif
