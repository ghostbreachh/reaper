#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCHED_MAX_ENTRIES 8

/* Schedule entry action type. */
typedef enum {
    SCHED_ACTION_WIFI_START = 0,
    SCHED_ACTION_WIFI_STOP,
    SCHED_ACTION_STEALTH_SET_MODE,
    SCHED_ACTION_WARDRIVE_START,
    SCHED_ACTION_WARDRIVE_STOP,
    SCHED_ACTION_AI_TRAIN_START,
    SCHED_ACTION_AI_TRAIN_STOP,
    SCHED_ACTION_CUSTOM_JSONRPC
} sched_action_t;

/* One scheduled entry. */
typedef struct {
    bool enabled;
    uint8_t minute;      /* 0-59 */
    uint8_t hour;        /* 0-23 */
    uint8_t day_of_week; /* bitmask: bit0=Monday ... bit6=Sunday, bit7=any */
    sched_action_t action;
    char params[128];    /* action-specific string, e.g. "passive" or "both" */
} sched_entry_t;

/* Scheduler statistics. */
typedef struct {
    uint32_t total_entries;
    uint32_t enabled_entries;
    uint32_t last_fire_count;
    uint64_t last_fire_us;
} sched_stats_t;

/* Initialize scheduler and restore schedule from NVS. */
esp_err_t scheduler_init(void);

/* Add a new entry; returns index or negative error. */
int scheduler_add(const sched_entry_t *entry);

/* Remove entry by index. */
esp_err_t scheduler_remove(uint8_t index);

/* Update an existing entry. */
esp_err_t scheduler_update(uint8_t index, const sched_entry_t *entry);

/* Get entry by index. */
esp_err_t scheduler_get(uint8_t index, sched_entry_t *out);

/* List all entries as JSON array string. */
esp_err_t scheduler_json(char *buf, size_t bufsz);

/* Get stats. */
esp_err_t scheduler_get_stats(sched_stats_t *out);

/* Save current schedule to NVS. */
esp_err_t scheduler_save(void);

/* Deinit. */
esp_err_t scheduler_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* SCHEDULER_H */
