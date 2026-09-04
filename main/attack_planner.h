#ifndef ATTACK_PLANNER_H
#define ATTACK_PLANNER_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Attack step type. */
typedef enum {
    ATTACK_STEP_NONE = 0,
    ATTACK_STEP_DEAUTH,
    ATTACK_STEP_DISASSOC,
    ATTACK_STEP_AUTH_FLOOD,
    ATTACK_STEP_HANDSHAKE_CAPTURE,
    ATTACK_STEP_PMKID_CAPTURE,
    ATTACK_STEP_OFFLINE_CRACK,
    ATTACK_STEP_EVIL_TWIN,
    ATTACK_STEP_BEACON_FLOOD
} attack_step_t;

/* Attack plan for one target. */
typedef struct {
    char bssid[18];
    char ssid[33];
    uint8_t channel;
    uint8_t security; /* 0=open, 1=WEP, 2=WPA, 3=WPA2, 4=WPA3 */
    bool pmf_required;
    float score; /* 0.0 = worthless, 1.0 = perfect target */
    char warning[128];
    uint8_t step_count;
    attack_step_t steps[6];
    char summary[160];
} attack_plan_t;

/* Target scoring result. */
typedef struct {
    uint32_t ap_count;
    uint32_t viable_count;
    uint32_t best_idx;
    float best_score;
} planner_stats_t;

/* Initialize attack planner. */
esp_err_t attack_planner_init(void);

/* Build an attack plan for the AP at given index. */
esp_err_t attack_planner_build_plan(uint32_t ap_index, attack_plan_t *out);

/* Auto-select the best target. */
esp_err_t attack_planner_best_target(uint32_t *out_index);

/* Get planner statistics. */
esp_err_t attack_planner_get_stats(planner_stats_t *out);

/* Export stats as JSON. */
esp_err_t attack_planner_json(char *buf, size_t bufsz);

/* Deinit. */
esp_err_t attack_planner_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* ATTACK_PLANNER_H */
