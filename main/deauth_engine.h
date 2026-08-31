#ifndef DEAUTH_ENGINE_H
#define DEAUTH_ENGINE_H

#include "common_types.h"

esp_err_t deauth_init(void);
esp_err_t deauth_add_target(const uint8_t *bssid, const uint8_t *client_mac, uint32_t count, uint32_t delay_ms);
esp_err_t deauth_start(void);
void deauth_stop(void);
bool deauth_is_active(void);
void deauth_remove_all(void);
esp_err_t deauth_attack_ap_all_clients(const uint8_t *bssid, uint32_t count, uint32_t delay_ms);

/*
 * Fallback chain control.
 * Returns true if the target has already exhausted primary deauth and
 * escalated to disassoc/auth-flood stages.
 */
bool deauth_has_escalated(const uint8_t *bssid);
const char *deauth_fallback_level_name(deauth_fallback_t level);

extern deauth_target_t g_deauth_targets[MAX_TARGET_APS];
extern int g_deauth_target_count;

#endif // DEAUTH_ENGINE_H
