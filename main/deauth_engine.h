#ifndef DEAUTH_ENGINE_H
#define DEAUTH_ENGINE_H

#include "common_types.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t deauth_init(void);
esp_err_t deauth_add_target(const uint8_t *bssid, const uint8_t *client_mac, uint32_t count, uint32_t delay_ms, deauth_mode_t mode);
esp_err_t deauth_start(void);
void deauth_stop(void);
bool deauth_is_active(void);
void deauth_remove_all(void);
esp_err_t deauth_attack_ap_all_clients(const uint8_t *bssid, uint32_t count, uint32_t delay_ms);

bool deauth_has_escalated(const uint8_t *bssid);
const char *deauth_fallback_level_name(deauth_fallback_t level);

#ifdef __cplusplus
}
#endif

#endif // DEAUTH_ENGINE_H
