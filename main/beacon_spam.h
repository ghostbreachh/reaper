#ifndef BEACON_SPAM_H
#define BEACON_SPAM_H

#include "common_types.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_BEACON_SSIDS 30

/* Beacon Spam */
esp_err_t beacon_spam_start(const char **ssids, int count, uint8_t channel, uint32_t interval_ms);
esp_err_t beacon_spam_start_builtin(uint8_t channel);
void beacon_spam_stop(void);
bool beacon_spam_is_active(void);

/* Rogue AP */
esp_err_t rogue_ap_start(const char *ssid, uint8_t channel, bool open);
void rogue_ap_stop(void);
bool rogue_ap_is_active(void);

/* Evil Portal */
esp_err_t evil_portal_start(const char *ssid, uint8_t channel);
void evil_portal_stop(void);
void evil_portal_print_creds(void);

#ifdef __cplusplus
}
#endif

#endif // BEACON_SPAM_H
