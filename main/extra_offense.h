#ifndef EXTRA_OFFENSE_H
#define EXTRA_OFFENSE_H

#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t probe_flood_start(const char *ssid, uint32_t count, uint8_t channel);
void probe_flood_stop(void);

esp_err_t deauth_on_join_start(const uint8_t *bssid);
void deauth_on_join_stop(void);
void doj_feed(const uint8_t *data, size_t len);

const char *oui_lookup(const uint8_t *mac);
void channel_analyzer_run(uint32_t seconds_per_channel);

#ifdef __cplusplus
}
#endif

#endif // EXTRA_OFFENSE_H
