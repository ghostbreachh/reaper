#ifndef FT_ROAM_H
#define FT_ROAM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FT_MAX_TARGETS 16

typedef struct {
    uint8_t bssid[6];
    uint8_t channel;
    uint8_t mobility_domain;
    bool valid;
} ft_target_t;

esp_err_t ft_roam_init(void);
void ft_roam_record_target(const uint8_t *bssid, uint8_t channel,
                            uint8_t mobility_domain);
size_t ft_roam_targets(ft_target_t *out, size_t max);
bool ft_roam_inject_reassoc_request(const uint8_t *src_bssid,
                                    const uint8_t *dst_bssid);

#ifdef __cplusplus
}
#endif
#endif
