#ifndef WIFI_RRM_H
#define WIFI_RRM_H

#include <stdint.h>
#include <stdbool.h>
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

bool wifi_rrm_parse_beacon(const uint8_t *ies, size_t len,
                           neighbor_entry_t *out_nbrs, uint8_t *out_nbr_count);
bool wifi_rrm_parse_btm(const uint8_t *ies, size_t len);
bool wifi_rrm_capable(const uint8_t *frame, size_t len);
bool wifi_mbssid_parse(const uint8_t *ies, size_t len,
                       bool *out_multi, bool *out_transmitted,
                       uint8_t *out_max_bssid_ind, uint8_t *out_bssid_idx);
bool wifi_he_parse(const uint8_t *ies, size_t len,
                   bool *out_he_capable, uint8_t *out_mcs_nss, uint8_t *out_ppdu_type);

#ifdef __cplusplus
}
#endif
#endif /* WIFI_RRM_H */
