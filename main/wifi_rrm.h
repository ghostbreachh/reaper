#ifndef WIFI_RRM_H
#define WIFI_RRM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Maximum neighbor entries returned by wifi_rrm_parse_beacon().
 */
#define WIFI_RRM_MAX_NEIGHBORS 8

/*
 * Parse Neighbor Report IEs from a beacon/probe response IE stream.
 *
 * Important:
 *   ies must point to IEs only.
 *
 *   Probe request:        frame + 24
 *   Beacon/Probe Response: frame + 36
 */
bool wifi_rrm_parse_beacon(const uint8_t *ies,
                           size_t len,
                           neighbor_entry_t *out_nbrs,
                           uint8_t *out_nbr_count);

/*
 * Detect BSS Transition capability from Extended Capabilities IE.
 *
 * Expects IEs only.
 */
bool wifi_rrm_parse_btm(const uint8_t *ies, size_t len);

/*
 * Check RRM capability from a full beacon/probe response frame.
 *
 * frame must start with the 802.11 Frame Control field.
 */
bool wifi_rrm_capable(const uint8_t *frame, size_t len);

/*
 * Check RRM capability from beacon/probe response fixed body,
 * i.e. after the 24-byte MAC header:
 *
 *   timestamp [8]
 *   beacon interval [2]
 *   capability info [2]
 */
bool wifi_rrm_capable_from_fixed_body(const uint8_t *body, size_t len);

/*
 * Check RRM capability from IEs by looking for RM Enabled Capabilities.
 */
bool wifi_rrm_capable_from_ies(const uint8_t *ies, size_t len);

/*
 * Parse Multiple BSSID element.
 *
 * This is conservative:
 *   - detects Multi-BSSID presence
 *   - extracts MaxBSSID indicator
 *   - assumes current frame BSSID is transmitted BSSID
 */
bool wifi_mbssid_parse(const uint8_t *ies,
                       size_t len,
                       bool *out_multi,
                       bool *out_transmitted,
                       uint8_t *out_max_bssid_ind,
                       uint8_t *out_bssid_idx);

/*
 * Parse HE Capabilities element.
 *
 * out_mcs_nss:
 *   bits 0-3 = NSS count
 *   bits 4-7 = max MCS index approximation
 *
 * out_ppdu_type:
 *   0 = unknown
 */
bool wifi_he_parse(const uint8_t *ies,
                   size_t len,
                   bool *out_he_capable,
                   uint8_t *out_mcs_nss,
                   uint8_t *out_ppdu_type);

/*
 * Parse Country IE.
 *
 * out_country_code must be at least 3 bytes.
 */
bool wifi_country_parse(const uint8_t *ies,
                        size_t len,
                        char *out_country_code,
                        size_t cc_sz,
                        uint8_t *out_reg_class,
                        uint8_t *out_max_tx_power);

#ifdef __cplusplus
}
#endif

#endif /* WIFI_RRM_H */
