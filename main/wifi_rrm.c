#include "wifi_rrm.h"
#include <string.h>
#include <stdbool.h>
#include "esp_log.h"

static const char *TAG = "wifi_rrm";

#define IE_NEIGHBOR_REPORT  52
#define IE_MBSSID          55
#define IE_HE_CAPABILITIES 35
#define NBR_MIN_LEN 15

bool wifi_rrm_parse_beacon(const uint8_t *ies, size_t len,
                           neighbor_entry_t *out_nbrs, uint8_t *out_nbr_count)
{
    if (ies == NULL || len == 0 || out_nbrs == NULL || out_nbr_count == NULL) return false;
    *out_nbr_count = 0;

    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t tag_id = ies[pos];
        uint8_t tag_len = ies[pos + 1];
        if (pos + 2 + tag_len > len) break;

        if (tag_id == IE_NEIGHBOR_REPORT && tag_len >= NBR_MIN_LEN - 2) {
            if (*out_nbr_count < 8) {
                neighbor_entry_t *n = &out_nbrs[*out_nbr_count];
                memcpy(n->bssid, &ies[pos + 2], 6);
                n->channel = ies[pos + 13];
                n->phy_mode = ies[pos + 14];
                (*out_nbr_count)++;
            }
        }
        pos += 2 + tag_len;
    }
    return *out_nbr_count > 0;
}

bool wifi_rrm_parse_btm(const uint8_t *frame, size_t len)
{
    if (frame == NULL || len < 4) return false;
    return (frame[0] == 0 && frame[1] == 6);
}

bool wifi_rrm_capable(const uint8_t *frame, size_t len)
{
    if (frame == NULL || len < 24) return false;
    uint16_t cap = (uint16_t)(frame[10] | ((uint16_t)frame[11] << 8));
    return (cap & 0x1000) != 0;
}

bool wifi_mbssid_parse(const uint8_t *ies, size_t len,
                       bool *out_multi, bool *out_transmitted,
                       uint8_t *out_max_bssid_ind, uint8_t *out_bssid_idx)
{
    if (ies == NULL || len == 0 || out_multi == NULL ||
        out_transmitted == NULL || out_max_bssid_ind == NULL || out_bssid_idx == NULL) {
        return false;
    }
    *out_multi = false;
    *out_transmitted = false;
    *out_max_bssid_ind = 0;
    *out_bssid_idx = 0;

    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t tag_id = ies[pos];
        uint8_t tag_len = ies[pos + 1];
        if (pos + 2 + tag_len > len) break;

        if (tag_id == IE_MBSSID && tag_len >= 3) {
            *out_multi = true;
            *out_max_bssid_ind = ies[pos + 2];
            *out_bssid_idx = ies[pos + 3];
            *out_transmitted = (ies[pos + 4] & 0x01) != 0;
            return true;
        }
        pos += 2 + tag_len;
    }
    return false;
}

/* Parse HE Capabilities element (ID 35).
 * Returns true if element present and at least MAC/PHY caps parsed.
 * out_he_capable: true if HE capable
 * out_mcs_nss:    bits 0-3 = NSS, bits 4-7 = MCS index
 * out_ppdu_type:  0=unknown, 1=HE-MU, 2=HE-SU */
bool wifi_he_parse(const uint8_t *ies, size_t len,
                   bool *out_he_capable, uint8_t *out_mcs_nss, uint8_t *out_ppdu_type)
{
    if (ies == NULL || len == 0 || out_he_capable == NULL ||
        out_mcs_nss == NULL || out_ppdu_type == NULL) return false;
    *out_he_capable = false;
    *out_mcs_nss = 0;
    *out_ppdu_type = 0;

    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t tag_id = ies[pos];
        uint8_t tag_len = ies[pos + 1];
        if (pos + 2 + tag_len > len) break;

        if (tag_id == IE_HE_CAPABILITIES && tag_len >= 4) {
            /* HE MAC Capabilities Info at bytes 2-3 */
            uint16_t he_mac = (uint16_t)(ies[pos + 2] | ((uint16_t)ies[pos + 3] << 8));

            /* HE PHY Capabilities Info at bytes 4-5 */
            uint16_t he_phy = (uint16_t)(ies[pos + 4] | ((uint16_t)ies[pos + 5] << 8));

            /* Supported HE-MCS and NSS set at bytes 6-7 */
            uint8_t mcs_nss = ies[pos + 6];

            /* Determine PPDU type from PHY caps:
             * Bit 1 = HE-SU PPDU capable
             * Bit 2 = HE-ER-SU PPDU capable
             * Bit 3 = HE-MU PPDU capable */
            if (he_phy & 0x02) *out_ppdu_type = 2; /* HE-SU */
            else if (he_phy & 0x08) *out_ppdu_type = 1; /* HE-MU */

            /* Extract NSS: bits 0-3 of MCS/NSS field */
            uint8_t nss = mcs_nss & 0x0F;
            /* Extract MCS index: bits 4-7 */
            uint8_t mcs = (mcs_nss >> 4) & 0x0F;

            *out_he_capable = true;
            *out_mcs_nss = ((mcs & 0x0F) << 4) | (nss & 0x0F);
            return true;
        }
        pos += 2 + tag_len;
    }
    return false;
}
