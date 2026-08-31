#include "wifi_rrm.h"
#include <string.h>
#include <stdbool.h>
#include "esp_log.h"

static const char *TAG = "wifi_rrm";

#define IE_NEIGHBOR_REPORT  52
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
