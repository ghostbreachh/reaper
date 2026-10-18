#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

/*
 * Overrides the closed Wi-Fi lib's raw-frame sanity gate.
 * Providing both __wrap_ieee80211_raw_frame_sanity_check (used when
 * -Wl,--wrap=ieee80211_raw_frame_sanity_check is active in CMakeLists.txt)
 * and ieee80211_raw_frame_sanity_check ensures raw 802.11 management/data
 * frames (deauth, disassoc, auth, beacon, probe) are never dropped.
 */
int __wrap_ieee80211_raw_frame_sanity_check(int32_t arg1, const void *frame, int32_t len, bool en_sys_seq)
{
    (void)arg1;
    (void)frame;
    (void)len;
    (void)en_sys_seq;
    return 0;
}

int ieee80211_raw_frame_sanity_check(int32_t arg1, const void *frame, int32_t len, bool en_sys_seq)
{
    (void)arg1;
    (void)frame;
    (void)len;
    (void)en_sys_seq;
    return 0;
}
