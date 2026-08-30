#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

/*
 * Overrides the closed wifi lib's raw-frame gate.
 * With -Wl,-zmuldefs the linker accepts two definitions of this symbol;
 * the one in this project must win (verify in the .map, step 2).
 * Always returning 0 lets deauth (0xC0), auth (0xB0), assoc (0x00), ... transmit.
 */
int ieee80211_raw_frame_sanity_check(int32_t arg1, const void *frame, int32_t len, bool en_sys_seq)
{
    (void)arg1; (void)frame; (void)len; (void)en_sys_seq;
    return 0;
}