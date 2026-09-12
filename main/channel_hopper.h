#ifndef CHANNEL_HOPPER_H
#define CHANNEL_HOPPER_H

#include <stdint.h>
#include <stdbool.h>

#include "esp_err.h"
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CH_HOP_CHANNEL_MIN  1
#define CH_HOP_CHANNEL_MAX  13
#define CH_HOP_MASK_ALL     ((uint16_t)0x1FFFu)

/*
 * Smart channel hopper: configurable dwell time, sequential/random
 * traversal, and per-channel packet/RSSI statistics.
 *
 * Intended to be the single authoritative hopper shared by sniffer,
 * analyzer, and future radio subsystems.
 */

typedef enum {
    CH_HOP_MODE_SEQUENTIAL = 0,
    CH_HOP_MODE_RANDOM     = 1,
    CH_HOP_MODE_RSSI_OPT   = 2,
    CH_HOP_MODE_ADAPTIVE   = 3
} ch_hop_mode_t;

typedef struct {
    ch_hop_mode_t mode;

    /*
     * Dwell time in milliseconds.
     * 0 means default 100 ms.
     * Valid range is clamped internally.
     */
    uint16_t dwell_ms;

    /*
     * bit0 = channel 1 ... bit12 = channel 13.
     * Must be uint16_t, not uint8_t, to represent all 13 channels.
     */
    uint16_t channel_mask;

    /*
     * Optional microsecond dwell override.
     * If non-zero, this overrides dwell_ms.
     * Values below 1000 use busy-wait for sub-millisecond dwell.
     */
    uint32_t dwell_us;
} ch_hop_config_t;

typedef struct {
    uint32_t pkt_count;
    uint32_t beacon_count;
    uint32_t mgmt_count;
    uint32_t data_count;

    int32_t  rssi_sum;
    uint32_t rssi_samples;

    uint32_t adaptive_dwell_ms;

    /*
     * Packet count observed during the current dwell window.
     * Used by adaptive dwell logic.
     */
    uint32_t window_pkt_count;
    uint64_t window_start_us;
} ch_hop_stats_t;

/*
 * Initialize channel hopper state.
 * Must be called once before channel_hopper_start().
 */
esp_err_t channel_hopper_init(void);

/*
 * Start hopping with the given config.
 * Requires Wi-Fi already in promiscuous mode.
 */
esp_err_t channel_hopper_start(const ch_hop_config_t *cfg);

/*
 * Stop hopping and retain last collected stats.
 */
esp_err_t channel_hopper_stop(void);

/*
 * Query whether the hopper task is currently active.
 */
bool channel_hopper_is_active(void);

/*
 * Set microsecond dwell override.
 *
 * If us == 0, restore default millisecond dwell.
 * If us < 1000, use sub-millisecond busy-wait dwell.
 * If us >= 1000, convert to clamped millisecond dwell.
 */
esp_err_t channel_hopper_set_dwell_us(uint32_t us);

/*
 * Get current effective dwell in microseconds.
 */
uint32_t channel_hopper_get_dwell_us(void);

/*
 * Get adaptive dwell for a channel.
 * Returns 0 if channel invalid.
 */
uint32_t channel_hopper_adaptive_dwell(uint8_t channel);

/*
 * Retrieve statistics for a single 1..13 channel.
 */
esp_err_t channel_hopper_get_stats(uint8_t channel, ch_hop_stats_t *out);

/*
 * Snapshot all 14 stat slots into out.
 * Index 0 is unused; channels are stored at out[1..13].
 */
esp_err_t channel_hopper_get_all_stats(ch_hop_stats_t out[14]);

/*
 * Export summary as JSON into provided buffer.
 * Returns number of bytes written, not including NUL.
 */
int channel_hopper_json(char *buf, size_t bufsz);

/*
 * Human-readable summary to stdout.
 */
void channel_hopper_print_summary(void);

#ifdef __cplusplus
}
#endif

#endif /* CHANNEL_HOPPER_H */
