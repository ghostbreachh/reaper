#ifndef CHANNEL_HOPPER_H
#define CHANNEL_HOPPER_H

#include <stdint.h>
#include <stdbool.h>

#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Smart channel hopper: configurable dwell time, sequential/random
 * traversal, and per-channel packet/RSSI statistics.
 *
 * Intended to replace the inline channel_hopper_task inside wifi_sniffer
 * with a single authoritative hopper shared by sniffer, analyzer, and
 * future radio subsystems.
 */

typedef enum {
    CH_HOP_MODE_SEQUENTIAL = 0,
    CH_HOP_MODE_RANDOM     = 1,
    CH_HOP_MODE_RSSI_OPT   = 2,
    CH_HOP_MODE_ADAPTIVE   = 3
} ch_hop_mode_t;

typedef struct {
    ch_hop_mode_t mode;
    uint16_t dwell_ms;            /* 10..30000 ms; 0 means default 100 ms */
    uint8_t  channel_mask;        /* bit0=ch1 .. bit12=ch13; 0xFF = all */
    uint32_t dwell_us;            /* override: microsecond dwell; 0=use dwell_ms */
} ch_hop_config_t;

typedef struct {
    uint32_t pkt_count;
    uint32_t beacon_count;
    uint32_t mgmt_count;
    uint32_t data_count;
    int32_t  rssi_sum;
    uint32_t rssi_samples;
    uint32_t adaptive_dwell_ms; /* current adaptive dwell for this channel */
} ch_hop_stats_t;

/*
 * Initialize channel hopper state.
 * Must be called once from wifi_sniffer_init().
 */
esp_err_t channel_hopper_init(void);

/*
 * Start hopping with the given config.
 * Requires WiFi already in promiscuous mode.
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
 * If us > 0, this overrides dwell_ms for sub-millisecond precision.
 */
esp_err_t channel_hopper_set_dwell_us(uint32_t us);

/*
 * Get current microsecond dwell setting.
 */
uint32_t channel_hopper_get_dwell_us(void);

uint32_t channel_hopper_adaptive_dwell(uint8_t channel);

/*
 * Retrieve statistics for a single 1..13 channel.
 */
esp_err_t channel_hopper_get_stats(uint8_t channel, ch_hop_stats_t *out);

/*
 * Snapshot all 13 channels into out[1..13].
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
