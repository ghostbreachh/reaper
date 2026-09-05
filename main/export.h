#ifndef EXPORT_H
#define EXPORT_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EXPORT_MODE_OFF = 0,
    EXPORT_MODE_PCAP,
    EXPORT_MODE_PCAP_NG,
    EXPORT_MODE_NETXML,
    EXPORT_MODE_CSV,
    EXPORT_MODE_JSONL,
    EXPORT_MODE_ZST
} export_mode_t;

typedef struct {
    export_mode_t mode;
    bool active;
    uint32_t packets_written;
    uint32_t bytes_written;
    uint32_t dropped;
    char path[128];
} export_stats_t;

esp_err_t export_init(void);
esp_err_t export_start(export_mode_t mode, const char *base_path);
esp_err_t export_stop(void);
esp_err_t export_write_packet(const uint8_t *data, size_t len,
                              uint8_t channel, int8_t rssi,
                              uint64_t timestamp_us);
esp_err_t export_write_event(const char *type, const char *json);
esp_err_t export_get_stats(export_stats_t *out);
esp_err_t export_json(char *buf, size_t bufsz);
export_mode_t export_get_mode(void);
esp_err_t export_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* EXPORT_H */
