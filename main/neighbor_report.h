#ifndef NEIGHBOR_REPORT_H
#define NEIGHBOR_REPORT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NR_MAX_ENTRIES 32

typedef struct {
    uint8_t bssid[6];
    uint8_t channel;
    uint8_t phy;
    bool valid;
} nr_entry_t;

esp_err_t neighbor_report_init(void);
void neighbor_report_parse(const uint8_t *ie, size_t len);
size_t neighbor_report_list(nr_entry_t *out, size_t max);
void neighbor_report_clear(void);

#ifdef __cplusplus
}
#endif
#endif
