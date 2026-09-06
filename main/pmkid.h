#ifndef PMKID_H
#define PMKID_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PMKID_MAX_ENTRIES 32

typedef struct {
    uint8_t bssid[6];
    uint8_t pmkid[16];
    int8_t rssi;
    uint32_t ts_ms;
    bool valid;
} pmkid_entry_t;

esp_err_t pmkid_init(void);
void pmkid_add(const uint8_t *bssid, const uint8_t *pmkid, int8_t rssi);
size_t pmkid_count(void);
size_t pmkid_list(pmkid_entry_t *out, size_t max);
void pmkid_clear(void);
bool pmkid_has(const uint8_t *bssid, uint8_t *out_pmkid);

#ifdef __cplusplus
}
#endif
#endif
