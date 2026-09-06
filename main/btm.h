#ifndef BTM_H
#define BTM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BTM_MAX_REQUESTS 8

typedef struct {
    uint8_t src_bssid[6];
    uint8_t dst_bssid[6];
    uint8_t disassoc_timer;
    bool valid;
} btm_request_t;

esp_err_t btm_init(void);
void btm_parse_request(const uint8_t *frame, size_t len);
size_t btm_list(btm_request_t *out, size_t max);
void btm_clear(void);

#ifdef __cplusplus
}
#endif
#endif
