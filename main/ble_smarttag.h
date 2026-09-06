#ifndef BLE_SMARTTAG_H
#define BLE_SMARTTAG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SMARTTAG_MAX_DEVICES 16

typedef struct {
    uint8_t mac[6];
    uint8_t type;
    uint8_t battery;
    bool valid;
} smarttag_device_t;

esp_err_t smarttag_init(void);
void smarttag_parse_adv(const uint8_t *adv, size_t len,
                        const uint8_t *mac);
size_t smarttag_list(smarttag_device_t *out, size_t max);
void smarttag_clear(void);

#ifdef __cplusplus
}
#endif
#endif
