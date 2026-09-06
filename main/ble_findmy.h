#ifndef BLE_FINDMY_H
#define BLE_FINDMY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FINDMY_MAX_DEVICES 16

typedef struct {
    uint8_t mac[6];
    uint8_t status;
    uint8_t battery;
    bool valid;
} findmy_device_t;

esp_err_t findmy_init(void);
void findmy_parse_adv(const uint8_t *adv, size_t len,
                      const uint8_t *mac);
size_t findmy_list(findmy_device_t *out, size_t max);
void findmy_clear(void);

#ifdef __cplusplus
}
#endif
#endif
