#ifndef ZIGBEE_SNIFFER_H
#define ZIGBEE_SNIFFER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Zigbee/802.15.4 sniffer stub for future radio hardware.
 *
 *  Feature 94 — [HW] Zigbee sniffer
 *
 *  Current hardware: ESP32-S3 has no 802.15.4 radio.
 *  ESP32-H2/C6 can add 802.15.4 capability.
 *  This module provides the API surface for future hardware.
 */

esp_err_t zigbee_sniffer_init(void);
esp_err_t zigbee_sniffer_start(uint8_t channel);
esp_err_t zigbee_sniffer_stop(void);
bool zigbee_sniffer_is_active(void);
size_t zigbee_sniffer_get_packets(uint8_t *out, size_t max);
void zigbee_sniffer_clear(void);

#ifdef __cplusplus
}
#endif
#endif
