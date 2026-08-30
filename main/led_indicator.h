#ifndef LED_INDICATOR_H
#define LED_INDICATOR_H

#include "common_types.h"

esp_err_t helper_init(void);
void led_set_state(led_state_t state);
void led_set_rgb(uint8_t r, uint8_t g, uint8_t b);
void led_set_rgb(uint8_t r, uint8_t g, uint8_t b);

#endif // LED_INDICATOR_H
