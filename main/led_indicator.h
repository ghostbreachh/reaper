#ifndef LED_INDICATOR_H
#define LED_INDICATOR_H

#include <stdint.h>
#include "esp_err.h"
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t led_indicator_init(void);

/* Backward compatibility with old API name. */
esp_err_t helper_init(void);

void led_set_state(led_state_t state);
void led_set_rgb(uint8_t r, uint8_t g, uint8_t b);

#ifdef __cplusplus
}
#endif

#endif /* LED_INDICATOR_H */
