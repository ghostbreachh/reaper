#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CONFIG_PROFILE_PENTEST = 0,
    CONFIG_PROFILE_WARDIRVE,
    CONFIG_PROFILE_RESEARCH,
    CONFIG_PROFILE_STEALTH,
    CONFIG_PROFILE_COUNT
} config_profile_t;

esp_err_t platform_config_init(void);
esp_err_t platform_config_apply(config_profile_t profile);
config_profile_t platform_config_get(void);
esp_err_t platform_config_save(void);
esp_err_t platform_config_reset(void);

#ifdef __cplusplus
}
#endif
#endif
