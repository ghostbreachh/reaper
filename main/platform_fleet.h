#ifndef PLATFORM_FLEET_H
#define PLATFORM_FLEET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t platform_fleet_init(void);
esp_err_t platform_fleet_report(void);
bool platform_fleet_is_enabled(void);

#ifdef __cplusplus
}
#endif
#endif
