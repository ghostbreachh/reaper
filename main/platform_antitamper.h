#ifndef PLATFORM_ANTITAMPER_H
#define PLATFORM_ANTITAMPER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t platform_antitamper_init(void);
bool platform_antitamper_check(void);
esp_err_t platform_antitamper_get_report(char *out, size_t max_len);

#ifdef __cplusplus
}
#endif
#endif
