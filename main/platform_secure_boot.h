#ifndef PLATFORM_SECURE_BOOT_H
#define PLATFORM_SECURE_BOOT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t platform_secure_boot_init(void);
bool platform_secure_boot_is_enabled(void);
esp_err_t platform_secure_boot_get_fingerprint(char *out, size_t max_len);

#ifdef __cplusplus
}
#endif
#endif
