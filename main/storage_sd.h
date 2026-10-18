#ifndef STORAGE_SD_H
#define STORAGE_SD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize and mount the SD card.
 * 
 * Safe to call multiple times; subsequent calls return ESP_OK if already mounted.
 */
esp_err_t storage_init(void);

/**
 * @brief Unmount the SD card.
 */
void storage_deinit(void);

/**
 * @brief Check if the SD card is currently mounted and ready.
 */
bool storage_is_ready(void);

/**
 * @brief Get the mount point path (e.g., "/sd").
 */
const char* storage_sd_get_mount_point(void);
void storage_sd_print_info(FILE *out);

static inline esp_err_t storage_sd_init(void) { return storage_init(); }
static inline esp_err_t storage_sd_mount(void) { return storage_init(); }
static inline bool storage_sd_is_ready(void) { return storage_is_ready(); }

#ifdef __cplusplus
}
#endif

#endif // STORAGE_SD_H
