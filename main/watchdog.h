#ifndef WATCHDOG_H
#define WATCHDOG_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize watchdog supervisor and check for previous crash logs.
 * 
 * If the device previously panicked, this function safely writes the crash 
 * context to SPIFFS from a normal task context.
 */
esp_err_t watchdog_init(void);

/**
 * @brief Subscribe the calling task to the Task WDT (if not already) and reset it.
 */
void watchdog_task_refresh(const char *task_name);

/**
 * @brief Force a panic for testing purposes.
 */
void watchdog_test_panic(void);

/**
 * @brief Read the last crash log from SPIFFS.
 */
esp_err_t watchdog_read_crash(char *out, size_t out_len);

/**
 * @brief Clear the crash log from SPIFFS.
 */
void watchdog_clear_crash(void);

/**
 * @brief Check if a crash log currently exists on SPIFFS.
 */
bool watchdog_has_crash_log(void);

#ifdef __cplusplus
}
#endif

#endif // WATCHDOG_H
