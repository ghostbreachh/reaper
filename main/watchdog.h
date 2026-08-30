#ifndef WATCHDOG_H
#define WATCHDOG_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize watchdog + panic handler. */
esp_err_t watchdog_init(void);

/* Refresh the calling task's watchdog subscription. */
void watchdog_task_refresh(const char *task_name);

/* Force a panic for testing. */
void watchdog_test_panic(void);

/* Read last crash log from SPIFFS. */
esp_err_t watchdog_read_crash(char *out, size_t out_len);

/* Clear crash log. */
void watchdog_clear_crash(void);

/* Check if a panic occurred since last boot. */
bool watchdog_had_panic(void);

#ifdef __cplusplus
}
#endif

#endif // WATCHDOG_H
