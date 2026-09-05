#ifndef CLI_FLIPPER_H
#define CLI_FLIPPER_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize Flipper UART transport on UART1 at 115200 baud. */
esp_err_t cli_flipper_init(void);

/* Deinit Flipper transport. */
esp_err_t cli_flipper_deinit(void);

/* Check if Flipper is connected (DTR/CTS or recent traffic). */
bool cli_flipper_connected(void);

/* Read one JSON line from Flipper; returns length or -1. */
int cli_flipper_read_line(char *buf, size_t cap, uint32_t timeout_ms);

/* Write raw bytes to Flipper. */
int cli_flipper_write(const void *data, size_t len);

/* Printf-style write to Flipper. */
int cli_flipper_printf(const char *fmt, ...);

/* Send an event JSON to Flipper: {"type":"...",...} */
esp_err_t cli_flipper_send_event(const char *json);

#ifdef __cplusplus
}
#endif

#endif /* CLI_FLIPPER_H */
