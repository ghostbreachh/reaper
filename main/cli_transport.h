#ifndef CLI_TRANSPORT_H
#define CLI_TRANSPORT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Maximum command line length accepted from any transport.
#define CLI_LINE_MAX 192

// Transport interface. Implementations provide the same behaviour over
// UART0 or CDC-ACM so the command parser sees an identical stream.
typedef struct {
    esp_err_t (*init)(void);
    esp_err_t (*deinit)(void);
    bool      (*connected)(void);
    int       (*read_line)(char *buf, size_t cap, uint32_t timeout_ms);
    int       (*write)(const void *data, size_t len);
    int       (*printf)(const char *fmt, ...);
} cli_transport_t;

// Return the active transport selected at boot.
const cli_transport_t *cli_transport_get(void);

// Re-read boot detection and switch active transport at runtime.
esp_err_t cli_transport_switch(port_transport_t new_transport);

#ifdef __cplusplus
}
#endif

#endif // CLI_TRANSPORT_H
