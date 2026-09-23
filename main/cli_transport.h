#ifndef CLI_TRANSPORT_H
#define CLI_TRANSPORT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "common_types.h"
#include "port_detect.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CLI_LINE_MAX 192
#define CLI_MAX_ARGS 16

typedef struct {
    esp_err_t (*init)(void);
    esp_err_t (*deinit)(void);
    bool      (*connected)(void);
    int       (*read_line)(char *buf, size_t cap, uint32_t timeout_ms);
    int       (*write)(const void *data, size_t len);
    int       (*printf)(const char *fmt, ...);
} cli_transport_t;

const cli_transport_t *cli_transport_get(void);
esp_err_t cli_transport_switch(port_transport_t new_transport);
esp_err_t cli_start(void);

#ifdef __cplusplus
}
#endif

#endif // CLI_TRANSPORT_H
