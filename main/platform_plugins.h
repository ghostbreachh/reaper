#ifndef PLATFORM_PLUGINS_H
#define PLATFORM_PLUGINS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PLUGIN_MAX_SLOTS 8
#define PLUGIN_NAME_LEN 32

typedef struct {
    char name[PLUGIN_NAME_LEN];
    bool loaded;
    uint32_t size;
} plugin_slot_t;

esp_err_t platform_plugins_init(void);
size_t platform_plugins_list(plugin_slot_t *out, size_t max);
esp_err_t platform_plugin_load(const char *name);
esp_err_t platform_plugin_unload(const char *name);

#ifdef __cplusplus
}
#endif
#endif
