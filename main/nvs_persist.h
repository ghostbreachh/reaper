#ifndef NVS_PERSIST_H
#define NVS_PERSIST_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t persist_init(void);
static inline esp_err_t nvs_persist_init(void) { return persist_init(); }

/* Simple settings */
esp_err_t persist_set_u32(const char *key, uint32_t value);
esp_err_t persist_get_u32(const char *key, uint32_t *out, uint32_t def);
esp_err_t persist_set_u8(const char *key, uint8_t value);
esp_err_t persist_get_u8(const char *key, uint8_t *out, uint8_t def);
esp_err_t persist_set_bool(const char *key, bool value);
esp_err_t persist_get_bool(const char *key, bool *out, bool def);
esp_err_t persist_set_str(const char *key, const char *value);
esp_err_t persist_get_str(const char *key, char *out, size_t out_len, const char *def);

/* Target list (array of deauth_target_t) */
esp_err_t persist_save_targets(const deauth_target_t *targets, size_t count);
esp_err_t persist_load_targets(deauth_target_t *targets, size_t max, size_t *count);

/* Wordlist metadata */
esp_err_t persist_save_wordlist_meta(const char *name, size_t count, uint32_t duration_ms);
esp_err_t persist_load_wordlist_meta(char *name_out, size_t name_sz, size_t *count_out, uint32_t *duration_out);

/* Reset */
esp_err_t persist_erase_all(void);

#ifdef __cplusplus
}
#endif

#endif // NVS_PERSIST_H
