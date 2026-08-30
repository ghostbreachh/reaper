#ifndef STORAGE_SPIFFS_H
#define STORAGE_SPIFFS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t storage_spiffs_init(void);
void storage_spiffs_deinit(void);
bool storage_spiffs_is_ready(void);
esp_err_t storage_spiffs_format(void);

/* Wordlist storage */
esp_err_t storage_spiffs_save_wordlist(const char *path, const void *data, size_t len);
esp_err_t storage_spiffs_load_wordlist(const char *path, void **data_out, size_t *len_out);
void storage_spiffs_free_buffer(void *data);
esp_err_t storage_spiffs_list_wordlists(char ***names, size_t *count);
void storage_spiffs_free_list(char **names, size_t count);

/* Total / free bytes */
esp_err_t storage_spiffs_usage(uint64_t *total, uint64_t *used);

#ifdef __cplusplus
}
#endif

#endif // STORAGE_SPIFFS_H
