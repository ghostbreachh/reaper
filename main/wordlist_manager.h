#ifndef WORDLIST_MANAGER_H
#define WORDLIST_MANAGER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WORDLIST_MAX_ENTRIES 10000000
#define WORDLIST_CHUNK_SIZE 4096
#define WORDLIST_BLOOM_BITS 65536

esp_err_t wordlist_manager_init(void);
esp_err_t wordlist_manager_load(const char *name, const uint8_t *data,
                                size_t len);
bool wordlist_manager_lookup(const char *word, size_t len);
esp_err_t wordlist_manager_stream_next(char *out, size_t max,
                                       size_t *offset);
size_t wordlist_manager_count(void);
void wordlist_manager_clear(void);

#ifdef __cplusplus
}
#endif
#endif
