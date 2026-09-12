#ifndef WORDLIST_MANAGER_H
#define WORDLIST_MANAGER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Upper logical limit for wordlist entries.
 * This is not stored in RAM; it is a sanity bound.
 */
#define WORDLIST_MAX_ENTRIES 10000000

/*
 * Streaming read chunk size.
 */
#define WORDLIST_CHUNK_SIZE 4096

/*
 * Bloom filter size.
 *
 * 65536 bits = 8192 bytes.
 * This is small, so large wordlists will have false positives.
 */
#define WORDLIST_BLOOM_BITS 65536

/*
 * Maximum wordlist file name length.
 */
#define WORDLIST_MAX_NAME_LEN 48

/*
 * Maximum line length supported by streaming reader.
 * WPA2/WPA3 passphrases are normally <= 63 bytes, so 256 is safe.
 */
#define WORDLIST_LINE_MAX 256

/**
 * @brief Initialize wordlist manager.
 */
esp_err_t wordlist_manager_init(void);

/**
 * @brief Load/save a newline-delimited wordlist.
 *
 * The raw list is saved to SPIFFS.
 * A Bloom filter is built for fast probabilistic membership checks.
 */
esp_err_t wordlist_manager_load(const char *name,
                                const uint8_t *data,
                                size_t len);

/**
 * @brief Probabilistic membership check.
 *
 * This can return false positives.
 */
bool wordlist_manager_lookup(const char *word, size_t len);

/**
 * @brief Stream next word from the currently loaded wordlist.
 *
 * @param out     Output buffer for NUL-terminated word
 * @param max     Size of output buffer
 * @param offset  Output word index
 *
 * @return ESP_OK if a word was read.
 * @return ESP_ERR_NOT_FOUND at end of wordlist.
 */
esp_err_t wordlist_manager_stream_next(char *out,
                                       size_t max,
                                       size_t *offset);

/**
 * @brief Approximate number of words in active wordlist.
 */
size_t wordlist_manager_count(void);

/**
 * @brief Clear Bloom filter and close active stream.
 */
void wordlist_manager_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* WORDLIST_MANAGER_H */
