#include "wordlist_manager.h"
#include "storage_spiffs.h"
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"

static const char *TAG = "wordlist";

/* Bloom filter: 65536 bits = 8192 bytes */
static uint8_t s_bloom[WORDLIST_BLOOM_BITS / 8];
static size_t s_count = 0;
static size_t s_stream_offset = 0;
static bool s_init = false;

/* Simple hash functions for Bloom filter */
static uint32_t hash1(const char *s, size_t len)
{
    uint32_t h = 5381;
    for (size_t i = 0; i < len; i++) h = ((h << 5) + h) + (uint8_t)s[i];
    return h % WORDLIST_BLOOM_BITS;
}

static uint32_t hash2(const char *s, size_t len)
{
    uint32_t h = 0;
    for (size_t i = 0; i < len; i++) h = (h * 31) + (uint8_t)s[i];
    return h % WORDLIST_BLOOM_BITS;
}

static void bloom_set(uint32_t idx)
{
    s_bloom[idx / 8] |= (1 << (idx % 8));
}

static bool bloom_get(uint32_t idx)
{
    return (s_bloom[idx / 8] & (1 << (idx % 8))) != 0;
}

esp_err_t wordlist_manager_init(void)
{
    memset(s_bloom, 0, sizeof(s_bloom));
    s_count = 0;
    s_stream_offset = 0;
    s_init = true;
    ESP_LOGI(TAG, "Wordlist manager initialized");
    return ESP_OK;
}

esp_err_t wordlist_manager_load(const char *name, const uint8_t *data,
                                size_t len)
{
    if (!s_init || !name || !data || !len) return ESP_ERR_INVALID_ARG;
    /* Save raw to SPIFFS */
    char path[64];
    snprintf(path, sizeof(path), "/spiffs/wl/%s", name);
    esp_err_t rc = storage_spiffs_save_wordlist(path, data, len);
    if (rc != ESP_OK) return rc;

    /* Rebuild Bloom filter from data (assume newline-delimited) */
    memset(s_bloom, 0, sizeof(s_bloom));
    s_count = 0;
    size_t line_start = 0;
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\n' && i > line_start) {
            const char *word = (const char *)data + line_start;
            size_t wlen = i - line_start;
            /* Trim CR */
            if (wlen > 0 && word[wlen - 1] == '\r') wlen--;
            bloom_set(hash1(word, wlen));
            bloom_set(hash2(word, wlen));
            s_count++;
            line_start = i + 1;
        }
    }
    s_stream_offset = 0;
    ESP_LOGI(TAG, "Wordlist loaded: %s (%d words)", name, (int)s_count);
    return ESP_OK;
}

bool wordlist_manager_lookup(const char *word, size_t len)
{
    if (!s_init || !word || !len) return false;
    if ((bloom_get(hash1(word, len)) && bloom_get(hash2(word, len)))) {
        return true;
    }
    return false;
}

esp_err_t wordlist_manager_stream_next(char *out, size_t max,
                                       size_t *offset)
{
    if (!s_init || !out || !max || !offset) return ESP_ERR_INVALID_ARG;
    /* Stub: real implementation reads from SPIFFS file handle */
    *offset = 0;
    out[0] = 0;
    return ESP_ERR_NOT_SUPPORTED;
}

size_t wordlist_manager_count(void)
{
    return s_count;
}

void wordlist_manager_clear(void)
{
    memset(s_bloom, 0, sizeof(s_bloom));
    s_count = 0;
    s_stream_offset = 0;
}
