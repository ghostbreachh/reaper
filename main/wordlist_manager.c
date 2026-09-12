#include "wordlist_manager.h"
#include "storage_spiffs.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "wordlist";

/* Bloom filter: 65536 bits = 8192 bytes */
static uint8_t s_bloom[WORDLIST_BLOOM_BITS / 8];

static size_t s_count = 0;
static bool s_init = false;

static char s_current_path[128] = {0};
static FILE *s_stream = NULL;
static size_t s_stream_line = 0;

static SemaphoreHandle_t s_mutex = NULL;

/* -------------------------------------------------------------------------
 *  Bloom helpers
 * ----------------------------------------------------------------------- */

static uint32_t hash1(const char *s, size_t len)
{
    uint32_t h = 5381;

    for (size_t i = 0; i < len; i++) {
        h = ((h << 5) + h) + (uint8_t)s[i];
    }

    return h % WORDLIST_BLOOM_BITS;
}

static uint32_t hash2(const char *s, size_t len)
{
    uint32_t h = 0;

    for (size_t i = 0; i < len; i++) {
        h = (h * 31u) + (uint8_t)s[i];
    }

    return h % WORDLIST_BLOOM_BITS;
}

static void bloom_set(uint32_t idx)
{
    s_bloom[idx / 8] |= (uint8_t)(1u << (idx % 8));
}

static bool bloom_get(uint32_t idx)
{
    return (s_bloom[idx / 8] & (uint8_t)(1u << (idx % 8))) != 0;
}

static void bloom_add_word(const char *word, size_t len)
{
    if (word == NULL || len == 0) {
        return;
    }

    bloom_set(hash1(word, len));
    bloom_set(hash2(word, len));

    if (s_count < WORDLIST_MAX_ENTRIES) {
        s_count++;
    }
}

/* -------------------------------------------------------------------------
 *  Validation helpers
 * ----------------------------------------------------------------------- */

static bool wordlist_name_valid(const char *name)
{
    if (name == NULL) {
        return false;
    }

    size_t len = strlen(name);

    if (len == 0 || len >= WORDLIST_MAX_NAME_LEN) {
        return false;
    }

    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return false;
    }

    if (strstr(name, "..") != NULL) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];

        if (!isalnum(c) && c != '_' && c != '-' && c != '.') {
            return false;
        }
    }

    return true;
}

/* -------------------------------------------------------------------------
 *  Internal stream/file helpers
 * ----------------------------------------------------------------------- */

static void close_stream_locked(void)
{
    if (s_stream != NULL) {
        fclose(s_stream);
        s_stream = NULL;
    }

    s_stream_line = 0;
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t wordlist_manager_init(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
        if (s_mutex == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    memset(s_bloom, 0, sizeof(s_bloom));
    memset(s_current_path, 0, sizeof(s_current_path));

    s_count = 0;
    s_init = true;

    close_stream_locked();

    xSemaphoreGive(s_mutex);

    ESP_LOGI(TAG, "Wordlist manager initialized");
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Load
 * ----------------------------------------------------------------------- */

esp_err_t wordlist_manager_load(const char *name,
                                const uint8_t *data,
                                size_t len)
{
    if (!s_init || s_mutex == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (!wordlist_name_valid(name)) {
        ESP_LOGW(TAG, "Invalid wordlist name");
        return ESP_ERR_INVALID_ARG;
    }

    if (data == NULL || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    char path[sizeof(s_current_path)];

    int pr = snprintf(path, sizeof(path), "/spiffs/wl/%s", name);

    if (pr < 0 || pr >= (int)sizeof(path)) {
        return ESP_ERR_INVALID_SIZE;
    }

    esp_err_t rc = storage_spiffs_save_wordlist(path, data, len);

    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save wordlist to %s: %s",
                 path, esp_err_to_name(rc));
        return rc;
    }

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    close_stream_locked();

    snprintf(s_current_path, sizeof(s_current_path), "%s", path);

    memset(s_bloom, 0, sizeof(s_bloom));
    s_count = 0;

    size_t line_start = 0;

    for (size_t i = 0; i < len; i++) {
        uint8_t ch = data[i];

        if (ch == '\n' || ch == '\r') {
            size_t wlen = i - line_start;

            if (wlen > 0) {
                const char *word = (const char *)data + line_start;
                bloom_add_word(word, wlen);
            }

            /* Handle CRLF as one separator. */
            if (ch == '\r' && (i + 1) < len && data[i + 1] == '\n') {
                i++;
            }

            line_start = i + 1;
        }
    }

    /* Final line without trailing newline. */
    if (line_start < len) {
        size_t wlen = len - line_start;

        if (wlen > 0) {
            const char *word = (const char *)data + line_start;
            bloom_add_word(word, wlen);
        }
    }

    size_t loaded_count = s_count;

    xSemaphoreGive(s_mutex);

    if (loaded_count > (WORDLIST_BLOOM_BITS / 4)) {
        ESP_LOGW(TAG,
                 "Bloom filter may have high false-positive rate: "
                 "%zu words in %d bits",
                 loaded_count,
                 WORDLIST_BLOOM_BITS);
    }

    ESP_LOGI(TAG, "Wordlist loaded: %s (%zu words)", name, loaded_count);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Lookup
 * ----------------------------------------------------------------------- */

bool wordlist_manager_lookup(const char *word, size_t len)
{
    if (!s_init || s_mutex == NULL || word == NULL || len == 0) {
        return false;
    }

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    bool maybe_present =
        bloom_get(hash1(word, len)) &&
        bloom_get(hash2(word, len));

    xSemaphoreGive(s_mutex);

    return maybe_present;
}

/* -------------------------------------------------------------------------
 *  Streaming
 * ----------------------------------------------------------------------- */

esp_err_t wordlist_manager_stream_next(char *out,
                                       size_t max,
                                       size_t *offset)
{
    if (!s_init || s_mutex == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (out == NULL || max == 0 || offset == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    if (s_current_path[0] == '\0') {
        xSemaphoreGive(s_mutex);
        return ESP_ERR_INVALID_STATE;
    }

    if (s_stream == NULL) {
        s_stream = fopen(s_current_path, "r");

        if (s_stream == NULL) {
            xSemaphoreGive(s_mutex);
            ESP_LOGE(TAG, "Failed to open wordlist stream: %s", s_current_path);
            return ESP_ERR_NOT_FOUND;
        }

        s_stream_line = 0;
    }

    char line[WORDLIST_LINE_MAX];

    while (fgets(line, sizeof(line), s_stream) != NULL) {
        bool has_newline = (strchr(line, '\n') != NULL);

        /*
         * If the line is too long for the internal buffer and we are not at
         * EOF, discard the remainder of the line.
         */
        if (!has_newline && !feof(s_stream)) {
            int c;

            while ((c = fgetc(s_stream)) != EOF && c != '\n') {
                /* discard */
            }

            continue;
        }

        size_t len = strlen(line);

        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        if (len == 0) {
            continue;
        }

        size_t current_word_index = s_stream_line++;

        if (len >= max) {
            /* Word too large for caller buffer. */
            continue;
        }

        memcpy(out, line, len + 1);
        *offset = current_word_index;

        xSemaphoreGive(s_mutex);
        return ESP_OK;
    }

    xSemaphoreGive(s_mutex);

    return ESP_ERR_NOT_FOUND;
}

/* -------------------------------------------------------------------------
 *  Status / clear
 * ----------------------------------------------------------------------- */

size_t wordlist_manager_count(void)
{
    if (!s_init || s_mutex == NULL) {
        return 0;
    }

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    size_t count = s_count;
    xSemaphoreGive(s_mutex);

    return count;
}

void wordlist_manager_clear(void)
{
    if (s_mutex == NULL) {
        return;
    }

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    memset(s_bloom, 0, sizeof(s_bloom));
    memset(s_current_path, 0, sizeof(s_current_path));

    s_count = 0;

    close_stream_locked();

    xSemaphoreGive(s_mutex);
}
