/*
 * ============================================================================
 *  storage_spiffs.c  —  SPIFFS wordlist / blob storage for REAPER
 * ============================================================================
 */

#include "storage_spiffs.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_spiffs.h"
#include "esp_err.h"
#include "esp_heap_caps.h"

static const char *TAG = "spiffs";
static const char *BASE_PATH = "/spiffs";

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static bool path_is_safe(const char *path)
{
    if (path == NULL) return false;
    /* Prevent directory traversal */
    if (strstr(path, "..") != NULL) return false;
    return true;
}

static void build_full_path(char *out, size_t out_sz, const char *path)
{
    if (path[0] == '/') {
        /* Absolute path provided */
        snprintf(out, out_sz, "%s", path);
    } else {
        /* Relative path provided */
        snprintf(out, out_sz, "%s/%s", BASE_PATH, path);
    }
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t storage_spiffs_init(void)
{
    if (storage_spiffs_is_ready()) {
        return ESP_OK;
    }

    esp_vfs_spiffs_conf_t conf = {
        .base_path = BASE_PATH,
        .partition_label = "spiffs",
        .max_files = 32,
        .format_if_mount_failed = true, /* Auto-format if corrupt/empty */
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "SPIFFS mount failed even after format attempt: %s", esp_err_to_name(ret));
        return ret;
    }

    size_t total = 0, used = 0;
    esp_spiffs_info(NULL, &total, &used);
    ESP_LOGI(TAG, "SPIFFS mounted at %s — %u kB used / %u kB total",
             BASE_PATH, (unsigned)(used / 1024), (unsigned)(total / 1024));
             
    return ESP_OK;
}

void storage_spiffs_deinit(void)
{
    if (storage_spiffs_is_ready()) {
        esp_vfs_spiffs_unregister(NULL);
        ESP_LOGI(TAG, "SPIFFS unmounted");
    }
}

bool storage_spiffs_is_ready(void)
{
    return esp_spiffs_mounted(NULL);
}

esp_err_t storage_spiffs_format(void)
{
    bool was_mounted = storage_spiffs_is_ready();
    
    if (was_mounted) {
        ESP_LOGW(TAG, "Unmounting SPIFFS for format...");
        esp_vfs_spiffs_unregister(NULL);
    }

    esp_err_t ret = esp_spiffs_format(NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Format failed: %s", esp_err_to_name(ret));
        /* Attempt to remount even if format failed, to restore state */
        if (was_mounted) storage_spiffs_init();
        return ret;
    }
    
    ESP_LOGI(TAG, "SPIFFS formatted successfully");
    
    if (was_mounted) {
        return storage_spiffs_init();
    }
    
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  File I/O
 * ----------------------------------------------------------------------- */

esp_err_t storage_spiffs_save_wordlist(const char *path, const void *data, size_t len)
{
    if (!path_is_safe(path) || !data || len == 0) return ESP_ERR_INVALID_ARG;
    if (!storage_spiffs_is_ready()) return ESP_ERR_INVALID_STATE;

    char full[128];
    build_full_path(full, sizeof(full), path);

    FILE *f = fopen(full, "wb");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open %s for writing", full);
        return ESP_ERR_NOT_FOUND;
    }

    size_t written = fwrite(data, 1, len, f);
    
    /* CRITICAL: Flush and sync BEFORE closing to prevent UAF on fileno() */
    fflush(f);
    fsync(fileno(f));
    fclose(f);

    if (written != len) {
        ESP_LOGE(TAG, "Short write %zu/%zu to %s", written, len, full);
        return ESP_ERR_INVALID_SIZE;
    }

    ESP_LOGI(TAG, "Saved %s (%zu bytes)", full, len);
    return ESP_OK;
}

esp_err_t storage_spiffs_load_wordlist(const char *path, void **data_out, size_t *len_out)
{
    if (!path_is_safe(path) || !data_out || !len_out) return ESP_ERR_INVALID_ARG;
    if (!storage_spiffs_is_ready()) return ESP_ERR_INVALID_STATE;

    char full[128];
    build_full_path(full, sizeof(full), path);

    FILE *f = fopen(full, "rb");
    if (!f) return ESP_ERR_NOT_FOUND;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0) {
        fclose(f);
        return ESP_ERR_INVALID_SIZE;
    }

    size_t largest_free = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    if ((size_t)sz > largest_free) {
        ESP_LOGE(TAG, "File %s (%ld bytes) exceeds largest free PSRAM block (%u)", 
                 full, sz, (unsigned)largest_free);
        fclose(f);
        return ESP_ERR_NO_MEM;
    }

    void *buf = heap_caps_malloc((size_t)sz, MALLOC_CAP_SPIRAM);
    if (!buf) {
        fclose(f);
        return ESP_ERR_NO_MEM;
    }

    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    if (rd != (size_t)sz) {
        heap_caps_free(buf);
        return ESP_ERR_INVALID_SIZE;
    }

    *data_out = buf;
    *len_out = (size_t)rd;
    return ESP_OK;
}

void storage_spiffs_free_buffer(void *data)
{
    if (data) heap_caps_free(data);
}

/* -------------------------------------------------------------------------
 *  Directory Listing
 * ----------------------------------------------------------------------- */

static int list_filter(const struct dirent *d)
{
    return (d->d_name[0] != '.');
}

esp_err_t storage_spiffs_list_wordlists(char ***names, size_t *count)
{
    if (!names || !count) return ESP_ERR_INVALID_ARG;
    if (!storage_spiffs_is_ready()) return ESP_ERR_INVALID_STATE;

    struct dirent **entries = NULL;
    int n = scandir(BASE_PATH, &entries, list_filter, NULL);
    if (n <= 0) {
        *names = NULL;
        *count = 0;
        return (n == 0) ? ESP_OK : ESP_ERR_NOT_FOUND;
    }

    char **out = heap_caps_calloc(n, sizeof(char *), MALLOC_CAP_DEFAULT);
    if (!out) {
        for (int i = 0; i < n; i++) free(entries[i]);
        free(entries);
        return ESP_ERR_NO_MEM;
    }

    size_t valid = 0;
    for (int i = 0; i < n; i++) {
        char full[300];
        snprintf(full, sizeof(full), "%s/%s", BASE_PATH, entries[i]->d_name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISREG(st.st_mode)) {
            out[valid++] = strdup(entries[i]->d_name);
        }
        free(entries[i]);
    }
    free(entries);

    *names = out;
    *count = valid;
    return ESP_OK;
}

void storage_spiffs_free_list(char **names, size_t count)
{
    if (!names) return;
    for (size_t i = 0; i < count; i++) {
        if (names[i]) free(names[i]); /* strdup uses standard malloc */
    }
    heap_caps_free(names); /* heap_caps_calloc used for the array */
}

esp_err_t storage_spiffs_usage(uint64_t *total, uint64_t *used)
{
    if (!total || !used) return ESP_ERR_INVALID_ARG;
    if (!storage_spiffs_is_ready()) return ESP_ERR_INVALID_STATE;

    size_t t = 0, u = 0;
    esp_err_t ret = esp_spiffs_info(NULL, &t, &u);
    if (ret != ESP_OK) return ret;
    *total = t;
    *used = u;
    return ESP_OK;
}

esp_err_t storage_spiffs_list_wordlists_json(char *buf, size_t bufsz)
{
    if (!buf || bufsz == 0) return ESP_ERR_INVALID_ARG;
    char **names = NULL;
    size_t count = 0;
    esp_err_t rc = storage_spiffs_list_wordlists(&names, &count);
    if (rc != ESP_OK) return rc;

    size_t off = 0;
    int n = snprintf(buf + off, bufsz - off, "[");
    if (n < 0 || (size_t)n >= bufsz - off) {
        storage_spiffs_free_list(names, count);
        return ESP_ERR_NO_MEM;
    }
    off += (size_t)n;

    for (size_t i = 0; i < count; i++) {
        n = snprintf(buf + off, bufsz - off, "%s\"%s\"", (i > 0) ? "," : "", names[i] ? names[i] : "");
        if (n < 0 || (size_t)n >= bufsz - off) {
            storage_spiffs_free_list(names, count);
            return ESP_ERR_NO_MEM;
        }
        off += (size_t)n;
    }
    storage_spiffs_free_list(names, count);

    n = snprintf(buf + off, bufsz - off, "]");
    if (n < 0 || (size_t)n >= bufsz - off) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

esp_err_t storage_spiffs_load_wordlist_meta(const char *name)
{
    if (!path_is_safe(name)) return ESP_ERR_INVALID_ARG;
    if (!storage_spiffs_is_ready()) return ESP_ERR_INVALID_STATE;
    char full[128];
    build_full_path(full, sizeof(full), name);
    struct stat st;
    if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
        return ESP_ERR_NOT_FOUND;
    }
    return ESP_OK;
}
