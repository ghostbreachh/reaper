/*
 * ============================================================================
 *  nvs_persist.c  —  NVS persistence for REAPER settings/targets/wordlists
 * ============================================================================
 */

#include "nvs_persist.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "deauth_engine.h"
#include "esp_err.h"
#include "esp_log.h"
#include "string.h"
#include "stdio.h"

static const char *TAG = "nvs";
static const char *NS = "reaper";

esp_err_t nvs_persist_init(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    return ret;
}

static nvs_handle_t open_handle(bool write)
{
    nvs_handle_t h;
    esp_err_t ret = nvs_open(NS, write ? NVS_READWRITE : NVS_READONLY, &h);
    return (ret == ESP_OK) ? h : 0;
}

/* ── Simple scalar helpers ─────────────────────────────────────────────── */

esp_err_t nvs_set_u32(const char *key, uint32_t value)
{
    nvs_handle_t h = open_handle(true);
    if (!h) return ESP_FAIL;
    esp_err_t ret = nvs_set_u32(h, key, value);
    if (ret == ESP_OK) ret = nvs_commit(h);
    nvs_close(h);
    return ret;
}

esp_err_t nvs_get_u32(const char *key, uint32_t *out, uint32_t def)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    *out = def;
    nvs_handle_t h = open_handle(false);
    if (!h) return ESP_ERR_NOT_FOUND;
    esp_err_t ret = nvs_get_u32(h, key, out);
    nvs_close(h);
    return ret;
}

esp_err_t nvs_set_u8(const char *key, uint8_t value)
{
    nvs_handle_t h = open_handle(true);
    if (!h) return ESP_FAIL;
    esp_err_t ret = nvs_set_u8(h, key, value);
    if (ret == ESP_OK) ret = nvs_commit(h);
    nvs_close(h);
    return ret;
}

esp_err_t nvs_get_u8(const char *key, uint8_t *out, uint8_t def)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    *out = def;
    nvs_handle_t h = open_handle(false);
    if (!h) return ESP_ERR_NOT_FOUND;
    esp_err_t ret = nvs_get_u8(h, key, out);
    nvs_close(h);
    return ret;
}

esp_err_t nvs_set_bool(const char *key, bool value)
{
    nvs_handle_t h = open_handle(true);
    if (!h) return ESP_FAIL;
    esp_err_t ret = nvs_set_u8(h, key, value ? 1 : 0);
    if (ret == ESP_OK) ret = nvs_commit(h);
    nvs_close(h);
    return ret;
}

esp_err_t nvs_get_bool(const char *key, bool *out, bool def)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    *out = def;
    uint8_t v = def ? 1 : 0;
    esp_err_t ret = nvs_get_u8(key, &v, v);
    if (ret == ESP_OK) *out = v;
    return ret;
}

esp_err_t nvs_set_str(const char *key, const char *value)
{
    if (!key || !value) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h = open_handle(true);
    if (!h) return ESP_FAIL;
    esp_err_t ret = nvs_set_str(h, key, value);
    if (ret == ESP_OK) ret = nvs_commit(h);
    nvs_close(h);
    return ret;
}

esp_err_t nvs_get_str(const char *key, char *out, size_t out_len, const char *def)
{
    if (!out || !out_len) return ESP_ERR_INVALID_ARG;
    out[0] = '\0';
    nvs_handle_t h = open_handle(false);
    if (!h) {
        if (def) snprintf(out, out_len, "%s", def);
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t ret = nvs_get_str(h, key, out, &out_len);
    nvs_close(h);
    if (ret != ESP_OK && def) {
        snprintf(out, out_len, "%s", def);
    }
    return ret;
}

/* ── Target list persistence ─────────────────────────────────────────── */

#define MAX_SAVED_TARGETS 100

esp_err_t nvs_save_targets(const deauth_target_t *targets, size_t count)
{
    if (!targets || count == 0 || count > MAX_SAVED_TARGETS) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h = open_handle(true);
    if (!h) return ESP_FAIL;

    esp_err_t ret = nvs_set_u32(h, "tgts_n", (uint32_t)count);
    if (ret != ESP_OK) { nvs_close(h); return ret; }

    char key[8];
    for (size_t i = 0; i < count; i++) {
        snprintf(key, sizeof(key), "tgt_%d", (int)i);
        ret = nvs_set_blob(h, key, &targets[i], sizeof(deauth_target_t));
        if (ret != ESP_OK) { nvs_close(h); return ret; }
    }

    ret = nvs_commit(h);
    nvs_close(h);
    return ret;
}

esp_err_t nvs_load_targets(deauth_target_t *targets, size_t max, size_t *count)
{
    if (!targets || !count || max == 0) return ESP_ERR_INVALID_ARG;
    *count = 0;
    nvs_handle_t h = open_handle(false);
    if (!h) return ESP_ERR_NOT_FOUND;

    uint32_t n = 0;
    esp_err_t ret = nvs_get_u32(h, "tgts_n", &n, 0);
    if (ret != ESP_OK || n == 0) { nvs_close(h); return ESP_OK; }

    if (n > MAX_SAVED_TARGETS) n = MAX_SAVED_TARGETS;
    if (n > max) n = (uint32_t)max;

    char key[8];
    for (uint32_t i = 0; i < n; i++) {
        snprintf(key, sizeof(key), "tgt_%d", (int)i);
        size_t sz = sizeof(deauth_target_t);
        ret = nvs_get_blob(h, key, &targets[i], &sz);
        if (ret != ESP_OK) { break; }
        (*count)++;
    }

    nvs_close(h);
    return ESP_OK;
}

/* ── Wordlist metadata persistence ───────────────────────────────────── */

#define MAX_SAVED_WORDLISTS 16

typedef struct {
    char name[64];
    size_t count;
    uint32_t duration_ms;
} wordlist_meta_t;

esp_err_t nvs_save_wordlist_meta(const char *name, size_t count, uint32_t duration_ms)
{
    if (!name) return ESP_ERR_INVALID_ARG;
    nvs_handle_t h = open_handle(true);
    if (!h) return ESP_FAIL;

    uint32_t n = 1;
    esp_err_t ret = nvs_set_u32(h, "wl_n", 1);
    if (ret == ESP_OK) {
        wordlist_meta_t m;
        memset(&m, 0, sizeof(m));
        snprintf(m.name, sizeof(m.name), "%s", name);
        m.count = count;
        m.duration_ms = duration_ms;
        ret = nvs_set_blob(h, "wl_0", &m, sizeof(m));
    }
    if (ret == ESP_OK) ret = nvs_commit(h);
    nvs_close(h);
    return ret;
}

esp_err_t nvs_load_wordlist_meta(size_t max, size_t *count)
{
    if (!count || max == 0) return ESP_ERR_INVALID_ARG;
    *count = 0;
    nvs_handle_t h = open_handle(false);
    if (!h) return ESP_ERR_NOT_FOUND;

    uint32_t n = 0;
    esp_err_t ret = nvs_get_u32(h, "wl_n", &n, 0);
    if (ret != ESP_OK || n == 0) { nvs_close(h); return ESP_OK; }

    if (n > MAX_SAVED_WORDLISTS) n = MAX_SAVED_WORDLISTS;
    if (n > max) n = (uint32_t)max;

    wordlist_meta_t m;
    size_t sz = sizeof(m);
    ret = nvs_get_blob(h, "wl_0", &m, &sz);
    if (ret == ESP_OK) (*count)++;

    nvs_close(h);
    return ESP_OK;
}

/* ── Factory reset ───────────────────────────────────────────────────── */

esp_err_t nvs_erase_all(void)
{
    nvs_handle_t h = open_handle(true);
    if (!h) return ESP_FAIL;
    esp_err_t ret = nvs_erase_all(h);
    if (ret == ESP_OK) ret = nvs_commit(h);
    nvs_close(h);
    return ret;
}
