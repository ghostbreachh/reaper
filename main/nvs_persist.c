/*
 * ============================================================================
 *  nvs_persist.c  —  NVS persistence for REAPER settings/targets/wordlists
 * ============================================================================
 */

#include "nvs_persist.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "deauth_engine.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "esp_err.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "nvs";
static const char *NS = "reaper";

static SemaphoreHandle_t g_nvs_lock = NULL;

#define MAX_SAVED_TARGETS 100
#define MAX_SAVED_WORDLISTS 16

typedef struct {
    char name[64];
    size_t count;
    uint32_t duration_ms;
} wordlist_meta_t;

esp_err_t persist_init(void)
{
    if (g_nvs_lock == NULL) {
        g_nvs_lock = xSemaphoreCreateMutex();
        if (g_nvs_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

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

esp_err_t persist_set_u32(const char *key, uint32_t value)
{
    if (!key || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    
    nvs_handle_t h = open_handle(true);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_FAIL; }
    
    esp_err_t ret = nvs_set_u32(h, key, value);
    if (ret == ESP_OK) ret = nvs_commit(h);
    nvs_close(h);
    
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

esp_err_t persist_get_u32(const char *key, uint32_t *out, uint32_t def)
{
    if (!out || !key || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    *out = def;
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(false);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_ERR_NOT_FOUND; }
    
    esp_err_t ret = nvs_get_u32(h, key, out);
    nvs_close(h);
    
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

esp_err_t persist_set_u8(const char *key, uint8_t value)
{
    if (!key || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    
    nvs_handle_t h = open_handle(true);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_FAIL; }
    
    esp_err_t ret = nvs_set_u8(h, key, value);
    if (ret == ESP_OK) ret = nvs_commit(h);
    nvs_close(h);
    
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

esp_err_t persist_get_u8(const char *key, uint8_t *out, uint8_t def)
{
    if (!out || !key || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    *out = def;
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(false);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_ERR_NOT_FOUND; }
    
    esp_err_t ret = nvs_get_u8(h, key, out);
    nvs_close(h);
    
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

esp_err_t persist_set_bool(const char *key, bool value)
{
    return persist_set_u8(key, value ? 1 : 0);
}

esp_err_t persist_get_bool(const char *key, bool *out, bool def)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    uint8_t v = def ? 1 : 0;
    esp_err_t ret = persist_get_u8(key, &v, v);
    if (ret == ESP_OK) *out = (v != 0);
    return ret;
}

esp_err_t persist_set_str(const char *key, const char *value)
{
    if (!key || !value || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    
    nvs_handle_t h = open_handle(true);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_FAIL; }
    
    esp_err_t ret = nvs_set_str(h, key, value);
    if (ret == ESP_OK) ret = nvs_commit(h);
    nvs_close(h);
    
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

esp_err_t persist_get_str(const char *key, char *out, size_t out_len, const char *def)
{
    if (!out || !out_len || !key || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    out[0] = '\0';
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(false);
    if (!h) { 
        if (def) snprintf(out, out_len, "%s", def);
        xSemaphoreGive(g_nvs_lock);
        return ESP_ERR_NOT_FOUND; 
    }
    
    size_t len = out_len;
    esp_err_t ret = nvs_get_str(h, key, out, &len);
    nvs_close(h);
    
    if (ret != ESP_OK && def) {
        snprintf(out, out_len, "%s", def);
    }
    
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

/* ── Target list persistence ─────────────────────────────────────────── */

esp_err_t persist_save_targets(const deauth_target_t *targets, size_t count)
{
    if (!targets || count == 0 || count > MAX_SAVED_TARGETS || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(true);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_FAIL; }

    /* Clean up old keys to prevent NVS bloat */
    char key[16];
    for (int i = 0; i < MAX_SAVED_TARGETS; i++) {
        snprintf(key, sizeof(key), "tgt_%d", i);
        nvs_erase_key(h, key); /* Ignore errors if key doesn't exist */
    }

    esp_err_t ret = nvs_set_u32(h, "tgts_n", (uint32_t)count);
    if (ret != ESP_OK) { nvs_close(h); xSemaphoreGive(g_nvs_lock); return ret; }

    for (size_t i = 0; i < count; i++) {
        snprintf(key, sizeof(key), "tgt_%d", (int)i);
        ret = nvs_set_blob(h, key, &targets[i], sizeof(deauth_target_t));
        if (ret != ESP_OK) { nvs_close(h); xSemaphoreGive(g_nvs_lock); return ret; }
    }

    ret = nvs_commit(h);
    nvs_close(h);
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

esp_err_t persist_load_targets(deauth_target_t *targets, size_t max, size_t *count)
{
    if (!targets || !count || max == 0 || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    *count = 0;
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(false);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_ERR_NOT_FOUND; }

    uint32_t n = 0;
    esp_err_t ret = nvs_get_u32(h, "tgts_n", &n);
    if (ret != ESP_OK || n == 0) { nvs_close(h); xSemaphoreGive(g_nvs_lock); return ESP_OK; }

    if (n > MAX_SAVED_TARGETS) n = MAX_SAVED_TARGETS;
    if (n > max) n = (uint32_t)max;

    char key[16];
    for (uint32_t i = 0; i < n; i++) {
        snprintf(key, sizeof(key), "tgt_%d", (int)i);
        size_t sz = sizeof(deauth_target_t);
        ret = nvs_get_blob(h, key, &targets[i], &sz);
        if (ret != ESP_OK) { break; }
        (*count)++;
    }

    nvs_close(h);
    xSemaphoreGive(g_nvs_lock);
    return ESP_OK;
}

/* ── Wordlist metadata persistence ───────────────────────────────────── */

esp_err_t persist_save_wordlist_meta(const char *name, size_t count, uint32_t duration_ms)
{
    if (!name || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(true);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_FAIL; }

    wordlist_meta_t m;
    memset(&m, 0, sizeof(m));
    snprintf(m.name, sizeof(m.name), "%s", name);
    m.count = count;
    m.duration_ms = duration_ms;
    
    esp_err_t ret = nvs_set_blob(h, "wl_meta", &m, sizeof(m));
    if (ret == ESP_OK) ret = nvs_commit(h);
    
    nvs_close(h);
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

esp_err_t persist_load_wordlist_meta(char *name_out, size_t name_sz, size_t *count_out, uint32_t *duration_out)
{
    if (!name_out || !name_sz || !count_out || !duration_out || !g_nvs_lock) return ESP_ERR_INVALID_ARG;
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(false);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_ERR_NOT_FOUND; }

    wordlist_meta_t m;
    size_t sz = sizeof(m);
    esp_err_t ret = nvs_get_blob(h, "wl_meta", &m, &sz);
    nvs_close(h);
    
    if (ret == ESP_OK) {
        snprintf(name_out, name_sz, "%s", m.name);
        *count_out = m.count;
        *duration_out = m.duration_ms;
    }
    
    xSemaphoreGive(g_nvs_lock);
    return ret;
}

/* ── Factory reset ───────────────────────────────────────────────────── */

esp_err_t persist_erase_all(void)
{
    if (!g_nvs_lock) return ESP_ERR_INVALID_STATE;
    
    xSemaphoreTake(g_nvs_lock, portMAX_DELAY);
    nvs_handle_t h = open_handle(true);
    if (!h) { xSemaphoreGive(g_nvs_lock); return ESP_FAIL; }
    
    esp_err_t ret = nvs_erase_all(h);
    if (ret == ESP_OK) ret = nvs_commit(h);
    
    nvs_close(h);
    xSemaphoreGive(g_nvs_lock);
    return ret;
}
