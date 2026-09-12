#include "ai_rogue_detector.h"
#include "common_types.h"
#include "wifi_sniffer.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <inttypes.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "ai_rogue";

#define AI_ROGUE_SCAN_INTERVAL_US 1000000ULL /* 1 second */

typedef enum {
    ROGUE_SEC_OPEN = 0,
    ROGUE_SEC_PROTECTED = 1,
    ROGUE_SEC_WPA3 = 2
} rogue_sec_profile_t;

typedef struct {
    char ssid[33];
    uint8_t bssid[6];
    uint8_t oui[3];
    uint8_t channel;
    rogue_sec_profile_t sec;
} rogue_ap_entry_t;

static ai_rogue_alert_t g_alerts[AI_ROGUE_MAX_ALERTS];
static uint8_t g_alert_count = 0;

static rogue_ap_entry_t g_entries[MAX_DISCOVERED_APS];

static bool g_init_done = false;
static int64_t g_last_scan_us = 0;

static SemaphoreHandle_t g_lock = NULL;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static bool mac_is_locally_administered(const uint8_t *mac)
{
    if (mac == NULL) {
        return false;
    }

    return (mac[0] & 0x02u) != 0;
}

static rogue_sec_profile_t get_security_profile(const ap_info_t *ap)
{
    if (ap->wpa3_sae) {
        return ROGUE_SEC_WPA3;
    }

    if (ap->pmf_capable || ap->rsn_version != 0 || ap->akm_count != 0) {
        return ROGUE_SEC_PROTECTED;
    }

    return ROGUE_SEC_OPEN;
}

static void reason_append(char *reason, size_t reason_sz, const char *text)
{
    if (reason == NULL || reason_sz == 0 || text == NULL) {
        return;
    }

    size_t len = strlen(reason);

    if (len > 0) {
        snprintf(reason + len, reason_sz - len, "; %s", text);
    } else {
        snprintf(reason, reason_sz, "%s", text);
    }
}

static void escape_json_string(char *dst, size_t dst_sz, const char *src)
{
    if (dst == NULL || dst_sz == 0) {
        return;
    }

    size_t j = 0;

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    for (size_t i = 0; src[i] != '\0' && j + 1 < dst_sz; i++) {
        unsigned char c = (unsigned char)src[i];

        if (c == '"' || c == '\\') {
            if (j + 2 >= dst_sz) {
                break;
            }

            dst[j++] = '\\';
            dst[j++] = (char)c;
        } else if (isprint(c)) {
            dst[j++] = (char)c;
        } else {
            dst[j++] = '_';
        }
    }

    dst[j] = '\0';
}

static void add_alert_locked(const rogue_ap_entry_t *entry,
                             uint8_t flags,
                             uint8_t peer_count,
                             const char *reason)
{
    if (g_alert_count >= AI_ROGUE_MAX_ALERTS) {
        return;
    }

    ai_rogue_alert_t *a = &g_alerts[g_alert_count];

    memset(a, 0, sizeof(*a));

    snprintf(a->ssid, sizeof(a->ssid), "%s", entry->ssid);
    memcpy(a->bssid, entry->bssid, 6);
    memcpy(a->oui, entry->oui, 3);

    a->channel = entry->channel;
    a->flags = flags;
    a->peer_count = peer_count;

    snprintf(a->reason, sizeof(a->reason), "%s", reason != NULL ? reason : "");

    g_alert_count++;
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t ai_rogue_detector_init(void)
{
    if (g_init_done) {
        return ESP_OK;
    }

    if (g_lock == NULL) {
        g_lock = xSemaphoreCreateMutex();
        if (g_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_alerts, 0, sizeof(g_alerts));
    memset(g_entries, 0, sizeof(g_entries));

    g_alert_count = 0;
    g_last_scan_us = 0;
    g_init_done = true;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Rogue AP detector initialized");
    return ESP_OK;
}

void ai_rogue_detector_deinit(void)
{
    if (g_lock == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_alerts, 0, sizeof(g_alerts));
    memset(g_entries, 0, sizeof(g_entries));

    g_alert_count = 0;
    g_last_scan_us = 0;
    g_init_done = false;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Rogue AP detector deinitialized");
}

/* -------------------------------------------------------------------------
 *  Scan
 * ----------------------------------------------------------------------- */

esp_err_t ai_rogue_detector_scan(void)
{
    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    int64_t now = esp_timer_get_time();

    xSemaphoreTake(g_lock, portMAX_DELAY);

    if ((now - g_last_scan_us) < AI_ROGUE_SCAN_INTERVAL_US) {
        xSemaphoreGive(g_lock);
        return ESP_OK;
    }

    g_last_scan_us = now;

    g_alert_count = 0;
    memset(g_alerts, 0, sizeof(g_alerts));
    memset(g_entries, 0, sizeof(g_entries));

    xSemaphoreGive(g_lock);

    uint16_t ap_count = wifi_sniffer_get_ap_count();

    if (ap_count > MAX_DISCOVERED_APS) {
        ap_count = MAX_DISCOVERED_APS;
    }

    uint16_t entry_count = 0;

    for (uint16_t i = 0; i < ap_count; i++) {
        ap_info_t ap;

        if (wifi_sniffer_get_ap(i, &ap) != ESP_OK) {
            continue;
        }

        if (ap.ssid[0] == '\0') {
            continue;
        }

        if (strcmp(ap.ssid, "<HIDDEN>") == 0) {
            continue;
        }

        xSemaphoreTake(g_lock, portMAX_DELAY);

        rogue_ap_entry_t *e = &g_entries[entry_count];

        snprintf(e->ssid, sizeof(e->ssid), "%s", ap.ssid);
        memcpy(e->bssid, ap.bssid, 6);
        memcpy(e->oui, ap.bssid, 3);
        e->channel = ap.channel;
        e->sec = get_security_profile(&ap);

        entry_count++;

        xSemaphoreGive(g_lock);

        if (entry_count >= MAX_DISCOVERED_APS) {
            break;
        }
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    for (uint16_t i = 0; i < entry_count; i++) {
        const rogue_ap_entry_t *a = &g_entries[i];

        uint8_t flags = 0;
        uint8_t peer_count = 0;
        char reason[64] = "";

        for (uint16_t j = 0; j < entry_count; j++) {
            if (i == j) {
                continue;
            }

            const rogue_ap_entry_t *b = &g_entries[j];

            if (strcmp(a->ssid, b->ssid) != 0) {
                continue;
            }

            peer_count++;

            if (memcmp(a->oui, b->oui, 3) != 0) {
                flags |= AI_ROGUE_FLAG_DIFF_OUI;
                reason_append(reason, sizeof(reason), "diff OUI");
            }

            if (a->channel != b->channel) {
                flags |= AI_ROGUE_FLAG_DIFF_CHAN;
                reason_append(reason, sizeof(reason), "diff channel");
            }

            if (a->sec != b->sec) {
                flags |= AI_ROGUE_FLAG_DIFF_CIPHER;
                reason_append(reason, sizeof(reason), "mixed security");
            }
        }

        if (peer_count > 0 && mac_is_locally_administered(a->bssid)) {
            flags |= AI_ROGUE_FLAG_MAC_ANOMALY;
            reason_append(reason, sizeof(reason), "local MAC");
        }

        if (flags != 0) {
            add_alert_locked(a, flags, peer_count, reason);
        }
    }

    uint8_t final_count = g_alert_count;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Rogue scan complete: %u alerts", final_count);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Alert access
 * ----------------------------------------------------------------------- */

uint8_t ai_rogue_detector_alert_count(void)
{
    if (g_lock == NULL || !g_init_done) {
        return 0;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    uint8_t count = g_alert_count;
    xSemaphoreGive(g_lock);

    return count;
}

esp_err_t ai_rogue_detector_get_alert(uint8_t idx, ai_rogue_alert_t *out)
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    if (idx >= g_alert_count) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_ARG;
    }

    *out = g_alerts[idx];

    xSemaphoreGive(g_lock);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  JSON export
 * ----------------------------------------------------------------------- */

static bool json_append(char *buf, size_t bufsz, size_t *off, const char *fmt, ...)
{
    if (buf == NULL || bufsz == 0 || off == NULL || *off >= bufsz) {
        return false;
    }

    va_list args;
    va_start(args, fmt);

    int n = vsnprintf(buf + *off, bufsz - *off, fmt, args);

    va_end(args);

    if (n < 0) {
        return false;
    }

    if ((size_t)n >= bufsz - *off) {
        *off = bufsz - 1;
        return false;
    }

    *off += (size_t)n;
    return true;
}

esp_err_t ai_rogue_detector_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    ai_rogue_alert_t snapshot[AI_ROGUE_MAX_ALERTS];
    uint8_t count = 0;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    count = g_alert_count;

    if (count > AI_ROGUE_MAX_ALERTS) {
        count = AI_ROGUE_MAX_ALERTS;
    }

    memcpy(snapshot, g_alerts, sizeof(ai_rogue_alert_t) * count);

    xSemaphoreGive(g_lock);

    size_t off = 0;

    if (!json_append(buf, bufsz, &off, "[")) {
        return ESP_ERR_INVALID_SIZE;
    }

    for (uint8_t i = 0; i < count; i++) {
        char ssid_json[72];
        char reason_json[136];

        escape_json_string(ssid_json, sizeof(ssid_json), snapshot[i].ssid);
        escape_json_string(reason_json, sizeof(reason_json), snapshot[i].reason);

        if (i > 0) {
            if (!json_append(buf, bufsz, &off, ",")) {
                return ESP_ERR_INVALID_SIZE;
            }
        }

        if (!json_append(buf, bufsz, &off,
                         "{\"ssid\":\"%s\","
                         "\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
                         "\"oui\":\"%02X:%02X:%02X\","
                         "\"channel\":%u,"
                         "\"flags\":%u,"
                         "\"peer_count\":%u,"
                         "\"reason\":\"%s\"}",
                         ssid_json,
                         snapshot[i].bssid[0],
                         snapshot[i].bssid[1],
                         snapshot[i].bssid[2],
                         snapshot[i].bssid[3],
                         snapshot[i].bssid[4],
                         snapshot[i].bssid[5],
                         snapshot[i].oui[0],
                         snapshot[i].oui[1],
                         snapshot[i].oui[2],
                         (unsigned)snapshot[i].channel,
                         (unsigned)snapshot[i].flags,
                         (unsigned)snapshot[i].peer_count,
                         reason_json)) {
            return ESP_ERR_INVALID_SIZE;
        }
    }

    if (!json_append(buf, bufsz, &off, "]")) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}
