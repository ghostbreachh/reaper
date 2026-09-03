#include "ai_rogue_detector.h"
#include "common_types.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* ============================================================================
 *  ROGUE AP DETECTOR (evil twin clustering)
 * ============================================================================
 *
 *  Branch A — Full evil-twin ML model
 *    Decision: REJECTED. Rogue detection is rule-based clustering; ML adds
 *              little beyond what OUI/channel/cipher comparison already gives.
 *  Branch B — SSID group + BSSID/cipher/channel heuristic clustering
 *    Decision: ACCEPTED. Groups APs by SSID, flags mismatched OUI, channel,
 *              cipher, or channel-hop anomalies.
 *  Branch C — External IDS/rules engine
 *    Decision: REJECTED. Keep it inline; no external dependency.
 */

static const char *TAG = "ai_rogue";

static ai_rogue_alert_t g_alerts[16];
static uint8_t          g_alert_count = 0;
static bool             g_init_done   = false;
static uint64_t         g_last_scan_us = 0;
static const uint64_t    g_scan_interval_us = 1000000ULL; /* 1s throttle */

esp_err_t ai_rogue_detector_init(void)
{
    if (g_init_done) return ESP_OK;

    memset(g_alerts, 0, sizeof(g_alerts));
    g_alert_count = 0;
    g_init_done = true;
    ESP_LOGI(TAG, "rogue detector init");
    return ESP_OK;
}

static void add_alert(const char *ssid, const uint8_t *bssid, const uint8_t *oui,
                      uint8_t channel, uint8_t flags, const char *reason)
{
    if (g_alert_count >= 16) return;

    ai_rogue_alert_t *a = &g_alerts[g_alert_count++];
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    memcpy(a->bssid, bssid, 6);
    if (oui) memcpy(a->oui, oui, 3);
    a->channel = channel;
    a->flags = flags;
    snprintf(a->reason, sizeof(a->reason), "%s", reason);
}

esp_err_t ai_rogue_detector_scan(void)
{
    if (!g_init_done) return ESP_ERR_INVALID_STATE;

    uint64_t now = esp_timer_get_time();
    if (now - g_last_scan_us < g_scan_interval_us) return ESP_OK;
    g_last_scan_us = now;

    g_alert_count = 0;
    memset(g_alerts, 0, sizeof(g_alerts));

    /* Group APs by SSID index for clustering */
    typedef struct { uint8_t idx; uint8_t bssid[6]; uint8_t oui[3]; uint8_t channel; bool open; } grp_ap_t;
    static grp_ap_t groups[8][16];
    static uint8_t  grp_count[8];
    memset(groups, 0, sizeof(groups));
    memset(grp_count, 0, sizeof(grp_count));

    extern ap_info_t *g_ap_list;
    extern uint32_t    g_ap_count;

    for (uint32_t i = 0; i < g_ap_count && i < 64; i++) {
        const ap_info_t *ap = &g_ap_list[i];
        if (ap->ssid[0] == '\0') continue;

        /* Hash SSID to group index */
        uint8_t gidx = 0;
        for (int j = 0; ap->ssid[j] != '\0' && j < 32; j++) gidx += (uint8_t)ap->ssid[j];
        gidx %= 8;
        if (grp_count[gidx] >= 16) continue;

        grp_ap_t *g = &groups[gidx][grp_count[gidx]++];
        g->idx = (uint8_t)i;
        memcpy(g->bssid, ap->bssid, 6);
        memcpy(g->oui, ap->bssid, 3);
        g->channel = ap->channel;
        g->open = !ap->pmf_capable && !ap->wpa3_sae && ap->akm_count == 0;
    }

    /* Detect anomalies within groups */
    for (uint8_t g = 0; g < 8; g++) {
        if (grp_count[g] < 2) continue;

        for (uint8_t a = 0; a < grp_count[g]; a++) {
            for (uint8_t b = a + 1; b < grp_count[g]; b++) {
                const grp_ap_t *x = &groups[g][a];
                const grp_ap_t *y = &groups[g][b];
                uint8_t flags = 0;
                char reason[64] = "";

                if (memcmp(x->oui, y->oui, 3) != 0) {
                    flags |= AI_ROGUE_FLAG_DIFF_OUI;
                    snprintf(reason, sizeof(reason), "diff OUI");
                }
                if (x->channel != y->channel) {
                    flags |= AI_ROGUE_FLAG_DIFF_CHAN;
                    if (reason[0]) snprintf(reason + strlen(reason), sizeof(reason) - strlen(reason), "; diff chan");
                }
                if (x->open != y->open) {
                    flags |= AI_ROGUE_FLAG_DIFF_CIPHER;
                    if (reason[0]) snprintf(reason + strlen(reason), sizeof(reason) - strlen(reason), "; mixed cipher");
                }

                if (flags != 0) {
                    add_alert(g_ap_list[x->idx].ssid, x->bssid, x->oui, x->channel, flags, reason);
                    break; /* one alert per pair */
                }
            }
        }
    }

    ESP_LOGI(TAG, "rogue scan: %d alerts", g_alert_count);
    return ESP_OK;
}

uint8_t ai_rogue_detector_alert_count(void)
{
    return g_alert_count;
}

esp_err_t ai_rogue_detector_get_alert(uint8_t idx, ai_rogue_alert_t *out)
{
    if (out == NULL || idx >= g_alert_count) return ESP_ERR_INVALID_ARG;
    memcpy(out, &g_alerts[idx], sizeof(*out));
    return ESP_OK;
}

esp_err_t ai_rogue_detector_json(char *buf, size_t bufsz)
{
    int w = snprintf(buf, bufsz, "[");
    if (w < 0 || (size_t)w >= bufsz) return ESP_ERR_NO_MEM;

    for (uint8_t i = 0; i < g_alert_count && (size_t)w < bufsz; i++) {
        int n = snprintf(buf + w, bufsz - w,
            "%s{\"ssid\":\"%s\",\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
            "\"oui\":\"%02X:%02X:%02X\",\"channel\":%d,\"flags\":%d,\"reason\":\"%s\"}",
            i == 0 ? "" : ",",
            g_alerts[i].ssid,
            g_alerts[i].bssid[0], g_alerts[i].bssid[1], g_alerts[i].bssid[2],
            g_alerts[i].bssid[3], g_alerts[i].bssid[4], g_alerts[i].bssid[5],
            g_alerts[i].oui[0], g_alerts[i].oui[1], g_alerts[i].oui[2],
            g_alerts[i].channel, g_alerts[i].flags, g_alerts[i].reason);
        if (n < 0 || (size_t)n >= bufsz - w) break;
        w += n;
    }

    if ((size_t)w + 1 >= bufsz) return ESP_ERR_NO_MEM;
    buf[w++] = ']';
    buf[w] = '\0';
    return ESP_OK;
}

void ai_rogue_detector_deinit(void)
{
    g_alert_count = 0;
    g_init_done = false;
    ESP_LOGI(TAG, "rogue detector deinit");
}
