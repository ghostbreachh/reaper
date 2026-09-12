#include "offensive.h"
#include "handshake_crack.h"
#include "wifi_sniffer.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <stdarg.h>

#include "esp_log.h"
#include "esp_mac.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#ifndef MACSTR
#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#endif

static const char *TAG = "offensive";

static uint32_t s_mode = OFF_MODE_NONE;
static SemaphoreHandle_t s_lock = NULL;

static off_pmkid_t      s_pmkid;
static off_sae_timing_t s_sae_timing;
static off_dragonfly_t  s_dragonfly;
static off_ft_t         s_ft;
static off_11k_t        s_11k;
static off_11v_t        s_11v;
static off_wps_t        s_wps;
static off_eap_t        s_eap;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static bool json_append(char *buf, size_t bufsz, int *n, const char *fmt, ...)
{
    if (buf == NULL || bufsz == 0 || n == NULL || *n >= (int)bufsz) {
        return false;
    }

    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(buf + *n, bufsz - (size_t)(*n), fmt, args);
    va_end(args);

    if (written < 0 || (size_t)(*n + written) >= bufsz) {
        *n = (int)bufsz - 1;
        return false;
    }

    *n += written;
    return true;
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t offensive_init(void)
{
    if (s_lock != NULL) {
        return ESP_OK;
    }

    s_lock = xSemaphoreCreateMutex();
    if (s_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    
    memset(&s_pmkid, 0, sizeof(s_pmkid));
    memset(&s_sae_timing, 0, sizeof(s_sae_timing));
    memset(&s_dragonfly, 0, sizeof(s_dragonfly));
    memset(&s_ft, 0, sizeof(s_ft));
    memset(&s_11k, 0, sizeof(s_11k));
    memset(&s_11v, 0, sizeof(s_11v));
    memset(&s_wps, 0, sizeof(s_wps));
    memset(&s_eap, 0, sizeof(s_eap));
    s_mode = OFF_MODE_NONE;
    
    xSemaphoreGive(s_lock);
    
    ESP_LOGI(TAG, "Offensive research module initialized");
    return ESP_OK;
}

esp_err_t offensive_deinit(void)
{
    if (s_lock == NULL) {
        return ESP_OK;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    memset(&s_pmkid, 0, sizeof(s_pmkid));
    memset(&s_sae_timing, 0, sizeof(s_sae_timing));
    memset(&s_dragonfly, 0, sizeof(s_dragonfly));
    memset(&s_ft, 0, sizeof(s_ft));
    memset(&s_11k, 0, sizeof(s_11k));
    memset(&s_11v, 0, sizeof(s_11v));
    memset(&s_wps, 0, sizeof(s_wps));
    memset(&s_eap, 0, sizeof(s_eap));
    s_mode = OFF_MODE_NONE;
    xSemaphoreGive(s_lock);

    vSemaphoreDelete(s_lock);
    s_lock = NULL;
    
    return ESP_OK;
}

esp_err_t offensive_set_mode(uint32_t mode_mask)
{
    if (s_lock == NULL) return ESP_ERR_INVALID_STATE;
    
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_mode = mode_mask;
    xSemaphoreGive(s_lock);
    
    ESP_LOGI(TAG, "Offensive mode set: 0x%08" PRIx32, mode_mask);
    return ESP_OK;
}

uint32_t offensive_get_mode(void)
{
    if (s_lock == NULL) return OFF_MODE_NONE;
    
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t mode = s_mode;
    xSemaphoreGive(s_lock);
    
    return mode;
}

/* -------------------------------------------------------------------------
 *  Packet Feed (Called from Wi-Fi Sniffer Observer)
 * ----------------------------------------------------------------------- */

esp_err_t offensive_feed(const uint8_t *data, size_t len,
                         const uint8_t *bssid, const uint8_t *sta,
                         uint8_t channel, int8_t rssi, uint64_t ts_us)
{
    if (s_lock == NULL || !data || len < 24 || !bssid) {
        return ESP_ERR_INVALID_ARG;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    
    if (s_mode == OFF_MODE_NONE) {
        xSemaphoreGive(s_lock);
        return ESP_OK;
    }

    /* Correct 802.11 Frame Control parsing */
    uint16_t fc = (uint16_t)(data[0] | (data[1] << 8));
    uint8_t type = (fc >> 2) & 0x03;
    uint8_t subtype = (fc >> 4) & 0x0F;

    /* ---------- PMKID (Sync from handshake_crack) ---------- */
    if (s_mode & OFF_MODE_PMKID) {
        handshake_t hs;
        if (handshake_get_snapshot(&hs) == ESP_OK && hs.has_pmkid && !s_pmkid.valid) {
            if (memcmp(hs.ap_mac, bssid, 6) == 0) {
                memcpy(s_pmkid.ap_bssid, bssid, 6);
                memcpy(s_pmkid.pmkid, hs.pmkid, 16);
                s_pmkid.capture_time_us = (uint32_t)ts_us;
                s_pmkid.valid = true;
                ESP_LOGI(TAG, "PMKID synced for " MACSTR, MAC2STR(bssid));
            }
        }
    }

    /* ---------- SAE Timing & Dragonfly (Authentication Frames) ---------- */
    if ((s_mode & OFF_MODE_SAE_TIMING) || (s_mode & OFF_MODE_DRAGONFLY)) {
        /* Management Frame (Type 0), Authentication (Subtype 11) */
        if (type == 0 && subtype == 11 && len >= 30) {
            uint16_t auth_alg = data[24] | (data[25] << 8);
            if (auth_alg == 3) { /* SAE Auth Algorithm */
                uint16_t auth_seq = data[26] | (data[27] << 8);
                uint32_t now_ms = (uint32_t)(ts_us / 1000);
                
                if (s_mode & OFF_MODE_SAE_TIMING) {
                    if (auth_seq == 1) { /* Commit */
                        s_sae_timing.commit_time_us = now_ms;
                        memcpy(s_sae_timing.ap_bssid, bssid, 6);
                    } else if (auth_seq == 2 && s_sae_timing.commit_time_us > 0) { /* Confirm */
                        s_sae_timing.confirm_time_us = now_ms;
                        s_sae_timing.delta_us = now_ms - s_sae_timing.commit_time_us;
                        ESP_LOGI(TAG, "SAE timing delta: %" PRIu32 " ms", s_sae_timing.delta_us);
                        s_sae_timing.commit_time_us = 0; /* Reset for next */
                    }
                }
                
                if ((s_mode & OFF_MODE_DRAGONFLY) && !s_dragonfly.valid && auth_seq == 1) {
                    memcpy(s_dragonfly.ap_bssid, bssid, 6);
                    wifi_sniffer_get_ssid_for_bssid(bssid, (char*)s_dragonfly.ssid, sizeof(s_dragonfly.ssid));
                    s_dragonfly.valid = true;
                    ESP_LOGI(TAG, "Dragonfly SAE Commit captured");
                }
            }
        }
    }

    /* ---------- 802.11r FT Handshake (Reassociation Request) ---------- */
    if (s_mode & OFF_MODE_FT) {
        /* Management Frame (Type 0), Reassociation Request (Subtype 2) */
        if (type == 0 && subtype == 2 && sta && !s_ft.valid) {
            memcpy(s_ft.ap_bssid, bssid, 6);
            memcpy(s_ft.sta_mac, sta, 6);
            s_ft.reassoc_time_us = (uint32_t)(ts_us / 1000);
            s_ft.valid = true;
            ESP_LOGI(TAG, "FT Reassociation Request captured");
        }
    }

    /* ---------- 802.11k Neighbor Report (Beacons/Probe Responses) ---------- */
    if (s_mode & OFF_MODE_11K) {
        /* Management Frame (Type 0), Beacon (8) or Probe Response (5) */
        if (type == 0 && (subtype == 8 || subtype == 5)) {
            s_11k.channel = channel;
            memcpy(s_11k.neighbor_bssid, bssid, 6);
            if (sta) memcpy(s_11k.target_bssid, sta, 6);
        }
    }

    /* ---------- 802.11v BTM (Action Frames) ---------- */
    if (s_mode & OFF_MODE_11V) {
        /* Management Frame (Type 0), Action (Subtype 13) */
        if (type == 0 && subtype == 13 && len >= 26) {
            uint8_t category = data[24];
            if (category == 10) { /* WNM (Wireless Network Management) */
                uint8_t action = data[25];
                if (action == 7) { /* BSS Transition Management Request */
                    memcpy(s_11v.ap_bssid, bssid, 6);
                    /* Disassoc timer is typically at offset 28 in BTM Req */
                    if (len >= 29) {
                        s_11v.disassoc_timer = data[28]; 
                    }
                    ESP_LOGI(TAG, "BTM Request captured from " MACSTR, MAC2STR(bssid));
                }
            }
        }
    }

    /* ---------- WPS & Enterprise EAP (Data Frames) ---------- */
    if ((s_mode & OFF_MODE_WPS) || (s_mode & OFF_MODE_EAP)) {
        /* Data Frame (Type 2) */
        if (type == 2) {
            if ((s_mode & OFF_MODE_WPS) && !s_wps.valid) {
                memcpy(s_wps.ap_bssid, bssid, 6);
                if (sta) memcpy(s_wps.enrollee_mac, sta, 6);
                size_t copy = len > sizeof(s_wps.m1) ? sizeof(s_wps.m1) : len;
                memcpy(s_wps.m1, data, copy);
                s_wps.m1_len = (uint16_t)copy;
                s_wps.valid = true;
                ESP_LOGI(TAG, "WPS Data Frame captured");
            }
            
            if (s_mode & OFF_MODE_EAP) {
                memcpy(s_eap.ap_bssid, bssid, 6);
                if (sta) memcpy(s_eap.sta_mac, sta, 6);
                size_t off = 24; /* Skip MAC header */
                if (len > off) {
                    size_t copy = len - off;
                    if (copy > sizeof(s_eap.challenge)) copy = sizeof(s_eap.challenge);
                    memcpy(s_eap.challenge, data + off, copy);
                    s_eap.challenge_len = (uint8_t)copy;
                }
            }
        }
    }

    xSemaphoreGive(s_lock);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Getters
 * ----------------------------------------------------------------------- */

#define SAFE_GETTER(func_name, struct_type, state_var) \
esp_err_t func_name(struct_type *out) { \
    if (!out || s_lock == NULL) return ESP_ERR_INVALID_ARG; \
    xSemaphoreTake(s_lock, portMAX_DELAY); \
    memcpy(out, &state_var, sizeof(struct_type)); \
    xSemaphoreGive(s_lock); \
    return ESP_OK; \
}

SAFE_GETTER(offensive_get_pmkid, off_pmkid_t, s_pmkid)
SAFE_GETTER(offensive_get_sae_timing, off_sae_timing_t, s_sae_timing)
SAFE_GETTER(offensive_get_dragonfly, off_dragonfly_t, s_dragonfly)
SAFE_GETTER(offensive_get_ft, off_ft_t, s_ft)
SAFE_GETTER(offensive_get_11k, off_11k_t, s_11k)
SAFE_GETTER(offensive_get_11v, off_11v_t, s_11v)
SAFE_GETTER(offensive_get_wps, off_wps_t, s_wps)
SAFE_GETTER(offensive_get_eap, off_eap_t, s_eap)

/* -------------------------------------------------------------------------
 *  JSON Report
 * ----------------------------------------------------------------------- */

esp_err_t offensive_json(char *buf, size_t bufsz)
{
    if (!buf || bufsz == 0 || s_lock == NULL) return ESP_ERR_INVALID_ARG;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    
    int n = 0;
    json_append(buf, bufsz, &n, "{\"mode\":\"0x%08" PRIx32 "\"", s_mode);

    if (s_pmkid.valid) {
        json_append(buf, bufsz, &n, ",\"pmkid\":{\"ap_bssid\":\"" MACSTR "\",\"pmkid\":\"", MAC2STR(s_pmkid.ap_bssid));
        for (int i = 0; i < 16 && n < (int)bufsz - 3; i++) {
            json_append(buf, bufsz, &n, "%02x", s_pmkid.pmkid[i]);
        }
        json_append(buf, bufsz, &n, "\"}");
    }

    if (s_sae_timing.commit_time_us > 0 || s_sae_timing.delta_us > 0) {
        json_append(buf, bufsz, &n, ",\"sae_timing\":{\"delta_ms\":%" PRIu32 "}", s_sae_timing.delta_us);
    }

    if (s_ft.valid) {
        json_append(buf, bufsz, &n, ",\"ft\":{\"ap_bssid\":\"" MACSTR "\",\"sta_mac\":\"" MACSTR "\"}",
                    MAC2STR(s_ft.ap_bssid), MAC2STR(s_ft.sta_mac));
    }

    if (s_wps.valid) {
        json_append(buf, bufsz, &n, ",\"wps\":{\"ap_bssid\":\"" MACSTR "\",\"m1_len\":%d}",
                    MAC2STR(s_wps.ap_bssid), s_wps.m1_len);
    }

    if (s_eap.challenge_len > 0) {
        json_append(buf, bufsz, &n, ",\"eap\":{\"ap_bssid\":\"" MACSTR "\",\"bytes\":%d}",
                    MAC2STR(s_eap.ap_bssid), s_eap.challenge_len);
    }

    json_append(buf, bufsz, &n, "}");
    
    xSemaphoreGive(s_lock);
    
    return (n >= (int)bufsz) ? ESP_ERR_NO_MEM : ESP_OK;
}
