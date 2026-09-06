#include "offensive.h"
#include "handshake_crack.h"
#include "wifi_sniffer.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_log.h"

static const char *TAG = "offensive";

/* Global state — single writer from wifi sniffer task. */
static uint32_t s_mode = OFF_MODE_NONE;

/* Feature state machines. */
static off_pmkid_t      s_pmkid;
static off_sae_timing_t  sae_timing;
static off_dragonfly_t   s_dragonfly;
static off_ft_t          s_ft;
static off_11k_t         s_11k;
static off_11v_t         s_11v;
static off_wps_t         s_wps;
static off_eap_t         s_eap;

static void reset_pmkid(void)
{
    memset(&s_pmkid, 0, sizeof(s_pmkid));
    s_pmkid.valid = false;
}

static void reset_sae_timing(void)
{
    memset(&sae_timing, 0, sizeof(sae_timing));
}

static void reset_dragonfly(void)
{
    memset(&s_dragonfly, 0, sizeof(s_dragonfly));
    s_dragonfly.valid = false;
}

static void reset_ft(void)
{
    memset(&s_ft, 0, sizeof(s_ft));
    s_ft.valid = false;
}

static void reset_11k(void)
{
    memset(&s_11k, 0, sizeof(s_11k));
}

static void reset_11v(void)
{
    memset(&s_11v, 0, sizeof(s_11v));
}

static void reset_wps(void)
{
    memset(&s_wps, 0, sizeof(s_wps));
    s_wps.valid = false;
}

static void reset_eap(void)
{
    memset(&s_eap, 0, sizeof(s_eap));
}

esp_err_t offensive_init(void)
{
    memset(&s_pmkid, 0, sizeof(s_pmkid));
    memset(&sae_timing, 0, sizeof(sae_timing));
    memset(&s_dragonfly, 0, sizeof(s_dragonfly));
    memset(&s_ft, 0, sizeof(s_ft));
    memset(&s_11k, 0, sizeof(s_11k));
    memset(&s_11v, 0, sizeof(s_11v));
    memset(&s_wps, 0, sizeof(s_wps));
    memset(&s_eap, 0, sizeof(s_eap));
    s_mode = OFF_MODE_NONE;
    return ESP_OK;
}

esp_err_t offensive_deinit(void)
{
    offensive_init();
    return ESP_OK;
}

esp_err_t offensive_set_mode(uint32_t mode_mask)
{
    s_mode = mode_mask;
    ESP_LOGI(TAG, "offensive mode: 0x%08" PRIx32, s_mode);
    return ESP_OK;
}

uint32_t offensive_get_mode(void)
{
    return s_mode;
}

/* ---------------------------------------------------------------------------
 *  Generic parser — called from wifi_sniffer on every captured frame.
 * --------------------------------------------------------------------------- */
esp_err_t offensive_feed(const uint8_t *data, size_t len,
                         const uint8_t *bssid, const uint8_t *sta,
                         uint8_t channel, int8_t rssi, uint64_t ts_us)
{
    if (!data || len == 0 || !bssid) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_mode == OFF_MODE_NONE) {
        return ESP_OK;
    }

    /* Frame type/subtype from radiotap / 802.11 header offset. */
    if (len < 26) {
        return ESP_OK;
    }
    uint8_t frame_ctrl = data[24];
    uint8_t type = (frame_ctrl >> 2) & 0x3;
    uint8_t subtype = (frame_ctrl >> 4) & 0xF;

    /* ---------- PMKID (EAPOL M1 with PMKID KDE) ---------- */
    if (s_mode & OFF_MODE_PMKID) {
        if (type == 2 && subtype == 0x0B && memcmp(bssid, g_hs.ap_mac, 6) == 0) {
            /* Extract PMKID from existing handshake capture if available. */
            if (g_hs.has_pmkid && !s_pmkid.valid) {
                memcpy(s_pmkid.ap_bssid, bssid, 6);
                memcpy(s_pmkid.pmkid, g_hs.pmkid, 16);
                s_pmkid.capture_time_us = ts_us;
                s_pmkid.valid = true;
                ESP_LOGI(TAG, "PMKID captured for "MACSTR"", MAC2STR(bssid));
            }
        }
    }

    /* ---------- SAE timing (commit/confirm) ---------- */
    if (s_mode & OFF_MODE_SAE_TIMING) {
        if (type == 2 && subtype == 0x0B && sta) {
            /* Auth frame: we measure time delta between commit/confirm. */
            uint32_t now = (uint32_t)(ts_us / 1000);
            if (sae_timing.commit_time_us == 0) {
                sae_timing.commit_time_us = now;
                memcpy(sae_timing.ap_bssid, bssid, 6);
            } else {
                sae_timing.confirm_time_us = now;
                sae_timing.delta_us = now - sae_timing.commit_time_us;
                ESP_LOGI(TAG, "SAE timing delta %" PRIu32 " ms", sae_timing.delta_us);
            }
        }
    }

    /* ---------- Dragonfly / SAE simulation ---------- */
    if (s_mode & OFF_MODE_DRAGONFLY) {
        if (type == 2 && subtype == 0x0B && !s_dragonfly.valid) {
            memcpy(s_dragonfly.ap_bssid, bssid, 6);
            wifi_sniffer_get_ssid_for_bssid(bssid, s_dragonfly.ssid, sizeof(s_dragonfly.ssid));
            s_dragonfly.valid = true;
            ESP_LOGI(TAG, "Dragonfly capture state initialized");
        }
    }

    /* ---------- 802.11r FT handshake ---------- */
    if (s_mode & OFF_MODE_FT) {
        if (type == 2 && subtype == 0x08) {
            /* Reassociation request: capture FT-related fields. */
            if (!s_ft.valid) {
                memcpy(s_ft.ap_bssid, bssid, 6);
                memcpy(s_ft.sta_mac, sta, 6);
                s_ft.reassoc_time_us = (uint32_t)(ts_us / 1000);
                s_ft.valid = true;
                ESP_LOGI(TAG, "FT reassoc captured");
            }
        }
    }

    /* ---------- 802.11k neighbor report injection ---------- */
    if (s_mode & OFF_MODE_11K) {
        /* State machine: store last seen BSSID + channel for injection. */
        s_11k.channel = channel;
        memcpy(s_11k.neighbor_bssid, bssid, 6);
        if (sta) {
            memcpy(s_11k.target_bssid, sta, 6);
        }
    }

    /* ---------- 802.11v BTM ---------- */
    if (s_mode & OFF_MODE_11V) {
        if (type == 0 && subtype == 0x0D) {
            /* Disassoc imminent frame from AP. */
            memcpy(s_11v.ap_bssid, bssid, 6);
            s_11v.disassoc_timer = data[25];
            ESP_LOGI(TAG, "BTM disassoc imminent from "MACSTR" in %d seconds",
                     MAC2STR(bssid), data[25]);
        }
    }

    /* ---------- WPS PixieDust ---------- */
    if (s_mode & OFF_MODE_WPS) {
        if (type == 2 && subtype == 0x0B && !s_wps.valid) {
            /* Auth frame may carry WPS IE. */
            memcpy(s_wps.ap_bssid, bssid, 6);
            if (sta) {
                memcpy(s_wps.enrollee_mac, sta, 6);
            }
            size_t copy = len > sizeof(s_wps.m1) ? sizeof(s_wps.m1) : len;
            memcpy(s_wps.m1, data, copy);
            s_wps.m1_len = (uint16_t)copy;
            s_wps.valid = true;
            ESP_LOGI(TAG, "WPS M1 captured");
        }
    }

    /* ---------- Enterprise EAP ---------- */
    if (s_mode & OFF_MODE_EAP) {
        if (type == 2 && subtype == 0x08) {
            /* Data frame with EAP payload. */
            memcpy(s_eap.ap_bssid, bssid, 6);
            if (sta) {
                memcpy(s_eap.sta_mac, sta, 6);
            }
            size_t off = len > 26 ? 26 : len;
            size_t copy = len - off;
            if (copy > sizeof(s_eap.challenge)) {
                copy = sizeof(s_eap.challenge);
            }
            memcpy(s_eap.challenge, data + off, copy);
            s_eap.challenge_len = (uint8_t)copy;
            ESP_LOGI(TAG, "Enterprise EAP capture %d bytes", s_eap.challenge_len);
        }
    }

    return ESP_OK;
}

/* ---------------------------------------------------------------------------
 *  Getters
 * --------------------------------------------------------------------------- */
esp_err_t offensive_get_pmkid(off_pmkid_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    memcpy(out, &s_pmkid, sizeof(s_pmkid));
    return ESP_OK;
}

esp_err_t offensive_get_sae_timing(off_sae_timing_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    memcpy(out, &sae_timing, sizeof(sae_timing));
    return ESP_OK;
}

esp_err_t offensive_get_dragonfly(off_dragonfly_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    memcpy(out, &s_dragonfly, sizeof(s_dragonfly));
    return ESP_OK;
}

esp_err_t offensive_get_ft(off_ft_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    memcpy(out, &s_ft, sizeof(s_ft));
    return ESP_OK;
}

esp_err_t offensive_get_11k(off_11k_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    memcpy(out, &s_11k, sizeof(s_11k));
    return ESP_OK;
}

esp_err_t offensive_get_11v(off_11v_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    memcpy(out, &s_11v, sizeof(s_11v));
    return ESP_OK;
}

esp_err_t offensive_get_wps(off_wps_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    memcpy(out, &s_wps, sizeof(s_wps));
    return ESP_OK;
}

esp_err_t offensive_get_eap(off_eap_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    memcpy(out, &s_eap, sizeof(s_eap));
    return ESP_OK;
}

/* ---------------------------------------------------------------------------
 *  JSON report
 * --------------------------------------------------------------------------- */
esp_err_t offensive_json(char *buf, size_t bufsz)
{
    if (!buf || bufsz == 0) return ESP_ERR_INVALID_ARG;
    int n = snprintf(buf, bufsz,
        "{"
        "\"mode\":\"0x%08" PRIx32 "\",", s_mode);

    if (s_pmkid.valid) {
        n += snprintf(buf + n, bufsz - n,
            "\"pmkid\":{\"ap_bssid\":\""MACSTR"\",\"pmkid\":\"", MAC2STR(s_pmkid.ap_bssid));
        for (int i = 0; i < 16 && n < (int)bufsz - 3; i++) {
            n += snprintf(buf + n, bufsz - n, "%02x", s_pmkid.pmkid[i]);
        }
        n += snprintf(buf + n, bufsz - n, "\"},");
    }

    if (sae_timing.commit_time_us > 0) {
        n += snprintf(buf + n, bufsz - n,
            "\"sae_timing\":{\"delta_ms\":%" PRIu32 "},", sae_timing.delta_us);
    }

    if (s_ft.valid) {
        n += snprintf(buf + n, bufsz - n,
            "\"ft\":{\"ap_bssid\":\""MACSTR"\",\"sta_mac\":\""MACSTR"\"},",
            MAC2STR(s_ft.ap_bssid), MAC2STR(s_ft.sta_mac));
    }

    if (s_wps.valid) {
        n += snprintf(buf + n, bufsz - n,
            "\"wps\":{\"ap_bssid\":\""MACSTR"\",\"m1_len\":%d},",
            MAC2STR(s_wps.ap_bssid), s_wps.m1_len);
    }

    if (s_eap.challenge_len > 0) {
        n += snprintf(buf + n, bufsz - n,
            "\"eap\":{\"ap_bssid\":\""MACSTR"\",\"bytes\":%d},",
            MAC2STR(s_eap.ap_bssid), s_eap.challenge_len);
    }

    /* Trim trailing comma */
    if (n > 1 && buf[n - 1] == ',') {
        buf[n - 1] = '}';
        n--;
    } else {
        buf[n++] = '}';
    }
    buf[n] = '\0';
    return ESP_OK;
}
