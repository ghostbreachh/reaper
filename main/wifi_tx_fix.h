/*
 * wifi_tx_fix.h — makes raw 802.11 TX work on ESP32-S3 in sniffer mode.
 *
 * PROBLEM:  esp_wifi_80211_tx(WIFI_IF_AP, ...) returns
 *           ESP_ERR_WIFI_IF ("invalid interface 1") when the radio is in
 *           WIFI_MODE_NULL (pure sniffer). Every deauth/DOJ/beacon frame
 *           fails and the attack task spams errors forever.
 *
 * FIX:      lazily bring up a hidden, zero-capacity AP (empty SSID,
 *           max_connection=0) so the AP interface becomes valid, then
 *           re-enable promiscuous RX so the sniffer keeps working.
 *           Idempotent, self-healing (retries after driver restarts).
 */
#ifndef WIFI_TX_FIX_H
#define WIFI_TX_FIX_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_log.h"
#include "esp_wifi.h"

#include "wifi_sniffer.h"

#ifdef __cplusplus
extern "C" {
#endif

// Fallback declaration if not declared in wifi_sniffer.h
extern _Atomic uint8_t g_wifi_fixed_channel;

static const char *WIFI_TX_FIX_TAG = "txfix";
static bool wifi_tx_iface_ready = false;

/* Bring up a phantom AP so WIFI_IF_AP is valid. Safe to call repeatedly. */
static inline esp_err_t wifi_tx_iface_ensure(void)
{
    if (wifi_tx_iface_ready) {
        return ESP_OK;
    }

    esp_err_t ret;

    wifi_mode_t mode = WIFI_MODE_NULL;
    ret = esp_wifi_get_mode(&mode);
    if (ret != ESP_OK) {
        return ret;
    }

    if (mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA) {
        wifi_tx_iface_ready = true;          /* AP iface already valid */
        return ESP_OK;
    }

    uint8_t fixed_ch = atomic_load(&g_wifi_fixed_channel);
    if (fixed_ch > 0) {
        esp_wifi_set_channel(fixed_ch, WIFI_SECOND_CHAN_NONE);
    }

    /* Phantom AP: no real SSID, no client slots, hidden. */
    wifi_config_t ap = { 0 };
    ap.ap.ssid_len       = 0;
    ap.ap.channel        = 1;
    ap.ap.max_connection = 0;
    ap.ap.ssid_hidden    = true;
    ap.ap.authmode       = WIFI_AUTH_OPEN;

    ret = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (ret != ESP_OK && ret != ESP_ERR_WIFI_NOT_STARTED && ret != ESP_ERR_INVALID_STATE) {
        return ret;
    }

    ret = esp_wifi_set_config(WIFI_IF_AP, &ap);
    if (ret != ESP_OK) {
        /* Some IDF builds reject a zero-length SSID; fall back to 1 char. */
        ap.ap.ssid[0] = '\0';
        ap.ap.ssid_len = 1;
        ret = esp_wifi_set_config(WIFI_IF_AP, &ap);
        if (ret != ESP_OK) {
            return ret;
        }
    }

    ret = esp_wifi_start();
    if (ret != ESP_OK && ret != ESP_ERR_WIFI_NOT_STARTED && ret != ESP_ERR_INVALID_STATE) {
        return ret;
    }

    /* Promiscuous RX resets on start — re-arm so sniffing keeps working. */
    ret = esp_wifi_set_promiscuous(true);
    if (ret != ESP_OK) {
        ESP_LOGW(WIFI_TX_FIX_TAG, "re-enable promiscuous: %s", esp_err_to_name(ret));
    }

    /* Re-apply fixed channel if one was set before we restarted the radio. */
    fixed_ch = atomic_load(&g_wifi_fixed_channel);
    if (fixed_ch > 0) {
        esp_wifi_set_channel(fixed_ch, WIFI_SECOND_CHAN_NONE);
    }

    wifi_tx_iface_ready = true;
    ESP_LOGI(WIFI_TX_FIX_TAG, "phantom AP up — raw TX enabled");
    return ESP_OK;
}

/* Replacement for esp_wifi_80211_tx(...). Self-healing on interface loss.
 * NOTE: ESP-IDF v6.0.2 keeps the bool 4th argument (en_sys_seq). */
static inline esp_err_t wifi_tx_safe(wifi_interface_t ifx, const void *buf, int len)
{
    esp_err_t ret = wifi_tx_iface_ensure();
    if (ret != ESP_OK) {
        return ret;
    }

    ret = esp_wifi_80211_tx(ifx, buf, len, false);
    if (ret == ESP_ERR_WIFI_IF) {
        /* Driver restarted under us (sniffer stop/start etc.) — re-arm once. */
        wifi_tx_iface_ready = false;
        ret = wifi_tx_iface_ensure();
        if (ret == ESP_OK) {
            ret = esp_wifi_80211_tx(ifx, buf, len, false);
        }
    }
    return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* WIFI_TX_FIX_H */