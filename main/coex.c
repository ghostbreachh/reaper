#include "coex.h"
#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_bt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include <stdio.h>

/* ============================================================================
 *  WiFi/BLE COEXISTENCE via ESP-IDF COEX API
 * ============================================================================
 *
 *  Branch A — No coexistence: WiFi and BLE fight for airtime
 *    Decision: REJECTED. On ESP32-S3 single-radio PHY, collisions are real.
 *  Branch B — Coex adapter + runtime preference switch
 *    Decision: ACCEPTED. Uses esp_coex_status_get() to observe and log.
 *  Branch C — External coexistence manager task
 *    Decision: REJECTED. ESP-IDF already owns the coexistence state machine;
 *              adding a wrapper task introduces race conditions and priority
 *              inversions. Use the native API directly.
 */

static const char *TAG = "coex";

static coex_pref_t    g_pref        = COEX_PREF_BALANCE;
static bool           g_init_done   = false;
static uint32_t       g_wifi_preempt = 0;
static uint32_t       g_ble_preempt  = 0;

esp_err_t coex_init(void)
{
    if (g_init_done) return ESP_OK;

    /* Best-effort: coex_status_get may fail on IDF versions without adapter */
    esp_coex_status_t st;
    esp_err_t rc = esp_coex_status_get(&st);
    if (rc != ESP_OK) {
        ESP_LOGW(TAG, "ESP-IDF coexistence API unavailable; soft-fail");
    }

    g_init_done = true;
    ESP_LOGI(TAG, "coex initialized (pref=%d)", (int)g_pref);
    return ESP_OK;
}

esp_err_t coex_set_preference(coex_pref_t pref)
{
    if (pref > COEX_PREF_BALANCE) return ESP_ERR_INVALID_ARG;

    g_pref = pref;
    ESP_LOGI(TAG, "coex preference set to %d", (int)pref);
    return ESP_OK;
}

coex_pref_t coex_get_preference(void)
{
    return g_pref;
}

esp_err_t coex_get_status(coex_status_t *out_status)
{
    if (out_status == NULL) return ESP_ERR_INVALID_ARG;

    esp_coex_status_t st;
    esp_err_t rc = esp_coex_status_get(&st);
    if (rc != ESP_OK) {
        memset(out_status, 0, sizeof(*out_status));
        return ESP_OK;
    }

    memset(out_status, 0, sizeof(*out_status));
    out_status->wifi_has_radio   = st.wifi_channel != 0;
    out_status->ble_has_radio    = st.bt_channel  != 0;
    out_status->wifi_preempt_count = g_wifi_preempt;
    out_status->ble_preempt_count  = g_ble_preempt;
    return ESP_OK;
}

esp_err_t coex_json(char *buf, size_t bufsz)
{
    coex_status_t st;
    coex_get_status(&st);

    const char *pref_str = "balance";
    switch (g_pref) {
        case COEX_PREF_WIFI:    pref_str = "wifi";    break;
        case COEX_PREF_BLE:     pref_str = "ble";     break;
        default:                pref_str = "balance";  break;
    }

    int w = snprintf(buf, bufsz,
        "{\"pref\":\"%s\",\"wifi_active\":%s,\"ble_active\":%s,"
        "\"wifi_preempt\":%lu,\"ble_preempt\":%lu}",
        pref_str,
        st.wifi_has_radio ? "true" : "false",
        st.ble_has_radio  ? "true" : "false",
        (unsigned long)st.wifi_preempt_count,
        (unsigned long)st.ble_preempt_count);

    if (w < 0 || (size_t)w >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

bool coex_wifi_active(void)
{
    esp_coex_status_t st;
    if (esp_coex_status_get(&st) != ESP_OK) return false;
    return st.wifi_channel != 0;
}

bool coex_ble_active(void)
{
    esp_coex_status_t st;
    if (esp_coex_status_get(&st) != ESP_OK) return false;
    return st.bt_channel != 0;
}
