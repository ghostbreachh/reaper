#include "coex.h"

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_coex.h" /* Required for esp_coex_status_get and esp_coex_preference_set */

static const char *TAG = "coex";

static atomic_int g_pref = COEX_PREF_BALANCE;
static atomic_bool g_init_done = false;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static const char *pref_to_str(coex_pref_t pref)
{
    switch (pref) {
        case COEX_PREF_WIFI:    return "wifi";
        case COEX_PREF_BLE:     return "ble";
        case COEX_PREF_BALANCE: 
        default:                return "balance";
    }
}

static esp_coex_preference_t map_to_idf_pref(coex_pref_t pref)
{
    switch (pref) {
        case COEX_PREF_WIFI:    return ESP_COEX_PREFER_WIFI;
        case COEX_PREF_BLE:     return ESP_COEX_PREFER_BT;
        case COEX_PREF_BALANCE: 
        default:                return ESP_COEX_PREFER_BALANCE;
    }
}

/* -------------------------------------------------------------------------
 *  Public API
 * ----------------------------------------------------------------------- */

esp_err_t coex_init(void)
{
    if (atomic_load(&g_init_done)) return ESP_OK;

    /* 
     * Best-effort: Verify the coexistence API is available. 
     * On some IDF configurations, this might return ESP_ERR_NOT_SUPPORTED.
     */
    esp_coex_status_t st = esp_coex_status_get();
    (void)st; /* Suppress unused variable warning if we just use it for the check */

    atomic_store(&g_init_done, true);
    ESP_LOGI(TAG, "Coexistence initialized (pref=%s)", pref_to_str(atomic_load(&g_pref)));
    return ESP_OK;
}

esp_err_t coex_set_preference(coex_pref_t pref)
{
    if (pref > COEX_PREF_BALANCE) return ESP_ERR_INVALID_ARG;

    atomic_store(&g_pref, pref);
    
    /* 
     * CRITICAL FIX: Actually apply the preference to the ESP-IDF hardware arbiter.
     * Without this, changing the preference does nothing to the radio.
     */
    esp_coex_preference_t idf_pref = map_to_idf_pref(pref);
    esp_err_t rc = esp_coex_preference_set(idf_pref);
    
    if (rc != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set hardware coex preference: %s", esp_err_to_name(rc));
    } else {
        ESP_LOGI(TAG, "Coex preference set to %s", pref_to_str(pref));
    }
    
    return rc;
}

coex_pref_t coex_get_preference(void)
{
    return (coex_pref_t)atomic_load(&g_pref);
}

esp_err_t coex_get_status(coex_status_t *out_status)
{
    if (out_status == NULL) return ESP_ERR_INVALID_ARG;

    memset(out_status, 0, sizeof(*out_status));

    /* 
     * CRITICAL FIX: esp_coex_status_get() returns an enum, not a struct pointer.
     * Map the IDF enum to our abstract boolean flags.
     */
    esp_coex_status_t st = esp_coex_status_get();
    
    switch (st) {
        case ESP_COEX_STATUS_WIFI_ACTIVE:
            out_status->wifi_has_radio = true;
            break;
        case ESP_COEX_STATUS_BT_ACTIVE:
            out_status->ble_has_radio = true;
            break;
        case ESP_COEX_STATUS_WIFI_BT_ACTIVE:
            out_status->wifi_has_radio = true;
            out_status->ble_has_radio = true;
            break;
        default:
            /* IDLE or unknown */
            break;
    }

    return ESP_OK;
}

esp_err_t coex_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;

    coex_status_t st;
    coex_get_status(&st);

    coex_pref_t pref = (coex_pref_t)atomic_load(&g_pref);

    int w = snprintf(buf, bufsz,
        "{\"pref\":\"%s\",\"wifi_active\":%s,\"ble_active\":%s}",
        pref_to_str(pref),
        st.wifi_has_radio ? "true" : "false",
        st.ble_has_radio  ? "true" : "false");

    if (w < 0 || (size_t)w >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

bool coex_wifi_active(void)
{
    esp_coex_status_t st = esp_coex_status_get();
    return (st == ESP_COEX_STATUS_WIFI_ACTIVE || st == ESP_COEX_STATUS_WIFI_BT_ACTIVE);
}

bool coex_ble_active(void)
{
    esp_coex_status_t st = esp_coex_status_get();
    return (st == ESP_COEX_STATUS_BT_ACTIVE || st == ESP_COEX_STATUS_WIFI_BT_ACTIVE);
}
