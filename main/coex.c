#include "coex.h"
#include "wifi_sniffer.h"
#include "ble_scanner.h"

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"

#if __has_include("esp_coex.h") && (defined(CONFIG_SW_COEXIST_ENABLE) || defined(CONFIG_ESP_COEX_SW_COEXIST_ENABLE))
#include "esp_coex.h"
#define REAPER_HAS_ESP_COEX 1
#else
#define REAPER_HAS_ESP_COEX 0
#endif

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

#if REAPER_HAS_ESP_COEX
static esp_coex_prefer_t map_to_idf_pref(coex_pref_t pref)
{
    switch (pref) {
        case COEX_PREF_WIFI:    return ESP_COEX_PREFER_WIFI;
        case COEX_PREF_BLE:     return ESP_COEX_PREFER_BT;
        case COEX_PREF_BALANCE:
        default:                return ESP_COEX_PREFER_BALANCE;
    }
}
#endif

/* -------------------------------------------------------------------------
 *  Public API
 * ----------------------------------------------------------------------- */

esp_err_t coex_init(void)
{
    if (atomic_load(&g_init_done)) return ESP_OK;

    atomic_store(&g_init_done, true);
    coex_set_preference((coex_pref_t)atomic_load(&g_pref));
    (void)pref_to_str;
    ESP_LOGI(TAG, "Coexistence initialized (pref=%s)", pref_to_str((coex_pref_t)atomic_load(&g_pref)));
    return ESP_OK;
}

esp_err_t coex_set_preference(coex_pref_t pref)
{
    if (pref > COEX_PREF_BALANCE) return ESP_ERR_INVALID_ARG;

    atomic_store(&g_pref, pref);

#if REAPER_HAS_ESP_COEX
    esp_coex_prefer_t idf_pref = map_to_idf_pref(pref);
    esp_err_t rc = esp_coex_preference_set(idf_pref);
    if (rc != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set hardware coex preference: %s", esp_err_to_name(rc));
    } else {
        ESP_LOGI(TAG, "Coex preference set to %s", pref_to_str(pref));
    }
    return rc;
#else
    ESP_LOGI(TAG, "Coex preference set to %s (SW coex not enabled in sdkconfig)", pref_to_str(pref));
    return ESP_OK;
#endif
}

coex_pref_t coex_get_preference(void)
{
    return (coex_pref_t)atomic_load(&g_pref);
}

esp_err_t coex_get_status(coex_status_t *out_status)
{
    if (out_status == NULL) return ESP_ERR_INVALID_ARG;

    memset(out_status, 0, sizeof(*out_status));
    out_status->wifi_has_radio = wifi_sniffer_is_active();
    out_status->ble_has_radio  = ble_scanner_is_initialized();

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
    coex_status_t st;
    if (coex_get_status(&st) != ESP_OK) return false;
    return st.wifi_has_radio;
}

bool coex_ble_active(void)
{
    coex_status_t st;
    if (coex_get_status(&st) != ESP_OK) return false;
    return st.ble_has_radio;
}
