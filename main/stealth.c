#include "stealth.h"
#include "wifi_sniffer.h"
#include "deauth_engine.h"
#include "beacon_spam.h"
#include "extra_offense.h"
#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_wifi.h"
#include "esp_system.h"

static const char *TAG = "stealth";

static stealth_mode_t g_mode = STEALTH_MODE_OFF;
static uint8_t g_factory_mac[6];
static bool g_factory_mac_saved;
static SemaphoreHandle_t g_lock;
static uint32_t g_random_mac_switches;
static uint32_t g_blocked_tx;

static bool is_local_admin(const uint8_t *mac)
{
    return (mac[0] & 0x02) != 0;
}

static void set_random_mac(void)
{
    uint8_t mac[6];
    esp_fill_random(mac, 6);
    mac[0] = (mac[0] & 0xFE) | 0x02; /* locally administered, unicast */
    esp_wifi_set_mac(WIFI_IF_STA, mac);
    g_random_mac_switches++;
    ESP_LOGI(TAG, "random MAC set " MACSTR, MAC2STR(mac));
}

esp_err_t stealth_init(void)
{
    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }
    g_mode = STEALTH_MODE_OFF;
    g_factory_mac_saved = false;
    memset(g_factory_mac, 0, sizeof(g_factory_mac));
    g_random_mac_switches = 0;
    g_blocked_tx = 0;
    ESP_LOGI(TAG, "stealth init");
    return ESP_OK;
}

esp_err_t stealth_set_mode(stealth_mode_t mode)
{
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    if (g_mode == mode) {
        xSemaphoreGive(g_lock);
        return ESP_OK;
    }

    switch (mode) {
        case STEALTH_MODE_OFF:
            stealth_restore_mac();
            stealth_restore_tx_power();
            g_mode = STEALTH_MODE_OFF;
            break;
        case STEALTH_MODE_PASSIVE:
            if (!g_factory_mac_saved) {
                esp_wifi_get_mac(WIFI_IF_STA, g_factory_mac);
                g_factory_mac_saved = true;
            }
            set_random_mac();
            stealth_set_min_tx_power();
            g_mode = STEALTH_MODE_PASSIVE;
            break;
        case STEALTH_MODE_ACTIVE:
            if (!g_factory_mac_saved) {
                esp_wifi_get_mac(WIFI_IF_STA, g_factory_mac);
                g_factory_mac_saved = true;
            }
            set_random_mac();
            stealth_set_min_tx_power();
            g_mode = STEALTH_MODE_ACTIVE;
            break;
        default:
            xSemaphoreGive(g_lock);
            return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "stealth mode -> %s",
             mode == STEALTH_MODE_OFF ? "off" :
             mode == STEALTH_MODE_PASSIVE ? "passive" : "active");
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t stealth_set_random_mac(void)
{
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    if (!g_factory_mac_saved) {
        esp_wifi_get_mac(WIFI_IF_STA, g_factory_mac);
        g_factory_mac_saved = true;
    }
    set_random_mac();
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t stealth_restore_mac(void)
{
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    if (g_factory_mac_saved) {
        esp_wifi_set_mac(WIFI_IF_STA, g_factory_mac);
        ESP_LOGI(TAG, "factory MAC restored " MACSTR, MAC2STR(g_factory_mac));
    }
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t stealth_set_min_tx_power(void)
{
    return esp_wifi_set_max_tx_power(0); /* 0 dBm */
}

esp_err_t stealth_restore_tx_power(void)
{
    return esp_wifi_set_max_tx_power(19); /* 19 dBm default */
}

stealth_mode_t stealth_get_mode(void)
{
    return g_mode;
}

bool stealth_can_transmit(void)
{
    return g_mode == STEALTH_MODE_ACTIVE;
}

static bool is_active_module(const char *name)
{
    if (name == NULL) return false;
    if (strcmp(name, "deauth") == 0 && deauth_engine_is_active()) return true;
    if (strcmp(name, "beacon_spam") == 0 && beacon_spam_is_active()) return true;
    if (strcmp(name, "arp_poison") == 0 && arp_poison_is_active()) return true;
    if (strcmp(name, "doj") == 0 && doj_is_active()) return true;
    return false;
}

esp_err_t stealth_check_tx(const char *module_name)
{
    if (g_mode == STEALTH_MODE_PASSIVE && is_active_module(module_name)) {
        g_blocked_tx++;
        return ESP_ERR_NOT_ALLOWED;
    }
    return ESP_OK;
}

esp_err_t stealth_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;
    const char *mode_str =
        g_mode == STEALTH_MODE_OFF ? "off" :
        g_mode == STEALTH_MODE_PASSIVE ? "passive" : "active";
    int n = snprintf(buf, bufsz,
                     "{\"mode\":\"%s\",\"mac_switches\":%u,\"blocked_tx\":%u}",
                     mode_str, g_random_mac_switches, g_blocked_tx);
    return (n < 0 || (size_t)n >= bufsz) ? ESP_ERR_NO_MEM : ESP_OK;
}

esp_err_t stealth_deinit(void)
{
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    stealth_restore_mac();
    stealth_restore_tx_power();
    g_mode = STEALTH_MODE_OFF;
    xSemaphoreGive(g_lock);
    if (g_lock != NULL) {
        vSemaphoreDelete(g_lock);
        g_lock = NULL;
    }
    return ESP_OK;
}
