#include "stealth.h"

#include <string.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_mac.h" /* For MACSTR / MAC2STR if needed, or manual print */

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "stealth";

/* 
 * TX Power configuration.
 * ESP-IDF esp_wifi_set_max_tx_power takes values in 0.25 dBm units.
 * Example: 19 dBm = 19 * 4 = 76.
 */
#define STEALTH_MIN_TX_POWER_DBM  0
#define STEALTH_MAX_TX_POWER_DBM  19

#define DBM_TO_ESP_IDF(dbm) ((int8_t)((dbm) * 4))

static atomic_int g_mode = STEALTH_MODE_OFF;
static uint8_t g_factory_mac[6];
static bool g_factory_mac_saved = false;

static SemaphoreHandle_t g_lock = NULL;

static uint32_t g_random_mac_switches = 0;
static uint32_t g_blocked_tx = 0;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static void set_random_mac_internal(void)
{
    uint8_t mac[6];
    esp_fill_random(mac, 6);
    
    /* Set locally administered bit (bit 1), clear multicast bit (bit 0) */
    mac[0] = (mac[0] & 0xFE) | 0x02; 
    
    esp_wifi_set_mac(WIFI_IF_STA, mac);
    g_random_mac_switches++;
    
    ESP_LOGI(TAG, "Random MAC set: %02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static esp_err_t set_tx_power_dbm(int8_t dbm)
{
    return esp_wifi_set_max_tx_power(DBM_TO_ESP_IDF(dbm));
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t stealth_init(void)
{
    if (g_lock != NULL) {
        return ESP_OK;
    }

    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }

    atomic_store(&g_mode, STEALTH_MODE_OFF);
    g_factory_mac_saved = false;
    memset(g_factory_mac, 0, sizeof(g_factory_mac));
    g_random_mac_switches = 0;
    g_blocked_tx = 0;
    
    ESP_LOGI(TAG, "Stealth module initialized");
    return ESP_OK;
}

esp_err_t stealth_deinit(void)
{
    if (g_lock == NULL) return ESP_OK;

    stealth_set_mode(STEALTH_MODE_OFF);

    vSemaphoreDelete(g_lock);
    g_lock = NULL;
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Mode Control
 * ----------------------------------------------------------------------- */

esp_err_t stealth_set_mode(stealth_mode_t mode)
{
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    stealth_mode_t current = atomic_load(&g_mode);
    if (current == mode) {
        xSemaphoreGive(g_lock);
        return ESP_OK;
    }

    switch (mode) {
        case STEALTH_MODE_OFF:
            /* Inline restore to avoid deadlock with public API */
            if (g_factory_mac_saved) {
                esp_wifi_set_mac(WIFI_IF_STA, g_factory_mac);
                ESP_LOGI(TAG, "Factory MAC restored");
            }
            set_tx_power_dbm(STEALTH_MAX_TX_POWER_DBM);
            break;

        case STEALTH_MODE_PASSIVE:
        case STEALTH_MODE_ACTIVE:
            if (!g_factory_mac_saved) {
                esp_wifi_get_mac(WIFI_IF_STA, g_factory_mac);
                g_factory_mac_saved = true;
            }
            set_random_mac_internal();
            set_tx_power_dbm(STEALTH_MIN_TX_POWER_DBM);
            break;

        default:
            xSemaphoreGive(g_lock);
            return ESP_ERR_INVALID_ARG;
    }

    atomic_store(&g_mode, mode);
    
    ESP_LOGI(TAG, "Stealth mode -> %s",
             mode == STEALTH_MODE_OFF ? "off" :
             mode == STEALTH_MODE_PASSIVE ? "passive" : "active");
             
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Public Actions
 * ----------------------------------------------------------------------- */

esp_err_t stealth_set_random_mac(void)
{
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    if (!g_factory_mac_saved) {
        esp_wifi_get_mac(WIFI_IF_STA, g_factory_mac);
        g_factory_mac_saved = true;
    }
    
    set_random_mac_internal();
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t stealth_restore_mac(void)
{
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    if (g_factory_mac_saved) {
        esp_wifi_set_mac(WIFI_IF_STA, g_factory_mac);
        ESP_LOGI(TAG, "Factory MAC restored");
    }
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t stealth_set_min_tx_power(void)
{
    return set_tx_power_dbm(STEALTH_MIN_TX_POWER_DBM);
}

esp_err_t stealth_restore_tx_power(void)
{
    return set_tx_power_dbm(STEALTH_MAX_TX_POWER_DBM);
}

/* -------------------------------------------------------------------------
 *  Status & Checks
 * ----------------------------------------------------------------------- */

stealth_mode_t stealth_get_mode(void)
{
    return (stealth_mode_t)atomic_load(&g_mode);
}

bool stealth_can_transmit(void)
{
    return atomic_load(&g_mode) == STEALTH_MODE_ACTIVE;
}

esp_err_t stealth_check_tx(const char *module_name)
{
    (void)module_name; /* Decoupled: we block ALL TX in passive mode */

    if (atomic_load(&g_mode) == STEALTH_MODE_PASSIVE) {
        if (g_lock) {
            xSemaphoreTake(g_lock, portMAX_DELAY);
            g_blocked_tx++;
            xSemaphoreGive(g_lock);
        }
        return ESP_ERR_NOT_ALLOWED;
    }
    
    return ESP_OK;
}

esp_err_t stealth_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;

    stealth_mode_t mode;
    uint32_t switches;
    uint32_t blocked;

    xSemaphoreTake(g_lock, portMAX_DELAY);
    mode = atomic_load(&g_mode);
    switches = g_random_mac_switches;
    blocked = g_blocked_tx;
    xSemaphoreGive(g_lock);

    const char *mode_str =
        (mode == STEALTH_MODE_OFF) ? "off" :
        (mode == STEALTH_MODE_PASSIVE) ? "passive" : "active";

    int n = snprintf(buf, bufsz,
                     "{\"mode\":\"%s\",\"mac_switches\":%"PRIu32",\"blocked_tx\":%"PRIu32"}",
                     mode_str, switches, blocked);
                     
    return (n < 0 || (size_t)n >= bufsz) ? ESP_ERR_NO_MEM : ESP_OK;
}
