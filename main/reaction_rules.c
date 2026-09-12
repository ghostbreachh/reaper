#include "reaction_rules.h"
#include "deauth_engine.h"
#include "stealth.h"
#include "wardrive.h"
#include "ai_training.h"
#include "ai_anomaly.h"
#include "ai_rogue_detector.h"
#include "ble_scanner.h"

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>
#include <ctype.h>

#include "esp_log.h"
#include "esp_err.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_timer.h"

static const char *TAG = "reaction";

static reaction_rule_t g_rules[REACTION_MAX_RULES];
static SemaphoreHandle_t g_lock = NULL;
static atomic_uint g_fire_count = ATOMIC_VAR_INIT(0);

/* -------------------------------------------------------------------------
 *  Matching Helpers
 * ----------------------------------------------------------------------- */

static bool match_bssid(const uint8_t *rule_bssid, const uint8_t *bssid)
{
    if (bssid == NULL) return false;
    
    /* Wildcard: all zeros matches any BSSID */
    bool is_wildcard = true;
    for (int i = 0; i < 6; i++) {
        if (rule_bssid[i] != 0) {
            is_wildcard = false;
            break;
        }
    }
    if (is_wildcard) return true;
    
    return memcmp(rule_bssid, bssid, 6) == 0;
}

static bool match_ssid_prefix(const uint8_t *rule_ssid, size_t rule_len, const char *ssid)
{
    if (ssid == NULL) return false;
    
    /* Find length of rule_ssid up to rule_len */
    size_t len = 0;
    while (len < rule_len && rule_ssid[len] != '\0') {
        len++;
    }
    
    /* Empty rule matches any SSID */
    if (len == 0) return true;
    
    return strncmp((const char *)rule_ssid, ssid, len) == 0;
}

/* -------------------------------------------------------------------------
 *  Action Execution
 * ----------------------------------------------------------------------- */

static void execute_action(const reaction_rule_t *rule)
{
    switch (rule->action) {
        case REACTION_ACT_DEAUTH: {
            /* 
             * rule->param is assumed to be the target BSSID (6 bytes).
             * rule->action_param is assumed to be the target client MAC (6 bytes),
             * or all zeros for broadcast deauth.
             */
            const uint8_t *bssid = rule->param;
            
            uint8_t client_mac[6];
            memcpy(client_mac, rule->action_param, 6);
            
            bool is_broadcast = true;
            for (int i = 0; i < 6; i++) {
                if (client_mac[i] != 0) {
                    is_broadcast = false;
                    break;
                }
            }
            
            const uint8_t *client = is_broadcast ? NULL : client_mac;
            
            deauth_add_target(bssid, client, 10, 100, DEAUTH_MODE_FALLBACK_CHAIN);
            deauth_start();
            break;
        }
        case REACTION_ACT_WARDRIVE_START: {
            wardrive_mode_t mode = WARDRIVE_MODE_OFF;
            if (strcmp((const char *)rule->action_param, "wifi") == 0) mode = WARDRIVE_MODE_WIFI;
            else if (strcmp((const char *)rule->action_param, "ble") == 0) mode = WARDRIVE_MODE_BLE;
            else if (strcmp((const char *)rule->action_param, "both") == 0) mode = WARDRIVE_MODE_BOTH;
            
            if (mode != WARDRIVE_MODE_OFF) {
                wardrive_start(mode);
            }
            break;
        }
        case REACTION_ACT_STEALTH_PASSIVE:
            stealth_set_mode(STEALTH_MODE_PASSIVE);
            break;
        case REACTION_ACT_TRAIN_START: {
            ai_train_mode_t mode = AI_TRAIN_MODE_OFF;
            if (strcmp((const char *)rule->action_param, "wifi") == 0) mode = AI_TRAIN_MODE_WIFI;
            else if (strcmp((const char *)rule->action_param, "ble") == 0) mode = AI_TRAIN_MODE_BLE;
            else if (strcmp((const char *)rule->action_param, "both") == 0) mode = AI_TRAIN_MODE_BOTH;
            
            if (mode != AI_TRAIN_MODE_OFF) {
                ai_train_start(mode);
            }
            break;
        }
        case REACTION_ACT_TRAIN_STOP:
            ai_train_stop();
            break;
        case REACTION_ACT_ALERT:
            ESP_LOGI(TAG, "REACTION ALERT fired for rule param=%.*s", 32, (const char *)rule->param);
            break;
        default:
            break;
    }
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t reaction_rules_init(void)
{
    if (g_lock != NULL) return ESP_OK;

    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }
    
    memset(g_rules, 0, sizeof(g_rules));
    atomic_store(&g_fire_count, 0);
    
    ESP_LOGI(TAG, "Reaction rules engine initialized");
    return ESP_OK;
}

int reaction_rules_add(const reaction_rule_t *rule)
{
    if (rule == NULL || g_lock == NULL) return -1;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return -2;
    
    for (int i = 0; i < REACTION_MAX_RULES; i++) {
        if (!g_rules[i].enabled) {
            memcpy(&g_rules[i], rule, sizeof(reaction_rule_t));
            xSemaphoreGive(g_lock);
            return i;
        }
    }
    
    xSemaphoreGive(g_lock);
    return -3; /* Full */
}

esp_err_t reaction_rules_remove(uint8_t index)
{
    if (index >= REACTION_MAX_RULES || g_lock == NULL) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    memset(&g_rules[index], 0, sizeof(reaction_rule_t));
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t reaction_rules_get(uint8_t index, reaction_rule_t *out)
{
    if (index >= REACTION_MAX_RULES || out == NULL || g_lock == NULL) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    memcpy(out, &g_rules[index], sizeof(reaction_rule_t));
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t reaction_rules_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0 || g_lock == NULL) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    int n = snprintf(buf, bufsz, "[");
    if (n < 0 || (size_t)n >= bufsz) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_NO_MEM;
    }

    bool first = true;
    for (int i = 0; i < REACTION_MAX_RULES; i++) {
        const reaction_rule_t *e = &g_rules[i];
        if (!e->enabled) continue;

        if (!first) {
            int c = snprintf(buf + n, bufsz - (size_t)n, ",");
            if (c < 0 || (size_t)(n + c) >= bufsz) break;
            n += c;
        }

        int c = snprintf(buf + n, bufsz - (size_t)n,
                         "{\"i\":%d,\"trigger\":%d,\"action\":%d}",
                         i, e->trigger, e->action);
        if (c < 0 || (size_t)(n + c) >= bufsz) break;
        n += c;
        first = false;
    }

    if ((size_t)n + 1 < bufsz) {
        n += snprintf(buf + n, bufsz - (size_t)n, "]");
    }

    xSemaphoreGive(g_lock);
    return ((size_t)n >= bufsz) ? ESP_ERR_NO_MEM : ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Trigger Checks
 * ----------------------------------------------------------------------- */

static esp_err_t fire(const reaction_rule_t *rule)
{
    execute_action(rule);
    atomic_fetch_add(&g_fire_count, 1);
    return ESP_OK;
}

esp_err_t reaction_rules_check_ap(const uint8_t *bssid, const char *ssid)
{
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    for (int i = 0; i < REACTION_MAX_RULES; i++) {
        const reaction_rule_t *e = &g_rules[i];
        if (!e->enabled || e->trigger != REACTION_TRIG_AP_SEEN) continue;
        
        /* param = BSSID, action_param = SSID prefix */
        if (match_bssid(e->param, bssid) && 
            match_ssid_prefix(e->action_param, sizeof(e->action_param), ssid)) {
            fire(e);
        }
    }
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t reaction_rules_check_client(const uint8_t *client, const uint8_t *ap)
{
    (void)client; 
    
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    for (int i = 0; i < REACTION_MAX_RULES; i++) {
        const reaction_rule_t *e = &g_rules[i];
        if (!e->enabled || e->trigger != REACTION_TRIG_CLIENT_JOIN) continue;
        
        if (match_bssid(e->param, ap)) {
            fire(e);
        }
    }
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t reaction_rules_check_anomaly(float score)
{
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    for (int i = 0; i < REACTION_MAX_RULES; i++) {
        const reaction_rule_t *e = &g_rules[i];
        if (!e->enabled || e->trigger != REACTION_TRIG_ANOMALY_HIGH) continue;
        
        /* Safely read float threshold from byte array to avoid unaligned access */
        float threshold = 0.0f;
        memcpy(&threshold, e->param, sizeof(float));
        
        if (score >= threshold) {
            fire(e);
        }
    }
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t reaction_rules_check_ble(const uint8_t *addr)
{
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    for (int i = 0; i < REACTION_MAX_RULES; i++) {
        const reaction_rule_t *e = &g_rules[i];
        if (!e->enabled || e->trigger != REACTION_TRIG_BLE_SEEN) continue;
        
        if (match_bssid(e->param, addr)) {
            fire(e);
        }
    }
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t reaction_rules_check_handshake(void)
{
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    for (int i = 0; i < REACTION_MAX_RULES; i++) {
        const reaction_rule_t *e = &g_rules[i];
        if (!e->enabled || e->trigger != REACTION_TRIG_HANDSHAKE) continue;
        fire(e);
    }
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t reaction_rules_check_rogue(const char *ssid)
{
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    for (int i = 0; i < REACTION_MAX_RULES; i++) {
        const reaction_rule_t *e = &g_rules[i];
        if (!e->enabled || e->trigger != REACTION_TRIG_ROGUE_AP) continue;
        
        if (match_ssid_prefix(e->param, sizeof(e->param), ssid)) {
            fire(e);
        }
    }
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t reaction_rules_check_rogue_alerts(void)
{
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    uint8_t count = ai_rogue_detector_alert_count();
    for (uint8_t a = 0; a < count; a++) {
        ai_rogue_alert_t alert;
        if (ai_rogue_detector_get_alert(a, &alert) == ESP_OK) {
            for (int i = 0; i < REACTION_MAX_RULES; i++) {
                const reaction_rule_t *e = &g_rules[i];
                if (!e->enabled || e->trigger != REACTION_TRIG_ROGUE_AP) continue;
                
                if (match_ssid_prefix(e->param, sizeof(e->param), (const char *)alert.ssid)) {
                    fire(e);
                }
            }
        }
    }
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t reaction_rules_deinit(void)
{
    if (g_lock != NULL) {
        vSemaphoreDelete(g_lock);
        g_lock = NULL;
    }
    memset(g_rules, 0, sizeof(g_rules));
    return ESP_OK;
}
