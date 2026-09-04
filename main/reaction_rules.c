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
#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_timer.h"

static const char *TAG = "reaction";

static reaction_rule_t g_rules[REACTION_MAX_RULES];
static SemaphoreHandle_t g_lock;
static uint32_t g_fire_count;

static bool match_bssid(const uint8_t *rule_bssid, const uint8_t *bssid)
{
    if (memcmp(rule_bssid, "\x00\x00\x00\x00\x00\x00", 6) == 0) return true;
    return memcmp(rule_bssid, bssid, 6) == 0;
}

static bool match_ssid_prefix(const char *rule_ssid, const char *ssid)
{
    if (rule_ssid[0] == '\0' || ssid == NULL) return true;
    return strncmp(rule_ssid, ssid, strlen(rule_ssid)) == 0;
}

static void execute_action(const reaction_rule_t *rule)
{
    switch (rule->action) {
        case REACTION_ACT_DEAUTH: {
            deauth_target_t t;
            memset(&t, 0, sizeof(t));
            memcpy(t.bssid, rule->param, 6);
            t.active = true;
            deauth_engine_start(&t, 1, DEAUTH_MODE_FALLBACK_CHAIN);
            break;
        }
        case REACTION_ACT_WARDRIVE_START: {
            wardrive_mode_t mode = WARDIRVE_MODE_OFF;
            if (strcmp((const char *)rule->action_param, "wifi") == 0) mode = WARDIRVE_MODE_WIFI;
            else if (strcmp((const char *)rule->action_param, "ble") == 0) mode = WARDIRVE_MODE_BLE;
            else if (strcmp((const char *)rule->action_param, "both") == 0) mode = WARDIRVE_MODE_BOTH;
            if (mode != WARDIRVE_MODE_OFF) wardrive_start(mode);
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
            if (mode != AI_TRAIN_MODE_OFF) ai_train_start(mode);
            break;
        }
        case REACTION_ACT_TRAIN_STOP:
            ai_train_stop();
            break;
        case REACTION_ACT_ALERT:
            ESP_LOGI(TAG, "REACTION ALERT fired for rule param=%s", (const char *)rule->param);
            break;
        default:
            break;
    }
}

esp_err_t reaction_rules_init(void)
{
    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }
    memset(g_rules, 0, sizeof(g_rules));
    g_fire_count = 0;
    ESP_LOGI(TAG, "reaction rules init");
    return ESP_OK;
}

int reaction_rules_add(const reaction_rule_t *rule)
{
    if (rule == NULL) return -1;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return -2;
    }
    for (int i = 0; i < REACTION_MAX_RULES; i++) {
        if (!g_rules[i].enabled) {
            memcpy(&g_rules[i], rule, sizeof(reaction_rule_t));
            xSemaphoreGive(g_lock);
            return i;
        }
    }
    xSemaphoreGive(g_lock);
    return -3;
}

esp_err_t reaction_rules_remove(uint8_t index)
{
    if (index >= REACTION_MAX_RULES) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    memset(&g_rules[index], 0, sizeof(reaction_rule_t));
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t reaction_rules_get(uint8_t index, reaction_rule_t *out)
{
    if (index >= REACTION_MAX_RULES || out == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    memcpy(out, &g_rules[index], sizeof(reaction_rule_t));
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t reaction_rules_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    int n = snprintf(buf, bufsz, "[");
    for (int i = 0; i < REACTION_MAX_RULES && n < (int)bufsz; i++) {
        const reaction_rule_t *e = &g_rules[i];
        if (!e->enabled) continue;
        n += snprintf(buf + n, bufsz - (size_t)n,
                      "%s{\"i\":%d,\"trigger\":%d,\"action\":%d}",
                      n > 1 ? "," : "", i, e->trigger, e->action);
    }
    if (n + 1 < (int)bufsz) {
        n += snprintf(buf + n, bufsz - (size_t)n, "]");
    }
    xSemaphoreGive(g_lock);
    return (n < 0 || (size_t)n >= bufsz) ? ESP_ERR_NO_MEM : ESP_OK;
}

static esp_err_t fire(const reaction_rule_t *rule)
{
    execute_action(rule);
    g_fire_count++;
    return ESP_OK;
}

esp_err_t reaction_rules_check_ap(const uint8_t *bssid, const char *ssid)
{
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    for (int i = 0; i < REACTION_MAX_RULES; i++) {
        const reaction_rule_t *e = &g_rules[i];
        if (!e->enabled || e->trigger != REACTION_TRIG_AP_SEEN) continue;
        if (match_bssid(e->param, bssid) && match_ssid_prefix((const char *)e->action_param, ssid)) {
            fire(e);
        }
    }
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t reaction_rules_check_client(const uint8_t *client, const uint8_t *ap)
{
    (void)client; (void)ap;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
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
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    for (int i = 0; i < REACTION_MAX_RULES; i++) {
        const reaction_rule_t *e = &g_rules[i];
        if (!e->enabled || e->trigger != REACTION_TRIG_ANOMALY_HIGH) continue;
        float threshold = ((const float *)e->param)[0];
        if (score >= threshold) {
            fire(e);
        }
    }
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t reaction_rules_check_ble(const uint8_t *addr)
{
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
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
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
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
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    for (int i = 0; i < REACTION_MAX_RULES; i++) {
        const reaction_rule_t *e = &g_rules[i];
        if (!e->enabled || e->trigger != REACTION_TRIG_ROGUE_AP) continue;
        if (match_ssid_prefix((const char *)e->param, ssid)) {
            fire(e);
        }
    }
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t reaction_rules_check_rogue_alerts(void)
{
    extern uint8_t ai_rogue_detector_alert_count(void);
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    uint8_t count = ai_rogue_detector_alert_count();
    for (uint8_t a = 0; a < count; a++) {
        ai_rogue_alert_t alert;
        extern esp_err_t ai_rogue_detector_get_alert(uint8_t, ai_rogue_alert_t *);
        if (ai_rogue_detector_get_alert(a, &alert) == ESP_OK) {
            for (int i = 0; i < REACTION_MAX_RULES; i++) {
                const reaction_rule_t *e = &g_rules[i];
                if (!e->enabled || e->trigger != REACTION_TRIG_ROGUE_AP) continue;
                if (match_ssid_prefix((const char *)e->param, (const char *)alert.ssid)) {
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
