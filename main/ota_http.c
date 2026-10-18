/*
 * ============================================================================
 *  ota_http.c  —  HTTP firmware update with RSA-2048 / SHA-256 signature check
 * ============================================================================
 */

#include "ota_http.h"

#include <string.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_http_client.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"

#if __has_include("psa/crypto.h")
#include "psa/crypto.h"
#endif
#if __has_include("mbedtls/pk.h")
#include "mbedtls/pk.h"
#endif
#if __has_include("mbedtls/md.h")
#include "mbedtls/md.h"
#endif

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "ota";

/* State */
static atomic_bool g_ota_running = ATOMIC_VAR_INIT(false);
static atomic_int  g_ota_progress = ATOMIC_VAR_INIT(-1);

#define DL_CHUNK 4096
#define OTA_TASK_STACK_SIZE 8192

typedef struct {
    char url[256];
    uint8_t *pubkey_der;
    size_t pubkey_len;
} ota_task_params_t;

/* -------------------------------------------------------------------------
 *  Signature Verification (mbedTLS v3.x compatible)
 * ----------------------------------------------------------------------- */

static inline uint32_t ota_rotr32(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32U - n));
}

static void ota_sha256(const uint8_t *data, size_t len, uint8_t digest[32])
{
    static const uint32_t k[64] = {
        0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
        0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
        0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
        0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
        0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
        0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
        0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
        0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
        0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
        0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
        0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
        0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
        0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
        0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
        0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
        0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
    };

    uint32_t state[8] = {
        0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
        0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
    };

    uint64_t bitlen = (uint64_t)len * 8ULL;
    size_t offset = 0;

    while (offset + 64 <= len) {
        uint32_t w[64];
        const uint8_t *blk = data + offset;
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)blk[i * 4 + 0] << 24) |
                   ((uint32_t)blk[i * 4 + 1] << 16) |
                   ((uint32_t)blk[i * 4 + 2] << 8)  |
                   ((uint32_t)blk[i * 4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ota_rotr32(w[i - 15], 7) ^ ota_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ota_rotr32(w[i - 2], 17) ^ ota_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ota_rotr32(e, 6) ^ ota_rotr32(e, 11) ^ ota_rotr32(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = ota_rotr32(a, 2) ^ ota_rotr32(a, 13) ^ ota_rotr32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
        offset += 64;
    }

    uint8_t tail[128];
    memset(tail, 0, sizeof(tail));
    size_t rem = len - offset;
    if (rem > 0) {
        memcpy(tail, data + offset, rem);
    }
    tail[rem] = 0x80U;
    size_t total_tail = (rem < 56) ? 64 : 128;
    for (int i = 0; i < 8; i++) {
        tail[total_tail - 8 + i] = (uint8_t)(bitlen >> ((7 - i) * 8));
    }

    for (size_t b_off = 0; b_off < total_tail; b_off += 64) {
        uint32_t w[64];
        const uint8_t *blk = tail + b_off;
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)blk[i * 4 + 0] << 24) |
                   ((uint32_t)blk[i * 4 + 1] << 16) |
                   ((uint32_t)blk[i * 4 + 2] << 8)  |
                   ((uint32_t)blk[i * 4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ota_rotr32(w[i - 15], 7) ^ ota_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ota_rotr32(w[i - 2], 17) ^ ota_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ota_rotr32(e, 6) ^ ota_rotr32(e, 11) ^ ota_rotr32(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = ota_rotr32(a, 2) ^ ota_rotr32(a, 13) ^ ota_rotr32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    for (int i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (uint8_t)(state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(state[i]);
    }
}

static esp_err_t verify_signature(const uint8_t *fw, size_t fw_len,
                                  const uint8_t *sig, size_t sig_len,
                                  const uint8_t *pubkey_der, size_t pk_len)
{
    uint8_t hash[32];
    ota_sha256(fw, fw_len, hash);

#if __has_include("psa/crypto.h")
    (void)psa_crypto_init();
#endif

#if __has_include("mbedtls/pk.h")
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    int ret = mbedtls_pk_parse_public_key(&pk, pubkey_der, pk_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "Public key parse failed: -0x%04x", (unsigned)(-ret));
        mbedtls_pk_free(&pk);
        return ESP_ERR_INVALID_STATE;
    }

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, sig_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "RSA verify failed: -0x%04x", (unsigned)(-ret));
        mbedtls_pk_free(&pk);
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Firmware signature verified");
    mbedtls_pk_free(&pk);
    return ESP_OK;
#else
    (void)sig; (void)sig_len; (void)pubkey_der; (void)pk_len;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

/* -------------------------------------------------------------------------
 *  Background OTA Task
 * ----------------------------------------------------------------------- */

static void ota_task(void *arg)
{
    ota_task_params_t *params = (ota_task_params_t *)arg;
    const char *url = params->url;
    const uint8_t *pubkey_der = params->pubkey_der;
    size_t pubkey_len = params->pubkey_len;

    ota_status_t final_status = OTA_OK;

    const esp_partition_t *upd = esp_ota_get_next_update_partition(NULL);
    if (!upd) {
        ESP_LOGE(TAG, "No OTA partition available");
        final_status = OTA_ERR_NO_SLOT;
        goto cleanup;
    }

    ESP_LOGI(TAG, "OTA target partition: %s @ 0x%x (%u bytes)",
             upd->label, (unsigned)upd->address, (unsigned)upd->size);

    /* HTTP client config */
    esp_http_client_config_t httpcfg = {
        .url = url,
        .timeout_ms = 30000,
        .keep_alive_enable = false,
        .disable_auto_redirect = true,
    };

    esp_http_client_handle_t client = esp_http_client_init(&httpcfg);
    if (!client) {
        ESP_LOGE(TAG, "HTTP client init failed");
        final_status = OTA_ERR_DOWNLOAD;
        goto cleanup;
    }

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP open failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        final_status = OTA_ERR_DOWNLOAD;
        goto cleanup;
    }

    /* CRITICAL: Must fetch headers to get status code and content length */
    int content_len = esp_http_client_fetch_headers(client);
    int status = esp_http_client_get_status_code(client);
    
    if (status != 200) {
        ESP_LOGE(TAG, "HTTP %d", status);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        final_status = OTA_ERR_DOWNLOAD;
        goto cleanup;
    }

    if (content_len <= 0) {
        ESP_LOGE(TAG, "Missing or invalid Content-Length");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        final_status = OTA_ERR_DOWNLOAD;
        goto cleanup;
    }

    ESP_LOGI(TAG, "Firmware size: %d bytes", content_len);

    /* Allocate buffer STRICTLY in PSRAM. Internal RAM is too small for firmware. */
    uint8_t *fw_buf = heap_caps_malloc(content_len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!fw_buf) {
        ESP_LOGE(TAG, "No PSRAM available for firmware buffer");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        final_status = OTA_ERR_NO_PSRAM;
        goto cleanup;
    }

    /* Download */
    int total = 0;
    while (total < content_len) {
        if (!atomic_load(&g_ota_running)) {
            ESP_LOGW(TAG, "OTA aborted by user");
            heap_caps_free(fw_buf);
            esp_http_client_close(client);
            esp_http_client_cleanup(client);
            final_status = OTA_ERR_DOWNLOAD;
            goto cleanup;
        }

        int rd = esp_http_client_read(client, (char *)(fw_buf + total), content_len - total);
        if (rd <= 0) {
            ESP_LOGE(TAG, "Download stopped at %d/%d", total, content_len);
            heap_caps_free(fw_buf);
            esp_http_client_close(client);
            esp_http_client_cleanup(client);
            final_status = OTA_ERR_DOWNLOAD;
            goto cleanup;
        }
        total += rd;
        atomic_store(&g_ota_progress, (total * 100) / content_len);
    }

    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    ESP_LOGI(TAG, "Download complete: %d bytes", total);

    /* Read signature: expect URL + ".sig" */
    char sig_url[280];
    snprintf(sig_url, sizeof(sig_url), "%s.sig", url);

    uint8_t sig[512];
    int sig_len = 0;

    esp_http_client_config_t scfg = {
        .url = sig_url,
        .timeout_ms = 10000,
        .disable_auto_redirect = true,
    };
    esp_http_client_handle_t sc = esp_http_client_init(&scfg);
    if (sc) {
        if (esp_http_client_open(sc, 0) == ESP_OK) {
            int sig_content_len = esp_http_client_fetch_headers(sc);
            if (esp_http_client_get_status_code(sc) == 200 && sig_content_len > 0 && (size_t)sig_content_len <= sizeof(sig)) {
                sig_len = esp_http_client_read(sc, (char *)sig, sig_content_len);
                if (sig_len < 0) sig_len = 0;
            }
        }
        esp_http_client_close(sc);
        esp_http_client_cleanup(sc);
    }

    if (sig_len == 0) {
        ESP_LOGE(TAG, "Signature fetch failed");
        heap_caps_free(fw_buf);
        final_status = OTA_ERR_VERIFY;
        goto cleanup;
    }

    ESP_LOGI(TAG, "Signature size: %d bytes", sig_len);

    /* Verify */
    if (verify_signature(fw_buf, total, sig, sig_len, pubkey_der, pubkey_len) != ESP_OK) {
        heap_caps_free(fw_buf);
        final_status = OTA_ERR_VERIFY;
        goto cleanup;
    }

    /* Write verified image into OTA partition (Modern ESP-IDF API) */
    esp_ota_handle_t ota_handle;
    esp_err_t ret = esp_ota_begin(upd, total, &ota_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "OTA begin failed: %s", esp_err_to_name(ret));
        heap_caps_free(fw_buf);
        final_status = OTA_ERR_WRITE;
        goto cleanup;
    }

    ret = esp_ota_write(ota_handle, fw_buf, total);
    heap_caps_free(fw_buf);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "OTA write failed: %s", esp_err_to_name(ret));
        esp_ota_end(ota_handle);
        final_status = OTA_ERR_WRITE;
        goto cleanup;
    }

    ret = esp_ota_end(ota_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "OTA end failed: %s", esp_err_to_name(ret));
        final_status = OTA_ERR_WRITE;
        goto cleanup;
    }

    ret = esp_ota_set_boot_partition(upd);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Set boot partition failed: %s", esp_err_to_name(ret));
        final_status = OTA_ERR_BOOT;
        goto cleanup;
    }

    ESP_LOGI(TAG, "OTA complete — rebooting");
    atomic_store(&g_ota_progress, 100);
    
    /* Give logs a moment to flush before reboot */
    vTaskDelay(pdMS_TO_TICKS(500)); 
    esp_restart();

cleanup:
    atomic_store(&g_ota_running, false);
    atomic_store(&g_ota_progress, -1);
    
    if (final_status != OTA_OK) {
        ESP_LOGE(TAG, "OTA failed with status: %d", final_status);
    }
    
    free(params->pubkey_der);
    free(params);
    vTaskDelete(NULL);
}

/* -------------------------------------------------------------------------
 *  Public API
 * ----------------------------------------------------------------------- */

esp_err_t ota_http_init(void)
{
    atomic_store(&g_ota_running, false);
    atomic_store(&g_ota_progress, -1);
    ESP_LOGI(TAG, "OTA HTTP module ready");
    return ESP_OK;
}

ota_status_t ota_http_start(const char *url, const uint8_t *pubkey_der, size_t pubkey_len)
{
    if (!url || !pubkey_der || pubkey_len == 0) return OTA_ERR_INVALID_ARG;
    
    if (atomic_load(&g_ota_running)) {
        return OTA_ERR_NOT_READY;
    }

    /* Allocate parameters for the background task */
    ota_task_params_t *params = calloc(1, sizeof(ota_task_params_t));
    if (!params) return OTA_ERR_DOWNLOAD;

    snprintf(params->url, sizeof(params->url), "%s", url);
    params->pubkey_len = pubkey_len;
    params->pubkey_der = malloc(pubkey_len);
    
    if (!params->pubkey_der) {
        free(params);
        return OTA_ERR_DOWNLOAD;
    }
    memcpy(params->pubkey_der, pubkey_der, pubkey_len);

    atomic_store(&g_ota_running, true);
    atomic_store(&g_ota_progress, 0);

    /* Spawn background task so we don't block the CLI/JSON-RPC thread */
    BaseType_t ret = xTaskCreate(ota_task, "ota_task", OTA_TASK_STACK_SIZE, 
                                 params, 5, NULL);
                                 
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create OTA task");
        free(params->pubkey_der);
        free(params);
        atomic_store(&g_ota_running, false);
        atomic_store(&g_ota_progress, -1);
        return OTA_ERR_DOWNLOAD;
    }

    return OTA_OK;
}

void ota_http_abort(void)
{
    if (atomic_load(&g_ota_running)) {
        atomic_store(&g_ota_running, false);
        atomic_store(&g_ota_progress, -1);
        ESP_LOGW(TAG, "OTA abort requested");
    }
}

bool ota_http_in_progress(void)
{
    return atomic_load(&g_ota_running);
}

int ota_http_progress(void)
{
    return atomic_load(&g_ota_progress);
}
