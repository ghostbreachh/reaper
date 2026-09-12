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
#include "esp_http_client.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"

#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"

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

static esp_err_t verify_signature(const uint8_t *fw, size_t fw_len,
                                  const uint8_t *sig, size_t sig_len,
                                  const uint8_t *pubkey_der, size_t pk_len)
{
    mbedtls_pk_context pk;
    uint8_t hash[32];

    mbedtls_pk_init(&pk);

    /* Hash firmware */
    int ret = mbedtls_sha256(fw, fw_len, hash, 0);
    if (ret != 0) {
        ESP_LOGE(TAG, "SHA-256 compute failed: -0x%04x", -ret);
        mbedtls_pk_free(&pk);
        return ESP_ERR_INVALID_STATE;
    }

    /* Load public key */
    ret = mbedtls_pk_parse_public_key(&pk, pubkey_der, pk_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "Public key parse failed: -0x%04x", -ret);
        mbedtls_pk_free(&pk);
        return ESP_ERR_INVALID_STATE;
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        ESP_LOGE(TAG, "Key is not RSA");
        mbedtls_pk_free(&pk);
        return ESP_ERR_INVALID_STATE;
    }

    /* Modern mbedTLS v3.x API for PKCS#1 v1.5 verification */
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, sig, sig_len);

    if (ret != 0) {
        ESP_LOGE(TAG, "RSA verify failed: -0x%04x", -ret);
        mbedtls_pk_free(&pk);
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Firmware signature verified");
    mbedtls_pk_free(&pk);
    return ESP_OK;
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
            if (esp_http_client_get_status_code(sc) == 200 && sig_content_len > 0 && sig_content_len <= sizeof(sig)) {
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
