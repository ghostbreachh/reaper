/*
 * ============================================================================
 *  ota_http.c  —  HTTP firmware update with RSA-2048 / SHA-256 signature check
 *
 *  DECISION BLOCK — ToT Branch Selection
 *  -------------------------------------
 *  Requirement: HTTP-based OTA with signed firmware verification.
 *
 *  Branch A — Unverified HTTP OTA (esp_https_ota without auth)
 *    Pros: trivial API, HTTPS built-in.
 *    Cons: NO signature verification. Any MITM can push malicious firmware.
 *    Decision: REJECTED. Fails security requirement.
 *
 *  Branch B — eFuse-burned RSA public key
 *    Pros: strongest anti-rollback, unmodifiable key.
 *    Cons: irreversible hardware provisioning; user reflashes often during
 *          development. eFuse block can brick the chip if misused.
 *    Decision: REJECTED. Too brittle for dev/reflash workflow.
 *
 *  Branch C — HTTP fetch + mbedtls RSA-2048 verify + OTA write
 *    Pros: meets signed verification requirement, no eFuse, no TLS overhead,
 *          public key stored in NVS so it can be updated/recovered.
 *    Cons: uses plain HTTP for download; security relies solely on signature,
 *          so key secrecy matters more than transport secrecy.
 *    Decision: ACCEPTED. Best fit for dev + production without TLS infra.
 *
 *  Chosen implementation flow:
 *    1. Download raw firmware bytes over HTTP.
 *    2. Fetch companion .sig file (URL + ".sig") containing RSA-2048 PKCS#1v1.5.
 *    3. Compute SHA-256 over firmware.
 *    4. Verify using mbedtls pk/md stack + embedded DER public key.
 *    5. Write verified payload into inactive OTA partition.
 *    6. Mark bootable and reboot.
 *
 *  This satisfies the requirement for signed verification without requiring
 *  eFuse provisioning or TLS stack overhead.
 * ============================================================================
 */

#include "ota_http.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_persist.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "string.h"
#include <stdatomic.h>
#include "stdio.h"

static const char *TAG = "ota";

/* State */
static atomic_bool g_ota_running = ATOMIC_VAR_INIT(false);
static atomic_int  g_ota_progress = ATOMIC_VAR_INIT(-1);

/* Download buffer */
#define DL_CHUNK 4096

static esp_err_t verify_signature(const uint8_t *fw, size_t fw_len,
                                  const uint8_t *sig, size_t sig_len,
                                  const uint8_t *pubkey_der, size_t pk_len)
{
    mbedtls_sha256_context sha;
    mbedtls_pk_context pk;
    uint8_t hash[32];

    memset(&pk, 0, sizeof(pk));
    memset(&sha, 0, sizeof(sha));

    mbedtls_pk_init(&pk);
    mbedtls_sha256_init(&sha);

    /* Hash firmware */
    if (mbedtls_sha256_ret(fw, fw_len, hash, 0) != 0) {
        ESP_LOGE(TAG, "SHA-256 compute failed");
        mbedtls_pk_free(&pk);
        mbedtls_sha256_free(&sha);
        return ESP_ERR_INVALID_STATE;
    }

    /* Load public key */
    int ret = mbedtls_pk_parse_public_key(&pk, pubkey_der, pk_len, NULL, 0);
    if (ret != 0) {
        ESP_LOGE(TAG, "public key parse failed: -0x%04x", -ret);
        mbedtls_pk_free(&pk);
        mbedtls_sha256_free(&sha);
        return ESP_ERR_INVALID_STATE;
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        ESP_LOGE(TAG, "key is not RSA");
        mbedtls_pk_free(&pk);
        mbedtls_sha256_free(&sha);
        return ESP_ERR_INVALID_STATE;
    }

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
    ret = mbedtls_rsa_pkcs1_verify(rsa, MBEDTLS_MD_NONE, MBEDTLS_MD_SHA256,
                                    0, hash, sig);

    if (ret != 0) {
        ESP_LOGE(TAG, "RSA verify failed: -0x%04x", -ret);
        mbedtls_pk_free(&pk);
        mbedtls_sha256_free(&sha);
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Firmware signature verified");
    mbedtls_pk_free(&pk);
    mbedtls_sha256_free(&sha);
    return ESP_OK;
}

ota_status_t ota_http_start(const char *url, const uint8_t *pubkey_der, size_t pubkey_len)
{
    if (!url || !pubkey_der || pubkey_len == 0) return OTA_ERR_INVALID_ARG;
    if (atomic_load(&g_ota_running)) return OTA_ERR_NOT_READY;

    const esp_partition_t *upd = esp_ota_get_next_update_partition(NULL);
    if (!upd) {
        ESP_LOGE(TAG, "no OTA partition available");
        return OTA_ERR_NO_SLOT;
    }

    atomic_store(&g_ota_running, true);
    atomic_store(&g_ota_progress, 0);

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
        atomic_store(&g_ota_running, false);
        return OTA_ERR_DOWNLOAD;
    }

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP open failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        atomic_store(&g_ota_running, false);
        return OTA_ERR_DOWNLOAD;
    }

    int status = esp_http_client_get_status_code(client);
    if (status != 200) {
        ESP_LOGE(TAG, "HTTP %d", status);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        atomic_store(&g_ota_running, false);
        return OTA_ERR_DOWNLOAD;
    }

    int content_len = esp_http_client_get_content_length(client);
    if (content_len <= 0) {
        ESP_LOGE(TAG, "missing Content-Length");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        atomic_store(&g_ota_running, false);
        return OTA_ERR_DOWNLOAD;
    }

    ESP_LOGI(TAG, "Firmware size: %d bytes", content_len);

    /* Allocate buffer (PSRAM preferred) */
    uint8_t *fw_buf = heap_caps_malloc(content_len, MALLOC_CAP_SPIRAM);
    if (!fw_buf) fw_buf = heap_caps_malloc(content_len, MALLOC_CAP_DEFAULT);
    if (!fw_buf) {
        ESP_LOGE(TAG, "no memory for firmware buffer");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        atomic_store(&g_ota_running, false);
        return OTA_ERR_DOWNLOAD;
    }

    /* Download */
    int total = 0;
    while (total < content_len) {
        int rd = esp_http_client_read(client, fw_buf + total, content_len - total);
        if (rd <= 0) {
            ESP_LOGE(TAG, "download stopped at %d/%d", total, content_len);
            heap_caps_free(fw_buf);
            esp_http_client_close(client);
            esp_http_client_cleanup(client);
            atomic_store(&g_ota_running, false);
            return OTA_ERR_DOWNLOAD;
        }
        total += rd;
        atomic_store(&g_ota_progress, (total * 100) / content_len);
    }

    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    ESP_LOGI(TAG, "Download complete: %d bytes", total);

    /* Read signature: expect URL + ".sig" */
    char sig_url[256];
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
        if (esp_http_client_open(sc, 0) == ESP_OK &&
            esp_http_client_get_status_code(sc) == 200) {
            sig_len = esp_http_client_read(sc, (char *)sig, sizeof(sig));
            if (sig_len < 0) sig_len = 0;
        }
        esp_http_client_close(sc);
        esp_http_client_cleanup(sc);
    }

    if (sig_len == 0) {
        ESP_LOGE(TAG, "signature fetch failed");
        heap_caps_free(fw_buf);
        atomic_store(&g_ota_running, false);
        return OTA_ERR_VERIFY;
    }

    ESP_LOGI(TAG, "Signature size: %d bytes", sig_len);

    /* Verify */
    if (verify_signature(fw_buf, total, sig, sig_len, pubkey_der, pubkey_len) != ESP_OK) {
        heap_caps_free(fw_buf);
        atomic_store(&g_ota_running, false);
        return OTA_ERR_VERIFY;
    }

    /* Write verified image into OTA partition */
    esp_ota_ops_t *ops = NULL;
    esp_err_t ret = esp_ota_begin(upd, total, &ops);
    if (ret != ESP_OK || !ops) {
        ESP_LOGE(TAG, "OTA begin failed: %s", esp_err_to_name(ret));
        heap_caps_free(fw_buf);
        atomic_store(&g_ota_running, false);
        return OTA_ERR_WRITE;
    }

    ret = esp_ota_write(ops, fw_buf, total);
    heap_caps_free(fw_buf);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "OTA write failed: %s", esp_err_to_name(ret));
        esp_ota_end(ops);
        atomic_store(&g_ota_running, false);
        return OTA_ERR_WRITE;
    }

    ret = esp_ota_end(ops);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "OTA end failed: %s", esp_err_to_name(ret));
        atomic_store(&g_ota_running, false);
        return OTA_ERR_WRITE;
    }

    ret = esp_ota_set_boot_partition(upd);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "set boot partition failed: %s", esp_err_to_name(ret));
        atomic_store(&g_ota_running, false);
        return OTA_ERR_BOOT;
    }

    ESP_LOGI(TAG, "OTA complete — rebooting");
    atomic_store(&g_ota_running, false);
    atomic_store(&g_ota_progress, 100);
    esp_restart();
    return OTA_OK; /* never reached */
}

void ota_http_abort(void)
{
    if (atomic_load(&g_ota_running)) {
        atomic_store(&g_ota_running, false);
        atomic_store(&g_ota_progress, -1);
        ESP_LOGW(TAG, "OTA aborted");
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

/*============================================================================*/
esp_err_t ota_http_init(void)
{
    atomic_store(&g_ota_running, false);
    atomic_store(&g_ota_progress, -1);
    ESP_LOGI(TAG, "OTA HTTP module ready");
    return ESP_OK;
}
