#ifndef OTA_HTTP_H
#define OTA_HTTP_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Result code for OTA operations. */
typedef enum {
    OTA_OK = 0,
    OTA_ERR_INVALID_ARG = -1,
    OTA_ERR_NOT_READY = -2,
    OTA_ERR_DOWNLOAD = -3,
    OTA_ERR_VERIFY = -4,
    OTA_ERR_WRITE = -5,
    OTA_ERR_BOOT = -6,
    OTA_ERR_NO_SLOT = -7,
    OTA_ERR_NO_PSRAM = -8,
} ota_status_t;

esp_err_t ota_http_init(void);

/**
 * @brief Start OTA update in a background task.
 * 
 * @param url HTTP URL of the firmware binary.
 * @param pubkey_der DER-encoded RSA-2048 public key.
 * @param pubkey_len Length of the public key.
 * @return OTA_OK if the background task was successfully spawned.
 */
ota_status_t ota_http_start(const char *url, const uint8_t *pubkey_der, size_t pubkey_len);

/* Abort in-progress OTA. */
void ota_http_abort(void);

/* Query current state. */
bool ota_http_in_progress(void);
int ota_http_progress(void);  /* 0..100, -1 if unknown */

#ifdef __cplusplus
}
#endif

#endif // OTA_HTTP_H
