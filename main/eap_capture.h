#ifndef EAP_CAPTURE_H
#define EAP_CAPTURE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EAP_MAX_CERTS 4
#define EAP_MAX_ID 64

typedef struct {
    uint8_t data[512];
    size_t len;
    bool valid;
} eap_cert_t;

esp_err_t eap_capture_init(void);
void eap_capture_record_identity(const uint8_t *identity, size_t len);
void eap_capture_record_cert(const uint8_t *der, size_t len);
size_t eap_capture_identity(char *out, size_t max);
size_t eap_capture_certs(eap_cert_t *out, size_t max);
void eap_capture_clear(void);

#ifdef __cplusplus
}
#endif
#endif
