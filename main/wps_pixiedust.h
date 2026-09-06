#ifndef WPS_PIXIEDUST_H
#define WPS_PIXIEDUST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PIXIEDUST_MAX_NONCES 8
#define PIXIEDUST_KEYLEN 16

typedef struct {
    uint8_t enrollee_nonce[128];
    uint8_t registrar_nonce[128];
    uint8_t e_hash1[32];
    uint8_t e_hash2[32];
    bool valid;
} pd_candidate_t;

esp_err_t wps_pixiedust_init(void);
void wps_pixiedust_record(const uint8_t *e_nonce, size_t e_nonce_len,
                          const uint8_t *r_nonce, size_t r_nonce_len,
                          const uint8_t *e_hash1, size_t e1_len,
                          const uint8_t *e_hash2, size_t e2_len);
size_t wps_pixiedust_candidates(pd_candidate_t *out, size_t max);
void wps_pixiedust_clear(void);
bool wps_pixiedust_compute_pin(const uint8_t *e_hash1, const uint8_t *e_hash2,
                               const uint8_t *r_nonce, const uint8_t *e_nonce,
                               char *pin_out, size_t pin_len);

#ifdef __cplusplus
}
#endif
#endif
