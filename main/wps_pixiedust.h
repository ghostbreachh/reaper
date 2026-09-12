#ifndef WPS_PIXIEDUST_H
#define WPS_PIXIEDUST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PIXIEDUST_MAX_NONCES      8
#define PIXIEDUST_MAX_NONCE_LEN   128
#define PIXIEDUST_MAX_HASH_LEN    32
#define PIXIEDUST_KEYLEN          16

typedef struct {
    uint8_t enrollee_nonce[PIXIEDUST_MAX_NONCE_LEN];
    uint8_t registrar_nonce[PIXIEDUST_MAX_NONCE_LEN];

    uint8_t e_hash1[PIXIEDUST_MAX_HASH_LEN];
    uint8_t e_hash2[PIXIEDUST_MAX_HASH_LEN];

    uint8_t enrollee_nonce_len;
    uint8_t registrar_nonce_len;
    uint8_t e_hash1_len;
    uint8_t e_hash2_len;

    int64_t captured_at_us;

    bool valid;
} pd_candidate_t;

/**
 * @brief Initialize PixieDust candidate collector.
 */
esp_err_t wps_pixiedust_init(void);

/**
 * @brief Record a PixieDust candidate.
 *
 * Oversized fields are rejected rather than truncated.
 */
void wps_pixiedust_record(const uint8_t *e_nonce, size_t e_nonce_len,
                          const uint8_t *r_nonce, size_t r_nonce_len,
                          const uint8_t *e_hash1, size_t e1_len,
                          const uint8_t *e_hash2, size_t e2_len);

/**
 * @brief Copy stored candidates into caller buffer.
 *
 * @return Number of candidates copied.
 */
size_t wps_pixiedust_candidates(pd_candidate_t *out, size_t max);

/**
 * @brief Clear stored candidates.
 */
void wps_pixiedust_clear(void);

/**
 * @brief Attempt to compute a PIN from candidate material.
 *
 * Currently a stub. Pixie Dust recovery is computationally expensive
 * and is usually better performed offline on a host machine.
 */
bool wps_pixiedust_compute_pin(const uint8_t *e_hash1,
                               const uint8_t *e_hash2,
                               const uint8_t *r_nonce,
                               const uint8_t *e_nonce,
                               char *pin_out,
                               size_t pin_len);

#ifdef __cplusplus
}
#endif

#endif /* WPS_PIXIEDUST_H */
