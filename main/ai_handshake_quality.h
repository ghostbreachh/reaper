#ifndef AI_HANDSHAKE_QUALITY_H
#define AI_HANDSHAKE_QUALITY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Quality factor bits. */
#define AI_HS_FACTOR_COMPLETE     (1u << 0)
#define AI_HS_FACTOR_NONCES       (1u << 1)
#define AI_HS_FACTOR_MIC          (1u << 2)
#define AI_HS_FACTOR_PMKID        (1u << 3)
#define AI_HS_FACTOR_EAPOL        (1u << 4)
#define AI_HS_FACTOR_STRONG_RSSI  (1u << 5)

/* Handshake quality result. */
typedef struct {
    float    score;         /* 0..1: higher = more likely to crack */
    uint32_t factors;       /* bitmask of quality factors */
    uint32_t m1_count;      /* inferred M1 presence/count */
    uint32_t m2_count;      /* inferred M2 presence/count */
    int8_t   rssi;          /* RSSI of AP if known */
    uint16_t eapol_len;     /* captured EAPOL length */
    bool     has_anonce;
    bool     has_snonce;
    bool     has_mic;
    bool     has_pmkid;
    bool     complete;      /* valid capture present */
    bool     model_loaded;
    uint32_t inference_us;
} ai_hs_quality_t;

/**
 * @brief Initialize handshake quality scorer.
 */
esp_err_t ai_hs_quality_init(void);

/**
 * @brief Deinit scorer.
 */
void ai_hs_quality_deinit(void);

/**
 * @brief Set model name for crackability predictor.
 */
esp_err_t ai_hs_quality_set_model(const char *model_name);

/**
 * @brief Score current captured handshake.
 */
esp_err_t ai_hs_quality_score(ai_hs_quality_t *out);

/**
 * @brief Return quality stats as JSON.
 */
esp_err_t ai_hs_quality_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif /* AI_HANDSHAKE_QUALITY_H */
