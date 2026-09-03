#ifndef AI_HANDSHAKE_QUALITY_H
#define AI_HANDSHAKE_QUALITY_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Handshake quality result. */
typedef struct {
    float    score;         /* 0..1: higher = more likely to crack */
    uint32_t factors;       /* bitmask of quality factors */
    uint32_t m1_count;     /* EAPOL M1 frames seen */
    uint32_t m2_count;     /* EAPOL M2 frames seen */
    int8_t   rssi;         /* last seen RSSI */
    bool     has_anonce;
    bool     has_snonce;
    bool     has_mic;
    bool     has_pmkid;
    bool     complete;     /* full 4-way handshake captured */
} ai_hs_quality_t;

/**
 * @brief Initialize handshake quality scorer.
 */
esp_err_t ai_hs_quality_init(void);

/**
 * @brief Set model name for crackability predictor.
 */
esp_err_t ai_hs_quality_set_model(const char *model_name);

/**
 * @brief Score current captured handshake.
 */
esp_err_t ai_hs_quality_score(ai_hs_quality_t *out);

/**
 * @brief Return quality stats as JSON. */
esp_err_t ai_hs_quality_json(char *buf, size_t bufsz);

/**
 * @brief Deinit scorer. */
void ai_hs_quality_deinit(void);

#ifdef __cplusplus
}
#endif
#endif /* AI_HANDSHAKE_QUALITY_H */
