#ifndef AI_FINGERPRINT_H
#define AI_FINGERPRINT_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Device type labels. */
typedef enum {
    AI_FP_UNKNOWN = 0,
    AI_FP_PHONE   = 1,
    AI_FP_LAPTOP  = 2,
    AI_FP_IOT     = 3,
    AI_FP_AP      = 4,
    AI_FP_ROUTER  = 5
} ai_fp_class_t;

/* Fingerprint result. */
typedef struct {
    ai_fp_class_t  cls;
    char           label[32];
    uint8_t        oui[3];
    uint8_t        rates[8];
    uint8_t        rate_count;
    uint8_t        ext_cap[8];
    uint8_t        ext_cap_len;
    bool           model_loaded;
    uint32_t       inference_us;
} ai_fp_result_t;

/**
 * @brief Initialize device fingerprinting.
 */
esp_err_t ai_fingerprint_init(void);

/**
 * @brief Set model name for device-type classifier.
 */
esp_err_t ai_fingerprint_set_model(const char *model_name);

/**
 * @brief Classify device from probe request / beacon IE.
 *
 * @param ie_data   Pointer to tagged parameters (after fixed params)
 * @param ie_len    Length of IE blob
 * @param subtype   0=beacon/probe_resp, 4=probe_req, etc.
 * @param out       Output result
 */
esp_err_t ai_fingerprint_classify(const uint8_t *ie_data, size_t ie_len,
                                  uint8_t subtype, const uint8_t *oui_mac,
                                  ai_fp_result_t *out);

/**
 * @brief Convert class enum to human-readable string. */
const char *ai_fingerprint_class_name(ai_fp_class_t cls);

/**
 * @brief Return fingerprint stats as JSON. */
esp_err_t ai_fingerprint_json(char *buf, size_t bufsz);

/**
 * @brief Deinit fingerprinting. */
void ai_fingerprint_deinit(void);

#ifdef __cplusplus
}
#endif
#endif /* AI_FINGERPRINT_H */
