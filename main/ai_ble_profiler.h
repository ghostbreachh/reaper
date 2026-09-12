#ifndef AI_BLE_PROFILER_H
#define AI_BLE_PROFILER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Feature tensor size used by BLE profiler model. */
#define AI_BLE_PROFILER_FEAT_SZ             8

/* Default model inference divider. */
#define AI_BLE_PROFILER_DEFAULT_INFER_EVERY 8

/* BLE device type classes. */
typedef enum {
    AI_BLE_UNKNOWN = 0,
    AI_BLE_TAG     = 1,
    AI_BLE_PHONE   = 2,
    AI_BLE_SENSOR  = 3,
    AI_BLE_TRACKER = 4,
    AI_BLE_BEACON  = 5
} ai_ble_class_t;

/* BLE profiler result. */
typedef struct {
    ai_ble_class_t cls;
    char            label[32];
    uint8_t         oui[3];
    uint8_t         adv_type;
    uint8_t         flags;
    bool            model_loaded;
    uint32_t        inference_us;
} ai_ble_profile_t;

/**
 * @brief Initialize BLE device profiler.
 */
esp_err_t ai_ble_profiler_init(void);

/**
 * @brief Deinit profiler.
 */
void ai_ble_profiler_deinit(void);

/**
 * @brief Set model name for BLE classifier.
 */
esp_err_t ai_ble_profiler_set_model(const char *model_name);

/**
 * @brief Set how often model inference runs.
 *
 * every_n = 1 -> every advertisement
 * every_n = 8 -> every 8 advertisements
 */
esp_err_t ai_ble_profiler_set_infer_every(uint32_t every_n);

/**
 * @brief Classify a BLE device from scanner info + advertisement data.
 *
 * @param info      BLE device info produced by ble_scanner
 * @param adv_data  Raw advertisement payload
 * @param adv_len   Advertisement payload length
 * @param out       Output profile
 */
esp_err_t ai_ble_profiler_classify(const ble_info_t *info,
                                   const uint8_t *adv_data,
                                   size_t adv_len,
                                   ai_ble_profile_t *out);

/**
 * @brief Convert class enum to human-readable string.
 */
const char *ai_ble_profiler_class_name(ai_ble_class_t cls);

/**
 * @brief Return profiler stats as JSON.
 */
esp_err_t ai_ble_profiler_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif /* AI_BLE_PROFILER_H */
