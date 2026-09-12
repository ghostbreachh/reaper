#ifndef AI_MODEL_H
#define AI_MODEL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of models in the zoo. */
#define AI_MODEL_ZOO_CAPACITY 8
#define AI_MODEL_NAME_MAX     32
#define AI_MODEL_FORMAT_MAX   16

/* Model format types. */
typedef enum {
    AI_MODEL_FMT_ESPDL = 0,
    AI_MODEL_FMT_TFLITE = 1,
    AI_MODEL_FMT_UNKNOWN = 255
} ai_model_format_t;

/* Model metadata. */
typedef struct {
    char              name[AI_MODEL_NAME_MAX];
    ai_model_format_t format;
    size_t            model_size;
    uint32_t          loaded_at;    /* Unix epoch when loaded */
    bool              is_loaded;
    bool              is_quantized; /* INT8 vs FP32 */
} ai_model_info_t;

/**
 * @brief Initialize the model zoo subsystem.
 */
esp_err_t ai_model_zoo_init(void);

/**
 * @brief Load a model from SPIFFS into RAM.
 *
 * Model files live under /spiffs/models/<name>.bin or /spiffs/models/<name>.tflite.
 * If the same model is already loaded, returns ESP_OK without reloading.
 */
esp_err_t ai_model_zoo_load(const char *name);

/**
 * @brief Unload a model and free its memory.
 */
esp_err_t ai_model_zoo_unload(const char *name);

/**
 * @brief Run inference on a loaded model.
 */
esp_err_t ai_model_zoo_infer(const char *name,
                             const void *input,
                             size_t input_len,
                             void *output,
                             size_t output_len,
                             size_t *out_len);

/**
 * @brief List model names stored on SPIFFS.
 *
 * Returned names are base names without extension.
 */
esp_err_t ai_model_zoo_list(char ***names, size_t *count);

/**
 * @brief Free list returned by ai_model_zoo_list().
 */
void ai_model_zoo_free_list(char **names, size_t count);

/**
 * @brief Get metadata for a loaded model.
 */
esp_err_t ai_model_zoo_get_info(const char *name, ai_model_info_t *out_info);

/**
 * @brief Format all loaded models as JSON.
 */
esp_err_t ai_model_zoo_json(char *buf, size_t bufsz);

/**
 * @brief Unload all models and deinit.
 */
void ai_model_zoo_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* AI_MODEL_H */
