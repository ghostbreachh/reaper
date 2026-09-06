#ifndef SAE_SIDECHANNEL_H
#define SAE_SIDECHANNEL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SAE_SAMPLES_MAX 64

typedef struct {
    uint32_t t_us;
    int8_t rssi;
    bool commit;
} sae_sample_t;

esp_err_t sae_sidechannel_init(void);
void sae_sidechannel_record(uint32_t t_us, bool commit);
size_t sae_sidechannel_collect(sae_sample_t *out, size_t max);
float sae_sidechannel_entropy(void);
void sae_sidechannel_clear(void);

#ifdef __cplusplus
}
#endif
#endif
