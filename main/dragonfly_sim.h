#ifndef DRAGONFLY_SIM_H
#define DRAGONFLY_SIM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t dragonfly_sim_init(void);
bool dragonfly_sim_validate(const uint8_t *password, size_t pwd_len,
                            const uint8_t *pmk, const uint8_t *salt);
bool dragonfly_sim_try_commit(const uint8_t *pwd, size_t pwd_len,
                              const uint8_t *expected_element);

#ifdef __cplusplus
}
#endif
#endif
