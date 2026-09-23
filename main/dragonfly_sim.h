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

/**
 * @brief Validate a password against a known PMK using PBKDF2-SHA256.
 * 
 * NOTE: This is WPA2-PSK logic. WPA3-SAE uses ECC (Hunting & Pecking).
 * 
 * @param password The password to test.
 * @param pwd_len Length of the password.
 * @param pmk The expected 32-byte PMK.
 * @param salt The SSID (salt).
 * @param salt_len Length of the SSID (1-32 bytes).
 * @return true if the calculated PMK matches the expected PMK.
 */
bool dragonfly_sim_validate(const uint8_t *password, size_t pwd_len,
                            const uint8_t *pmk, 
                            const uint8_t *salt, size_t salt_len);

/**
 * @brief Stub for SAE Commit validation.
 * 
 * Real implementation requires mbedTLS ECC (ecp) to verify the PWE scalar/element.
 */
bool dragonfly_sim_try_commit(const uint8_t *pwd, size_t pwd_len,
                              const uint8_t *expected_element);

#ifdef __cplusplus
}
#endif

#endif /* DRAGONFLY_SIM_H */
