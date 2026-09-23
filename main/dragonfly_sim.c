#include "dragonfly_sim.h"

#include <string.h>
#include <stdatomic.h>

#include "esp_log.h"

#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"

static atomic_bool s_init = ATOMIC_VAR_INIT(false);
static const char *TAG = "dragonfly";

esp_err_t dragonfly_sim_init(void)
{
    atomic_store(&s_init, true);
    ESP_LOGI(TAG, "Dragonfly simulator initialized (PBKDF2-SHA256)");
    return ESP_OK;
}

bool dragonfly_sim_validate(const uint8_t *password, size_t pwd_len,
                            const uint8_t *pmk, 
                            const uint8_t *salt, size_t salt_len)
{
    if (!atomic_load(&s_init) || !password || !pmk || !salt || salt_len == 0) {
        return false;
    }

    /* PMK is always 32 bytes (256 bits) for SHA256 */
    uint8_t calc[32] = {0};
    
    /* 
     * Correct PBKDF2 usage: 
     * Iterations = 4096 (Standard for WPA2)
     * Salt = SSID (exact length required)
     */
    int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                             password, pwd_len,
                                             salt, salt_len, 
                                             4096,
                                             sizeof(calc), calc);
    if (ret != 0) {
        ESP_LOGE(TAG, "PBKDF2 failed: -0x%04x", -ret);
        return false;
    }
    
    return memcmp(calc, pmk, sizeof(calc)) == 0;
}

bool dragonfly_sim_try_commit(const uint8_t *pwd, size_t pwd_len,
                              const uint8_t *expected_element)
{
    (void)pwd; 
    (void)pwd_len; 
    (void)expected_element;
    
    /* 
     * STUB: 
     * Real WPA3-SAE commit validation requires:
     * 1. Hunting and Pecking algorithm to derive PWE (Password Element)
     * 2. Elliptic Curve point multiplication (mbedtls_ecp_mul)
     * 3. Verification of the scalar and element against the commit frame.
     * 
     * PBKDF2 alone cannot validate a SAE commit.
     */
    return false;
}
