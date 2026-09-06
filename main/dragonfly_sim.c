#include "dragonfly_sim.h"
#include <string.h>
#include "esp_log.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"

static bool s_init = false;
static const char *TAG = "dragonfly";

esp_err_t dragonfly_sim_init(void)
{
    s_init = true;
    ESP_LOGI(TAG, "Dragonfly simulator initialized");
    return ESP_OK;
}

bool dragonfly_sim_validate(const uint8_t *password, size_t pwd_len,
                            const uint8_t *pmk, const uint8_t *salt)
{
    if (!s_init || !password || !pmk || !salt) return false;
    uint8_t calc[32] = {0};
    int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                             password, (int)pwd_len,
                                             salt, 32, 4096,
                                             sizeof(calc), calc);
    if (ret != 0) return false;
    return memcmp(calc, pmk, sizeof(calc)) == 0;
}

bool dragonfly_sim_try_commit(const uint8_t *pwd, size_t pwd_len,
                              const uint8_t *expected_element)
{
    (void)pwd; (void)pwd_len; (void)expected_element;
    return false;
}
