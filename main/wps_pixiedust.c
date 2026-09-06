#include "wps_pixiedust.h"
#include <string.h>
#include "esp_log.h"

static pd_candidate_t s_cands[PIXIEDUST_MAX_NONCES];
static size_t s_count = 0;
static bool s_init = false;
static const char *TAG = "pixiedust";

esp_err_t wps_pixiedust_init(void)
{
    memset(s_cands, 0, sizeof(s_cands));
    s_count = 0;
    s_init = true;
    ESP_LOGI(TAG, "WPS PixieDust collector initialized");
    return ESP_OK;
}

void wps_pixiedust_record(const uint8_t *e_nonce, size_t e_nonce_len,
                          const uint8_t *r_nonce, size_t r_nonce_len,
                          const uint8_t *e_hash1, size_t e1_len,
                          const uint8_t *e_hash2, size_t e2_len)
{
    if (!s_init || !e_nonce || !r_nonce || !e_hash1 || !e_hash2) return;
    if (s_count >= PIXIEDUST_MAX_NONCES) return;
    pd_candidate_t *c = &s_cands[s_count];
    memcpy(c->enrollee_nonce, e_nonce, e_nonce_len < 128 ? e_nonce_len : 128);
    memcpy(c->registrar_nonce, r_nonce, r_nonce_len < 128 ? r_nonce_len : 128);
    memcpy(c->e_hash1, e_hash1, e1_len < 32 ? e1_len : 32);
    memcpy(c->e_hash2, e_hash2, e2_len < 32 ? e2_len : 32);
    c->valid = true;
    s_count++;
}

size_t wps_pixiedust_candidates(pd_candidate_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_count < max ? s_count : max;
    memcpy(out, s_cands, n * sizeof(pd_candidate_t));
    return n;
}

void wps_pixiedust_clear(void)
{
    memset(s_cands, 0, sizeof(s_cands));
    s_count = 0;
}

bool wps_pixiedust_compute_pin(const uint8_t *e_hash1, const uint8_t *e_hash2,
                               const uint8_t *r_nonce, const uint8_t *e_nonce,
                               char *pin_out, size_t pin_len)
{
    (void)e_hash1; (void)e_hash2; (void)r_nonce; (void)e_nonce;
    if (!pin_out || pin_len < 8) return false;
    memset(pin_out, 0, pin_len);
    return false;
}
