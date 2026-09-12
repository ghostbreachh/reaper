#include "wps_pixiedust.h"

#include <string.h>
#include <stdint.h>

#include "esp_log.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "pixiedust";

static pd_candidate_t s_cands[PIXIEDUST_MAX_NONCES];
static size_t s_count = 0;
static bool s_init = false;

static SemaphoreHandle_t s_mutex = NULL;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static bool copy_field(uint8_t *dst,
                       size_t dst_max,
                       const uint8_t *src,
                       size_t src_len,
                       uint8_t *out_len)
{
    if (dst == NULL || src == NULL || out_len == NULL) {
        return false;
    }

    if (src_len == 0 || src_len > dst_max || src_len > UINT8_MAX) {
        return false;
    }

    memset(dst, 0, dst_max);
    memcpy(dst, src, src_len);

    *out_len = (uint8_t)src_len;

    return true;
}

static bool candidate_matches(const pd_candidate_t *a, const pd_candidate_t *b)
{
    if (a->enrollee_nonce_len != b->enrollee_nonce_len) {
        return false;
    }

    if (a->registrar_nonce_len != b->registrar_nonce_len) {
        return false;
    }

    if (a->e_hash1_len != b->e_hash1_len) {
        return false;
    }

    if (a->e_hash2_len != b->e_hash2_len) {
        return false;
    }

    if (memcmp(a->enrollee_nonce, b->enrollee_nonce, a->enrollee_nonce_len) != 0) {
        return false;
    }

    if (memcmp(a->registrar_nonce, b->registrar_nonce, a->registrar_nonce_len) != 0) {
        return false;
    }

    if (memcmp(a->e_hash1, b->e_hash1, a->e_hash1_len) != 0) {
        return false;
    }

    if (memcmp(a->e_hash2, b->e_hash2, a->e_hash2_len) != 0) {
        return false;
    }

    return true;
}

/* -------------------------------------------------------------------------
 *  Public API
 * ----------------------------------------------------------------------- */

esp_err_t wps_pixiedust_init(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
        if (s_mutex == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    memset(s_cands, 0, sizeof(s_cands));
    s_count = 0;
    s_init = true;

    xSemaphoreGive(s_mutex);

    ESP_LOGI(TAG, "WPS PixieDust collector initialized");
    return ESP_OK;
}

void wps_pixiedust_record(const uint8_t *e_nonce, size_t e_nonce_len,
                          const uint8_t *r_nonce, size_t r_nonce_len,
                          const uint8_t *e_hash1, size_t e1_len,
                          const uint8_t *e_hash2, size_t e2_len)
{
    if (!s_init || s_mutex == NULL) {
        return;
    }

    if (e_nonce == NULL || r_nonce == NULL ||
        e_hash1 == NULL || e_hash2 == NULL) {
        return;
    }

    pd_candidate_t tmp;
    memset(&tmp, 0, sizeof(tmp));

    if (!copy_field(tmp.enrollee_nonce,
                    sizeof(tmp.enrollee_nonce),
                    e_nonce,
                    e_nonce_len,
                    &tmp.enrollee_nonce_len)) {
        ESP_LOGW(TAG, "Rejecting candidate: invalid enrollee nonce length");
        return;
    }

    if (!copy_field(tmp.registrar_nonce,
                    sizeof(tmp.registrar_nonce),
                    r_nonce,
                    r_nonce_len,
                    &tmp.registrar_nonce_len)) {
        ESP_LOGW(TAG, "Rejecting candidate: invalid registrar nonce length");
        return;
    }

    if (!copy_field(tmp.e_hash1,
                    sizeof(tmp.e_hash1),
                    e_hash1,
                    e1_len,
                    &tmp.e_hash1_len)) {
        ESP_LOGW(TAG, "Rejecting candidate: invalid E-Hash1 length");
        return;
    }

    if (!copy_field(tmp.e_hash2,
                    sizeof(tmp.e_hash2),
                    e_hash2,
                    e2_len,
                    &tmp.e_hash2_len)) {
        ESP_LOGW(TAG, "Rejecting candidate: invalid E-Hash2 length");
        return;
    }

    tmp.captured_at_us = esp_timer_get_time();
    tmp.valid = true;

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    if (s_count >= PIXIEDUST_MAX_NONCES) {
        xSemaphoreGive(s_mutex);
        ESP_LOGD(TAG, "PixieDust candidate table full; dropping new candidate");
        return;
    }

    for (size_t i = 0; i < s_count; i++) {
        if (candidate_matches(&s_cands[i], &tmp)) {
            xSemaphoreGive(s_mutex);
            ESP_LOGD(TAG, "Duplicate PixieDust candidate ignored");
            return;
        }
    }

    s_cands[s_count] = tmp;
    s_count++;

    xSemaphoreGive(s_mutex);

    ESP_LOGD(TAG, "PixieDust candidate recorded (%zu total)", s_count);
}

size_t wps_pixiedust_candidates(pd_candidate_t *out, size_t max)
{
    if (!s_init || s_mutex == NULL || out == NULL || max == 0) {
        return 0;
    }

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    size_t n = (s_count < max) ? s_count : max;

    memcpy(out, s_cands, n * sizeof(pd_candidate_t));

    xSemaphoreGive(s_mutex);

    return n;
}

void wps_pixiedust_clear(void)
{
    if (s_mutex == NULL) {
        return;
    }

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    memset(s_cands, 0, sizeof(s_cands));
    s_count = 0;

    xSemaphoreGive(s_mutex);
}

bool wps_pixiedust_compute_pin(const uint8_t *e_hash1,
                               const uint8_t *e_hash2,
                               const uint8_t *r_nonce,
                               const uint8_t *e_nonce,
                               char *pin_out,
                               size_t pin_len)
{
    (void)e_hash1;
    (void)e_hash2;
    (void)r_nonce;
    (void)e_nonce;

    if (pin_out == NULL || pin_len < 9) {
        return false;
    }

    memset(pin_out, 0, pin_len);

    /*
     * Intentionally unimplemented on-device.
     *
     * Pixie Dust recovery is computationally expensive and usually performed
     * offline using captured nonces/hashes.
     *
     * The ESP32 should collect and export the candidate material; the host
     * app or external tool should perform the actual recovery.
     */
    ESP_LOGD(TAG, "PixieDust PIN computation not implemented on-device");

    return false;
}
