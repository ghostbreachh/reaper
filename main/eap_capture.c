#include "eap_capture.h"

#include <string.h>
#include <stdatomic.h>

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static char s_identity[EAP_MAX_ID];
static size_t s_id_len = 0;
static eap_cert_t s_certs[EAP_MAX_CERTS];
static size_t s_cert_count = 0;
static atomic_bool s_init = ATOMIC_VAR_INIT(false);
static SemaphoreHandle_t s_lock = NULL;
static const char *TAG = "eap_cap";

esp_err_t eap_capture_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
        if (s_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    memset(s_identity, 0, sizeof(s_identity));
    s_id_len = 0;
    memset(s_certs, 0, sizeof(s_certs));
    s_cert_count = 0;
    xSemaphoreGive(s_lock);

    atomic_store(&s_init, true);
    ESP_LOGI(TAG, "Enterprise EAP capture initialized");
    return ESP_OK;
}

void eap_capture_record_identity(const uint8_t *identity, size_t len)
{
    if (!atomic_load(&s_init) || s_lock == NULL || !identity || !len) return;

    /* Non-blocking: drop if contended to avoid stalling the sniffer */
    if (xSemaphoreTake(s_lock, 0) != pdTRUE) return;

    size_t copy_len = len;
    if (copy_len >= sizeof(s_identity)) {
        copy_len = sizeof(s_identity) - 1;
        ESP_LOGW(TAG, "EAP Identity truncated to %zu bytes", copy_len);
    }
    
    memcpy(s_identity, identity, copy_len);
    s_identity[copy_len] = '\0';
    s_id_len = copy_len;

    xSemaphoreGive(s_lock);
}

void eap_capture_record_cert(const uint8_t *der, size_t len)
{
    if (!atomic_load(&s_init) || s_lock == NULL || !der || !len) return;

    if (xSemaphoreTake(s_lock, 0) != pdTRUE) return;

    if (s_cert_count >= EAP_MAX_CERTS) {
        xSemaphoreGive(s_lock);
        return;
    }

    size_t copy_len = len;
    bool truncated = false;
    if (copy_len > EAP_CERT_MAX_LEN) {
        copy_len = EAP_CERT_MAX_LEN;
        truncated = true;
        ESP_LOGW(TAG, "EAP Certificate fragment truncated to %zu bytes (orig: %zu)", copy_len, len);
    }
    
    memcpy(s_certs[s_cert_count].data, der, copy_len);
    s_certs[s_cert_count].len = copy_len;
    s_certs[s_cert_count].valid = true;
    s_certs[s_cert_count].truncated = truncated;
    s_cert_count++;

    xSemaphoreGive(s_lock);
}

size_t eap_capture_identity(char *out, size_t max)
{
    if (!out || !max || !atomic_load(&s_init) || s_lock == NULL) return 0;

    size_t n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        n = s_id_len;
        if (n >= max) n = max - 1;
        memcpy(out, s_identity, n);
        out[n] = '\0'; /* Ensure null-termination */
        xSemaphoreGive(s_lock);
    }
    return n;
}

size_t eap_capture_certs(eap_cert_t *out, size_t max)
{
    if (!out || !max || !atomic_load(&s_init) || s_lock == NULL) return 0;

    size_t n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        n = s_cert_count < max ? s_cert_count : max;
        memcpy(out, s_certs, n * sizeof(eap_cert_t));
        xSemaphoreGive(s_lock);
    }
    return n;
}

void eap_capture_clear(void)
{
    if (!atomic_load(&s_init) || s_lock == NULL) return;

    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        memset(s_identity, 0, sizeof(s_identity));
        s_id_len = 0;
        memset(s_certs, 0, sizeof(s_certs));
        s_cert_count = 0;
        xSemaphoreGive(s_lock);
    }
}
