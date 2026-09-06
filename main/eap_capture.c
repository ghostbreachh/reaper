#include "eap_capture.h"
#include <string.h>
#include "esp_log.h"

static char s_identity[EAP_MAX_ID];
static size_t s_id_len = 0;
static eap_cert_t s_certs[EAP_MAX_CERTS];
static size_t s_cert_count = 0;
static bool s_init = false;
static const char *TAG = "eap_cap";

esp_err_t eap_capture_init(void)
{
    memset(s_identity, 0, sizeof(s_identity));
    s_id_len = 0;
    memset(s_certs, 0, sizeof(s_certs));
    s_cert_count = 0;
    s_init = true;
    ESP_LOGI(TAG, "Enterprise EAP capture initialized");
    return ESP_OK;
}

void eap_capture_record_identity(const uint8_t *identity, size_t len)
{
    if (!s_init || !identity || !len) return;
    if (len >= sizeof(s_identity)) len = sizeof(s_identity) - 1;
    memcpy(s_identity, identity, len);
    s_identity[len] = 0;
    s_id_len = len;
}

void eap_capture_record_cert(const uint8_t *der, size_t len)
{
    if (!s_init || !der || !len || s_cert_count >= EAP_MAX_CERTS) return;
    size_t copy = len < sizeof(s_certs[0].data) ? len : sizeof(s_certs[0].data);
    memcpy(s_certs[s_cert_count].data, der, copy);
    s_certs[s_cert_count].len = copy;
    s_certs[s_cert_count].valid = true;
    s_cert_count++;
}

size_t eap_capture_identity(char *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_id_len < max ? s_id_len : max;
    memcpy(out, s_identity, n);
    return n;
}

size_t eap_capture_certs(eap_cert_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_cert_count < max ? s_cert_count : max;
    memcpy(out, s_certs, n * sizeof(eap_cert_t));
    return n;
}

void eap_capture_clear(void)
{
    memset(s_identity, 0, sizeof(s_identity));
    s_id_len = 0;
    memset(s_certs, 0, sizeof(s_certs));
    s_cert_count = 0;
}
