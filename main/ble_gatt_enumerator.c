#include "ble_gatt_enumerator.h"
#include "ble_gatt_client.h"
#include <string.h>
#include "esp_log.h"

static ble_gatt_enum_svc_t s_svcs[BLE_GATT_ENUM_MAX_SVCS];
static ble_gatt_enum_char_t s_chars[BLE_GATT_ENUM_MAX_CHARS];
static size_t s_svc_count = 0;
static size_t s_char_count = 0;
static bool s_init = false;
static const char *TAG = "gatt_enum";

static void svc_cb(ble_gattc_conn_t conn, const ble_gattc_svc_t *svc,
                   void *arg)
{
    (void)conn;
    if (!svc || !arg) return;
    size_t *count = (size_t *)arg;
    if (*count >= BLE_GATT_ENUM_MAX_SVCS) return;
    memcpy(s_svcs[*count].uuid, svc->uuid, svc->uuid_len);
    s_svcs[*count].uuid_len = svc->uuid_len;
    s_svcs[*count].start_handle = svc->start_handle;
    s_svcs[*count].end_handle = svc->end_handle;
    (*count)++;
}

static void char_cb(ble_gattc_conn_t conn, const ble_gattc_char_t *chr,
                    void *arg)
{
    (void)conn;
    if (!chr || !arg) return;
    size_t *count = (size_t *)arg;
    if (*count >= BLE_GATT_ENUM_MAX_CHARS) return;
    memcpy(s_chars[*count].uuid, chr->uuid, chr->uuid_len);
    s_chars[*count].uuid_len = chr->uuid_len;
    s_chars[*count].decl_handle = chr->decl_handle;
    s_chars[*count].value_handle = chr->value_handle;
    s_chars[*count].props = chr->props;
    s_chars[*count].perm = BLE_GATT_PERM_READ; /* Default: readable */
    (*count)++;
}

esp_err_t ble_gatt_enumerator_init(void)
{
    memset(s_svcs, 0, sizeof(s_svcs));
    memset(s_chars, 0, sizeof(s_chars));
    s_svc_count = 0;
    s_char_count = 0;
    s_init = true;
    ESP_LOGI(TAG, "GATT enumerator initialized");
    return ESP_OK;
}

esp_err_t ble_gatt_enumerator_enumerate(const uint8_t *mac, uint32_t timeout_ms)
{
    if (!s_init || !mac) return ESP_ERR_INVALID_ARG;
    ble_gattc_conn_t conn = 0;
    esp_err_t err = ble_gattc_connect(mac, timeout_ms, &conn);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "connect failed for "MACSTR, MAC2STR(mac));
        return err;
    }
    s_svc_count = 0;
    s_char_count = 0;
    err = ble_gattc_discover_services(conn, NULL, 0, &s_svc_count, svc_cb,
                                      &s_svc_count);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "service discovery failed");
        ble_gattc_disconnect(conn);
        return err;
    }
    for (size_t i = 0; i < s_svc_count; i++) {
        size_t idx = i;
        ble_gattc_discover_chars(conn,
                                 s_svcs[i].start_handle,
                                 s_svcs[i].end_handle,
                                 NULL, 0, &s_char_count, char_cb, &s_char_count);
    }
    ble_gattc_disconnect(conn);
    ESP_LOGI(TAG, "Enumerated %d services, %d characteristics",
             (int)s_svc_count, (int)s_char_count);
    return ESP_OK;
}

size_t ble_gatt_enumerator_services(ble_gatt_enum_svc_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_svc_count < max ? s_svc_count : max;
    memcpy(out, s_svcs, n * sizeof(ble_gatt_enum_svc_t));
    return n;
}

size_t ble_gatt_enumerator_chars(ble_gatt_enum_char_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_char_count < max ? s_char_count : max;
    memcpy(out, s_chars, n * sizeof(ble_gatt_enum_char_t));
    return n;
}

void ble_gatt_enumerator_clear(void)
{
    memset(s_svcs, 0, sizeof(s_svcs));
    memset(s_chars, 0, sizeof(s_chars));
    s_svc_count = 0;
    s_char_count = 0;
}
