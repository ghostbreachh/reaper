#include "ble_gatt_client.h"
#include <string.h>
#include <stdbool.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"

/* nimble GAP event callback typedef */
typedef int (*ble_gap_event_fn_t)(struct ble_gap_event *event, void *arg);

/* Discovery callback typedefs */
typedef void (*ble_gattc_disc_svc_fn)(ble_gattc_conn_t conn_handle,
                                      const ble_gattc_svc_t *svc, void *arg);
typedef void (*ble_gattc_disc_char_fn)(ble_gattc_conn_t conn_handle,
                                       const ble_gattc_char_t *chr, void *arg);

static const char *TAG = "ble_gattc";

#define MAX_GATTC_CONNECTIONS 4
#define GATTC_CONNECT_TIMEOUT_MS 10000
#define GATTC_DISCOVERY_TIMEOUT_MS 5000

/* Per-connection state */
typedef struct {
    ble_gattc_conn_t conn_handle;
    uint8_t peer_mac[6];
    bool in_use;
    ble_gattc_state_t state;
    int connect_rc;
    int disc_rc;
    uint32_t connect_start_ms;

    /* Service discovery callback storage */
    ble_gattc_disc_svc_fn svc_cb;
    void *svc_cb_arg;
    ble_gattc_disc_char_fn char_cb;
    void *char_cb_arg;
} gattc_conn_state_t;

static gattc_conn_state_t g_conns[MAX_GATTC_CONNECTIONS];
static SemaphoreHandle_t g_gattc_lock = NULL;
/* Previous GAP callback chain removed: ble_gap_event_cb reads local
 * stack variables and is unsafe to call from another translation unit.
 * GATTC events are handled directly here without chaining. */

static void gattc_lock_init(void)
{
    if (g_gattc_lock == NULL) {
        g_gattc_lock = xSemaphoreCreateMutex();
    }
}

static gattc_conn_state_t *gattc_find_free(void)
{
    if (g_gattc_lock == NULL) gattc_lock_init();
    xSemaphoreTake(g_gattc_lock, portMAX_DELAY);
    for (int i = 0; i < MAX_GATTC_CONNECTIONS; i++) {
        if (!g_conns[i].in_use) {
            xSemaphoreGive(g_gattc_lock);
            return &g_conns[i];
        }
    }
    xSemaphoreGive(g_gattc_lock);
    return NULL;
}

static gattc_conn_state_t *gattc_find_by_handle(ble_gattc_conn_t conn)
{
    if (g_gattc_lock == NULL) gattc_lock_init();
    xSemaphoreTake(g_gattc_lock, portMAX_DELAY);
    for (int i = 0; i < MAX_GATTC_CONNECTIONS; i++) {
        if (g_conns[i].in_use && g_conns[i].conn_handle == conn) {
            xSemaphoreGive(g_gattc_lock);
            return &g_conns[i];
        }
    }
    xSemaphoreGive(g_gattc_lock);
    return NULL;
}

static void gattc_set_state(ble_gattc_conn_t conn, ble_gattc_state_t new_state)
{
    if (g_gattc_lock == NULL) return;
    xSemaphoreTake(g_gattc_lock, portMAX_DELAY);
    for (int i = 0; i < MAX_GATTC_CONNECTIONS; i++) {
        if (g_conns[i].in_use && g_conns[i].conn_handle == conn) {
            g_conns[i].state = new_state;
            xSemaphoreGive(g_gattc_lock);
            return;
        }
    }
    xSemaphoreGive(g_gattc_lock);
}

static void gattc_free(ble_gattc_conn_t conn)
{
    if (g_gattc_lock == NULL) return;
    xSemaphoreTake(g_gattc_lock, portMAX_DELAY);
    for (int i = 0; i < MAX_GATTC_CONNECTIONS; i++) {
        if (g_conns[i].in_use && g_conns[i].conn_handle == conn) {
            g_conns[i].in_use = false;
            memset(&g_conns[i], 0, sizeof(g_conns[i]));
            xSemaphoreGive(g_gattc_lock);
            return;
        }
    }
    xSemaphoreGive(g_gattc_lock);
}

static int gattc_event_handler(struct ble_gap_event *event, void *arg)
{
    gattc_conn_state_t *st = (gattc_conn_state_t *)arg;

    if (st == NULL || !st->in_use) {
        return 0;
    }

    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT:
            if (event->connect.status == 0) {
                st->conn_handle = event->connect.conn_handle;
                st->state = BLE_GATTC_STATE_CONNECTED;
                ESP_LOGI(TAG, "GATTC connected, handle=%d", st->conn_handle);
            } else {
                st->state = BLE_GATTC_STATE_ERROR;
                st->connect_rc = event->connect.status;
                ESP_LOGE(TAG, "GATTC connect failed: %d", event->connect.status);
            }
            break;

        case BLE_GAP_EVENT_DISCONNECT:
            ESP_LOGI(TAG, "GATTC disconnected, reason=%d",
                     event->disconnect.reason);
            st->state = BLE_GATTC_STATE_IDLE;
            gattc_free(st->conn_handle);
            break;

        case BLE_GAP_EVENT_MTU:
            ESP_LOGI(TAG, "GATTC MTU updated: %d", event->mtu.value);
            break;

        default:
            break;
    }

    /* Chain to previous GAP callback if registered */
    return 0;
    return 0;
}

esp_err_t ble_gattc_init(void)
{
    gattc_lock_init();
    memset(g_conns, 0, sizeof(g_conns));
    ESP_LOGI(TAG, "GATT client initialized, max connections=%d",
             MAX_GATTC_CONNECTIONS);
    return ESP_OK;
}

esp_err_t ble_gattc_connect(const uint8_t *mac, uint32_t timeout_ms,
                            ble_gattc_conn_t *out_conn_handle)
{
    if (mac == NULL || out_conn_handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!g_ble_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    gattc_conn_state_t *st = gattc_find_free();
    if (st == NULL) {
        ESP_LOGE(TAG, "No free GATTC connection slots");
        return ESP_ERR_NO_MEM;
    }

    memcpy(st->peer_mac, mac, 6);
    st->in_use = true;
    st->state = BLE_GATTC_STATE_CONNECTING;
    st->connect_rc = 0;
    st->connect_start_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;

    /* Callback registered directly in ble_gap_connect() below */

    struct ble_gap_conn_params conn_params;
    memset(&conn_params, 0, sizeof(conn_params));
    conn_params.scan_interval = 0x0010;
    conn_params.scan_window = 0x0010;
    conn_params.itvl_min = 0x0018;
    conn_params.itvl_max = 0x0028;
    conn_params.latency = 0;
    conn_params.supervision_timeout = 0x01F4;
    conn_params.min_ce_len = 0x0000;
    conn_params.max_ce_len = 0x0000;

    int rc = ble_gap_connect(
        BLE_OWN_ADDR_RANDOM,
        (ble_addr_t *)mac,
        timeout_ms,
        &conn_params,
        gattc_event_handler,
        st
    );

    if (rc != 0) {
        st->state = BLE_GATTC_STATE_ERROR;
        st->in_use = false;
        memset(st, 0, sizeof(*st));
        ESP_LOGE(TAG, "ble_gap_connect failed: %d", rc);
        return ESP_FAIL;
    }

    /* Wait for connection or timeout */
    uint32_t start = xTaskGetTickCount();
    while (st->in_use && st->state == BLE_GATTC_STATE_CONNECTING) {
        uint32_t elapsed = (xTaskGetTickCount() - start) * portTICK_PERIOD_MS;
        if (elapsed >= timeout_ms) {
            st->state = BLE_GATTC_STATE_ERROR;
            gattc_free(st->conn_handle);
            ESP_LOGE(TAG, "GATTC connect timeout");
            return ESP_ERR_TIMEOUT;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    if (st->state != BLE_GATTC_STATE_CONNECTED) {
        gattc_free(st->conn_handle);
        return ESP_FAIL;
    }

    *out_conn_handle = st->conn_handle;
    return ESP_OK;
}

esp_err_t ble_gattc_disconnect(ble_gattc_conn_t conn_handle)
{
    gattc_conn_state_t *st = gattc_find_by_handle(conn_handle);
    if (st == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    int rc = ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_terminate failed: %d", rc);
        return ESP_FAIL;
    }

    st->state = BLE_GATTC_STATE_IDLE;
    gattc_free(conn_handle);
    return ESP_OK;
}

esp_err_t ble_gattc_discover_services(ble_gattc_conn_t conn_handle,
                                      ble_gattc_svc_t *svcs, size_t max,
                                      size_t *out_count,
                                      ble_gattc_disc_svc_fn cb, void *cb_arg)
{
    if (svcs == NULL || out_count == NULL || max == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    gattc_conn_state_t *st = gattc_find_by_handle(conn_handle);
    if (st == NULL || st->state != BLE_GATTC_STATE_CONNECTED) {
        return ESP_ERR_INVALID_STATE;
    }

    st->state = BLE_GATTC_STATE_DISCOVERING;
    st->svc_cb = cb;
    st->svc_cb_arg = cb_arg;

    /* Discover all primary services. Callback would populate svcs array;
     * here we start discovery and log intent because full callback storage
     * requires per-service context not yet wired into CLI/JSON-RPC. */
    int rc = ble_gattc_disc_all_svcs(conn_handle, NULL);
    if (rc != 0) {
        st->state = BLE_GATTC_STATE_CONNECTED;
        ESP_LOGE(TAG, "ble_gattc_disc_all_svcs failed: %d", rc);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Service discovery started on handle=%d", conn_handle);

    *out_count = 0;
    st->state = BLE_GATTC_STATE_CONNECTED;
    return ESP_OK;
}

esp_err_t ble_gattc_discover_chars(ble_gattc_conn_t conn_handle,
                                   uint16_t start_handle, uint16_t end_handle,
                                   ble_gattc_char_t *chars, size_t max,
                                   size_t *out_count,
                                   ble_gattc_disc_char_fn cb, void *cb_arg)
{
    if (chars == NULL || out_count == NULL || max == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    gattc_conn_state_t *st = gattc_find_by_handle(conn_handle);
    if (st == NULL || st->state != BLE_GATTC_STATE_CONNECTED) {
        return ESP_ERR_INVALID_STATE;
    }

    st->state = BLE_GATTC_STATE_DISCOVERING;
    st->char_cb = cb;
    st->char_cb_arg = cb_arg;

    int rc = ble_gattc_disc_chars(
        conn_handle,
        start_handle,
        end_handle,
        NULL,
        NULL
    );

    if (rc != 0) {
        st->state = BLE_GATTC_STATE_CONNECTED;
        ESP_LOGE(TAG, "ble_gattc_disc_chars failed: %d", rc);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Characteristic discovery started %u-%u",
             start_handle, end_handle);

    *out_count = 0;
    st->state = BLE_GATTC_STATE_CONNECTED;
    return ESP_OK;
}

esp_err_t ble_gattc_read_char(ble_gattc_conn_t conn_handle,
                              uint16_t char_handle,
                              uint8_t *buf, size_t max_len, size_t *out_len)
{
    if (buf == NULL || out_len == NULL || max_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    gattc_conn_state_t *st = gattc_find_by_handle(conn_handle);
    if (st == NULL || st->state != BLE_GATTC_STATE_CONNECTED) {
        return ESP_ERR_INVALID_STATE;
    }

    st->state = BLE_GATTC_STATE_READING;

    uint16_t actual_len = 0;
    memset(buf, 0, max_len);

    int rc = ble_gattc_read(
        conn_handle,
        char_handle,
        buf,
        max_len,
        &actual_len,
        BLE_GRP_ATTRS
    );

    if (rc != 0) {
        st->state = BLE_GATTC_STATE_CONNECTED;
        ESP_LOGE(TAG, "ble_gattc_read failed: %d", rc);
        return ESP_FAIL;
    }

    *out_len = actual_len;
    st->state = BLE_GATTC_STATE_CONNECTED;

    ESP_LOGI(TAG, "Read %u bytes from char handle %u", actual_len, char_handle);
    return ESP_OK;
}

ble_gattc_state_t ble_gattc_get_state(ble_gattc_conn_t conn_handle)
{
    gattc_conn_state_t *st = gattc_find_by_handle(conn_handle);
    if (st == NULL) {
        return BLE_GATTC_STATE_IDLE;
    }
    return st->state;
}

bool ble_gattc_get_remote_mac(ble_gattc_conn_t conn_handle, uint8_t *out_mac)
{
    if (out_mac == NULL) return false;
    gattc_conn_state_t *st = gattc_find_by_handle(conn_handle);
    if (st == NULL) {
        return false;
    }
    memcpy(out_mac, st->peer_mac, 6);
    return true;
}
