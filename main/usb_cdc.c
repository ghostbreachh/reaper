/*
 * ============================================================================
 *  usb_cdc.c  —  TinyUSB CDC-ACM: VID/PID, strings, line coding, break,
 *                 flow control, and capability detection on connect
 * ============================================================================
 *
 *  T2T Step 3.2 — Research & Brainstorming
 *
 *  Branch A — Capability snapshot only at init time
 *    Decision: REJECTED. Capabilities can change at runtime (DTR/RTS toggle,
 *    VID/PID update via CLI, TX buffer availability).
 *
 *  Branch B — On-demand snapshot API + JSON-RPC exposure
 *    Decision: ACCEPTED. Companion app queries this immediately after USB
 *    connect to learn device identity, line coding, and flow state.
 *
 *  Branch C — Automatic notification on connect/disconnect
 *    Decision: REJECTED. The companion app detects USB connect via OS APIs;
 *    we do not push unsolicited JSON-RPC over CDC because the transport may
 *    not be ready immediately after enum.
 * ============================================================================
 */

#include <string.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"

#include "usb_cdc.h"

static const char *TAG = "usb_cdc";

#define USB_CDC_DEFAULT_VID  0xDEAD
#define USB_CDC_DEFAULT_PID  0xBEEF
#define USB_CDC_NVS_NS       "usb_cdc"
#define USB_CDC_NVS_KEY      "line_coding"

static uint16_t             g_vid = USB_CDC_DEFAULT_VID;
static uint16_t             g_pid = USB_CDC_DEFAULT_PID;
static char                 g_serial[32] = {0};
static usb_cdc_line_coding_t g_line_coding = {
    .bit_rate   = 115200,
    .data_bits  = 8,
    .parity     = 0,
    .stop_bits  = 1,
};
static SemaphoreHandle_t    g_mutex = NULL;

static _Atomic bool         g_dtr_current = ATOMIC_VAR_INIT(false);
static _Atomic bool         g_rts_current = ATOMIC_VAR_INIT(false);
static bool                 g_break_pending = false;

/* Flow control state */
static _Atomic bool         g_tx_paused = ATOMIC_VAR_INIT(false);
static _Atomic size_t       g_tx_pending = ATOMIC_VAR_INIT(0);

/*============================================================================*/
static void ensure_serial(void)
{
    if (g_serial[0] != '\0') {
        return;
    }
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_BASE);
    snprintf(g_serial, sizeof(g_serial),
             "%02X%02X%02X", mac[3], mac[4], mac[5]);
}

/*============================================================================*/
static esp_err_t load_line_coding(void)
{
    nvs_handle_t nvs;
    esp_err_t rc = nvs_open(USB_CDC_NVS_NS, NVS_READONLY, &nvs);
    if (rc != ESP_OK) {
        return rc;
    }
    size_t sz = sizeof(g_line_coding);
    rc = nvs_get_blob(nvs, USB_CDC_NVS_KEY, &g_line_coding, &sz);
    if (rc == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        nvs_open(USB_CDC_NVS_NS, NVS_READWRITE, &nvs);
        nvs_set_blob(nvs, USB_CDC_NVS_KEY, &g_line_coding, sizeof(g_line_coding));
        nvs_commit(nvs);
        rc = ESP_OK;
    }
    nvs_close(nvs);
    return rc;
}

/*============================================================================*/
static esp_err_t save_line_coding(void)
{
    nvs_handle_t nvs;
    esp_err_t rc = nvs_open(USB_CDC_NVS_NS, NVS_READWRITE, &nvs);
    if (rc != ESP_OK) {
        return rc;
    }
    rc = nvs_set_blob(nvs, USB_CDC_NVS_KEY, &g_line_coding, sizeof(g_line_coding));
    if (rc == ESP_OK) {
        rc = nvs_commit(nvs);
    }
    nvs_close(nvs);
    return rc;
}

/*============================================================================*/
esp_err_t usb_cdc_init(void)
{
    if (g_mutex != NULL) {
        return ESP_OK;
    }
    g_mutex = xSemaphoreCreateMutex();
    if (g_mutex == NULL) {
        return ESP_ERR_NO_MEM;
    }
    ensure_serial();
    load_line_coding();
    atomic_store(&g_tx_paused, false);
    atomic_store(&g_tx_pending, 0);
    ESP_LOGI(TAG, "VID=0x%04X PID=0x%04X serial=%s baud=%u",
             g_vid, g_pid, g_serial, (unsigned)g_line_coding.bit_rate);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_set_vid_pid(uint16_t vid, uint16_t pid)
{
    if (g_mutex == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    g_vid = vid;
    g_pid = pid;
    xSemaphoreGive(g_mutex);
    ESP_LOGI(TAG, "VID/PID updated 0x%04X:0x%04X", vid, pid);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_get_vid_pid(uint16_t *out_vid, uint16_t *out_pid)
{
    if (out_vid == NULL || out_pid == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (g_mutex == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    *out_vid = g_vid;
    *out_pid = g_pid;
    xSemaphoreGive(g_mutex);
    return ESP_OK;
}

/*============================================================================*/
uint32_t usb_cdc_get_vidpid(void)
{
    uint16_t vid, pid;
    if (usb_cdc_get_vid_pid(&vid, &pid) != ESP_OK) {
        return ((uint32_t)USB_CDC_DEFAULT_VID << 16) | USB_CDC_DEFAULT_PID;
    }
    return ((uint32_t)vid << 16) | (uint32_t)pid;
}

/*============================================================================*/
const char *usb_cdc_manufacturer_string(void)
{
    return "GhostBreach";
}

const char *usb_cdc_product_string(void)
{
    return "REAPER";
}

const char *usb_cdc_serial_string(void)
{
    if (g_mutex == NULL) {
        return "";
    }
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return "";
    }
    const char *s = g_serial;
    xSemaphoreGive(g_mutex);
    return s;
}

/*============================================================================*/
esp_err_t usb_cdc_set_line_coding(const usb_cdc_line_coding_t *coding)
{
    if (coding == NULL || g_mutex == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    memcpy(&g_line_coding, coding, sizeof(g_line_coding));
    xSemaphoreGive(g_mutex);
    save_line_coding();
    ESP_LOGI(TAG, "line coding saved: baud=%u data=%u parity=%u stop=%u",
             (unsigned)coding->bit_rate, coding->data_bits,
             coding->parity, coding->stop_bits);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_get_line_coding(usb_cdc_line_coding_t *out)
{
    if (out == NULL || g_mutex == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    memcpy(out, &g_line_coding, sizeof(g_line_coding));
    xSemaphoreGive(g_mutex);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_line_coding_to_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    usb_cdc_line_coding_t lc;
    esp_err_t rc = usb_cdc_get_line_coding(&lc);
    if (rc != ESP_OK) {
        return rc;
    }
    int n = snprintf(buf, bufsz,
        "{\"bit_rate\":%u,\"data_bits\":%u,\"parity\":%u,\"stop_bits\":%u}",
        (unsigned)lc.bit_rate, lc.data_bits, lc.parity, lc.stop_bits);
    if (n < 0 || (size_t)n >= bufsz) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

/*============================================================================*/
void usb_cdc_break_signal(void)
{
    if (g_mutex == NULL) {
        return;
    }
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return;
    }
    g_break_pending = true;
    xSemaphoreGive(g_mutex);
    ESP_LOGI(TAG, "break signaled (Ctrl-C equivalent)");
}

/*============================================================================*/
bool usb_cdc_break_signaled(void)
{
    if (g_mutex == NULL) {
        return false;
    }
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return false;
    }
    bool pending = g_break_pending;
    xSemaphoreGive(g_mutex);
    return pending;
}

/*============================================================================*/
void usb_cdc_break_clear(void)
{
    if (g_mutex == NULL) {
        return;
    }
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return;
    }
    g_break_pending = false;
    xSemaphoreGive(g_mutex);
}

/*============================================================================*/
esp_err_t usb_cdc_break_to_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    bool pending = usb_cdc_break_signaled();
    int n = snprintf(buf, bufsz, "{\"break_pending\":%s}", pending ? "true" : "false");
    if (n < 0 || (size_t)n >= bufsz) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

/*============================================================================*/
bool usb_cdc_write_available(size_t needed_bytes)
{
    if (atomic_load(&g_tx_paused)) {
        return false;
    }
    int32_t avail = tud_cdc_write_available();
    if (avail < 0) {
        atomic_store(&g_tx_paused, true);
        return false;
    }
    if ((size_t)avail < needed_bytes) {
        return false;
    }
    return true;
}

/*============================================================================*/
esp_err_t usb_cdc_write(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    while (len > 0) {
        if (usb_cdc_break_signaled()) {
            usb_cdc_break_clear();
            atomic_store(&g_tx_paused, true);
            return ESP_ERR_CANCEL;
        }

        if (!usb_cdc_write_available(len)) {
            if (atomic_load(&g_tx_paused)) {
                return ESP_ERR_NOT_FINISHED;
            }
            vTaskDelay(pdMS_TO_TICKS(1));
            continue;
        }

        uint32_t chunk = (len > 64) ? 64 : (uint32_t)len;
        uint32_t written = tud_cdc_write(buf, chunk);
        if (written == 0) {
            vTaskDelay(pdMS_TO_TICKS(1));
            continue;
        }
        buf += written;
        len -= written;
        atomic_store(&g_tx_pending, len);
    }
    atomic_store(&g_tx_pending, 0);
    return ESP_OK;
}

/*============================================================================*/
void usb_cdc_flow_resume(void)
{
    atomic_store(&g_tx_paused, false);
}

/*============================================================================*/
size_t usb_cdc_tx_pending(void)
{
    return atomic_load(&g_tx_pending);
}

/*============================================================================*/
void usb_cdc_set_dtr_rts(bool dtr, bool rts)
{
    /* ISR-safe atomic store; no mutex. */
    g_dtr_current = dtr;
    g_rts_current = rts;
}

/*============================================================================*/
esp_err_t usb_cdc_get_capabilities(usb_cdc_caps_t *out)
{
    if (out == NULL || g_mutex == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    memset(out, 0, sizeof(*out));
    out->connected     = tud_cdc_connected();
    out->dtr_active    = atomic_load(&g_dtr_current);
    out->rts_active    = atomic_load(&g_rts_current);
    out->vid           = g_vid;
    out->pid           = g_pid;
    memcpy(out->serial,          g_serial, sizeof(g_serial));
    memcpy(out->manufacturer,    "GhostBreach", sizeof("GhostBreach"));
    memcpy(out->product,         "REAPER", sizeof("REAPER"));
    out->tx_avail      = (uint32_t)tud_cdc_write_available();
    out->tx_pending    = (size_t)atomic_load(&g_tx_pending);

    xSemaphoreGive(g_mutex);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_caps_to_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    usb_cdc_caps_t caps;
    esp_err_t rc = usb_cdc_get_capabilities(&caps);
    if (rc != ESP_OK) {
        return rc;
    }

    int n = snprintf(buf, bufsz,
        "{\"connected\":%s,\"dtr\":%s,\"rts\":%s,"
        "\"vid\":\"0x%04X\",\"pid\":\"0x%04X\","
        "\"serial\":\"%s\",\"manufacturer\":\"%s\",\"product\":\"%s\","
        "\"tx_avail\":%u,\"tx_pending\":%zu}",
        caps.connected ? "true" : "false",
        caps.dtr_active ? "true" : "false",
        caps.rts_active ? "true" : "false",
        caps.vid, caps.pid,
        caps.serial, caps.manufacturer, caps.product,
        caps.tx_avail, caps.tx_pending);

    if (n < 0 || (size_t)n >= bufsz) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
