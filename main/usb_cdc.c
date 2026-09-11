/*
 * ============================================================================
 *  usb_cdc.c  —  TinyUSB CDC-ACM Transport Layer
 * ============================================================================
 */

#include <string.h>
#include <stdio.h>
#include <stdatomic.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"

#include "tusb.h"  /* Required for tud_cdc_* APIs */

#include "usb_cdc.h"

static const char *TAG = "usb_cdc";

#define USB_CDC_DEFAULT_VID  0xDEAD
#define USB_CDC_DEFAULT_PID  0xBEEF
#define USB_CDC_NVS_NS       "usb_cdc"
#define USB_CDC_NVS_KEY      "line_coding"
#define USB_CDC_WRITE_TIMEOUT_MS 1000 /* Max ms to wait for host to read */

static uint16_t             g_vid = USB_CDC_DEFAULT_VID;
static uint16_t             g_pid = USB_CDC_DEFAULT_PID;
static char                 g_serial[32] = {0};
static usb_cdc_line_coding_t g_line_coding = {
    .bit_rate   = 115200,
    .data_bits  = 8,
    .parity     = 0,
    .stop_bits  = 1,
};

static SemaphoreHandle_t    g_mutex = NULL;       /* Protects config/state */
static SemaphoreHandle_t    g_write_mutex = NULL; /* Serializes USB TX */

static _Atomic bool         g_dtr_current = false;
static _Atomic bool         g_rts_current = false;
static _Atomic bool         g_break_pending = false;

/*============================================================================*/
static void ensure_serial(void)
{
    if (g_serial[0] != '\0') {
        return;
    }
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_BASE);
    /* Use full 6-byte MAC for better uniqueness */
    snprintf(g_serial, sizeof(g_serial),
             "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*============================================================================*/
static esp_err_t load_line_coding(void)
{
    nvs_handle_t nvs;
    esp_err_t rc = nvs_open(USB_CDC_NVS_NS, NVS_READONLY, &nvs);
    if (rc == ESP_OK) {
        size_t sz = sizeof(g_line_coding);
        rc = nvs_get_blob(nvs, USB_CDC_NVS_KEY, &g_line_coding, &sz);
        nvs_close(nvs);
        if (rc == ESP_OK) {
            return ESP_OK;
        }
    }
    /* If not found or error, keep defaults. No need to save immediately. */
    return ESP_OK;
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
        return ESP_ERR_INVALID_STATE;
    }
    
    g_mutex = xSemaphoreCreateMutex();
    g_write_mutex = xSemaphoreCreateMutex();
    
    if (g_mutex == NULL || g_write_mutex == NULL) {
        return ESP_ERR_NO_MEM;
    }
    
    ensure_serial();
    load_line_coding();
    
    ESP_LOGI(TAG, "VID=0x%04X PID=0x%04X serial=%s baud=%u",
             g_vid, g_pid, g_serial, (unsigned)g_line_coding.bit_rate);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_set_vid_pid(uint16_t vid, uint16_t pid)
{
    if (g_mutex == NULL) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    g_vid = vid;
    g_pid = pid;
    xSemaphoreGive(g_mutex);
    
    ESP_LOGI(TAG, "VID/PID updated 0x%04X:0x%04X", vid, pid);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_get_vid_pid(uint16_t *out_vid, uint16_t *out_pid)
{
    if (out_vid == NULL || out_pid == NULL) return ESP_ERR_INVALID_ARG;
    if (g_mutex == NULL) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
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
const char *usb_cdc_manufacturer_string(void) { return "GhostBreach"; }
const char *usb_cdc_product_string(void)      { return "REAPER"; }

const char *usb_cdc_serial_string(void)
{
    if (g_mutex == NULL) return "";
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return "";
    const char *s = g_serial;
    xSemaphoreGive(g_mutex);
    return s;
}

/*============================================================================*/
esp_err_t usb_cdc_set_line_coding(const usb_cdc_line_coding_t *coding)
{
    if (coding == NULL || g_mutex == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    memcpy(&g_line_coding, coding, sizeof(g_line_coding));
    xSemaphoreGive(g_mutex);
    
    save_line_coding();
    ESP_LOGI(TAG, "line coding saved: baud=%u", (unsigned)coding->bit_rate);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_get_line_coding(usb_cdc_line_coding_t *out)
{
    if (out == NULL || g_mutex == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    memcpy(out, &g_line_coding, sizeof(g_line_coding));
    xSemaphoreGive(g_mutex);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_line_coding_to_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;
    
    usb_cdc_line_coding_t lc;
    esp_err_t rc = usb_cdc_get_line_coding(&lc);
    if (rc != ESP_OK) return rc;
    
    int n = snprintf(buf, bufsz,
        "{\"bit_rate\":%u,\"data_bits\":%u,\"parity\":%u,\"stop_bits\":%u}",
        (unsigned)lc.bit_rate, lc.data_bits, lc.parity, lc.stop_bits);
        
    if (n < 0 || (size_t)n >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

/*============================================================================*/
void usb_cdc_break_signal(void)
{
    atomic_store(&g_break_pending, true);
    ESP_LOGI(TAG, "break signaled (Ctrl-C equivalent)");
}

bool usb_cdc_break_signaled(void)
{
    return atomic_load(&g_break_pending);
}

void usb_cdc_break_clear(void)
{
    atomic_store(&g_break_pending, false);
}

esp_err_t usb_cdc_break_to_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;
    bool pending = usb_cdc_break_signaled();
    int n = snprintf(buf, bufsz, "{\"break_pending\":%s}", pending ? "true" : "false");
    if (n < 0 || (size_t)n >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

/*============================================================================*/
/*  RX API (Added for completeness)                                           */
/*============================================================================*/
uint32_t usb_cdc_read_available(void)
{
    return tud_cdc_available();
}

uint32_t usb_cdc_read(uint8_t *buf, uint32_t len)
{
    return tud_cdc_read(buf, len);
}

/*============================================================================*/
/*  TX API                                                                    */
/*============================================================================*/
bool usb_cdc_write_available(size_t needed_bytes)
{
    if (!tud_cdc_connected() || !atomic_load(&g_dtr_current)) {
        return false;
    }
    uint32_t avail = tud_cdc_write_available();
    return (avail >= needed_bytes);
}

esp_err_t usb_cdc_write(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) return ESP_ERR_INVALID_ARG;
    if (g_write_mutex == NULL) return ESP_ERR_INVALID_STATE;

    /* Serialize writes to prevent JSON message interleaving */
    if (xSemaphoreTake(g_write_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    esp_err_t final_err = ESP_OK;
    TickType_t start_tick = xTaskGetTickCount();
    
    while (len > 0) {
        if (atomic_load(&g_break_pending)) {
            atomic_store(&g_break_pending, false);
            final_err = ESP_ERR_CANCEL;
            break;
        }

        /* If host isn't listening, don't block forever */
        if (!tud_cdc_connected() || !atomic_load(&g_dtr_current)) {
            final_err = ESP_ERR_INVALID_STATE;
            break;
        }

        uint32_t avail = tud_cdc_write_available();
        if (avail == 0) {
            if ((xTaskGetTickCount() - start_tick) > pdMS_TO_TICKS(USB_CDC_WRITE_TIMEOUT_MS)) {
                final_err = ESP_ERR_TIMEOUT;
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(1));
            continue;
        }

        uint32_t chunk = (len > avail) ? avail : (uint32_t)len;
        if (chunk > 64) chunk = 64; /* Respect FS USB packet size */

        uint32_t written = tud_cdc_write(buf, chunk);
        if (written == 0) {
            vTaskDelay(pdMS_TO_TICKS(1));
            continue;
        }
        
        buf += written;
        len -= written;
    }

    /* CRITICAL: Flush the TinyUSB buffer to actually send data over USB */
    if (final_err == ESP_OK && tud_cdc_write_available() < CFG_TUD_CDC_TX_BUFSIZE) {
        tud_cdc_write_flush();
    }

    xSemaphoreGive(g_write_mutex);
    return final_err;
}

void usb_cdc_flow_resume(void)
{
    /* Handled automatically by checking DTR/Connected in write loop */
}

size_t usb_cdc_tx_pending(void)
{
    /* Hard to track accurately without hooking TinyUSB TX complete callbacks */
    return 0; 
}

/*============================================================================*/
void usb_cdc_set_dtr_rts(bool dtr, bool rts)
{
    atomic_store(&g_dtr_current, dtr);
    atomic_store(&g_rts_current, rts);
}

/*============================================================================*/
esp_err_t usb_cdc_get_capabilities(usb_cdc_caps_t *out)
{
    if (out == NULL || g_mutex == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;

    memset(out, 0, sizeof(*out));
    out->connected     = tud_cdc_connected();
    out->dtr_active    = atomic_load(&g_dtr_current);
    out->rts_active    = atomic_load(&g_rts_current);
    out->vid           = g_vid;
    out->pid           = g_pid;
    
    strncpy(out->serial, g_serial, sizeof(out->serial) - 1);
    strncpy(out->manufacturer, "GhostBreach", sizeof(out->manufacturer) - 1);
    strncpy(out->product, "REAPER", sizeof(out->product) - 1);
    
    out->tx_avail      = tud_cdc_write_available();
    out->tx_pending    = 0;

    xSemaphoreGive(g_mutex);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t usb_cdc_caps_to_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;

    usb_cdc_caps_t caps;
    esp_err_t rc = usb_cdc_get_capabilities(&caps);
    if (rc != ESP_OK) return rc;

    int n = snprintf(buf, bufsz,
        "{\"connected\":%s,\"dtr\":%s,\"rts\":%s,"
        "\"vid\":\"0x%04X\",\"pid\":\"0x%04X\","
        "\"serial\":\"%s\",\"manufacturer\":\"%s\",\"product\":\"%s\","
        "\"tx_avail\":%u}",
        caps.connected ? "true" : "false",
        caps.dtr_active ? "true" : "false",
        caps.rts_active ? "true" : "false",
        caps.vid, caps.pid,
        caps.serial, caps.manufacturer, caps.product,
        caps.tx_avail);

    if (n < 0 || (size_t)n >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}
