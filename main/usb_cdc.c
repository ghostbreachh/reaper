/*
 * ============================================================================
 *  usb_cdc.c  —  TinyUSB CDC-ACM custom VID/PID management
 * ============================================================================
 *
 *  T2T Step 3.2 — Research & Brainstorming
 *
 *  Branch A — Dynamic TinyUSB descriptor rewrite
 *    Decision: REJECTED. TinyUSB device descriptors live in const flash and are
 *    consumed by the ROM driver; patching them at runtime is unsupported.
 *
 *  Branch B — Kconfig-only defaults
 *    Decision: REJECTED. Cannot encode sdkconfig changes in committed C source;
 *    the user would need to run menuconfig manually.
 *
 *  Branch C — Module-local fixed VID/PID with runtime override API
 *    Decision: ACCEPTED. Provides sane defaults in source (DEAD/BEEF) and
 *    exposes setters/getters so the CLI/JSON-RPC can change them on demand.
 *    Build-time override is still possible via:
 *      idf.py menuconfig -> Component config -> TinyUSB -> CDC VID/PID
 * ============================================================================
 */

#include <string.h>
#include <stdatomic.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"

#include "usb_cdc.h"

static const char *TAG = "usb_cdc";

#define USB_CDC_DEFAULT_VID  0xDEAD
#define USB_CDC_DEFAULT_PID  0xBEEF

static uint16_t       g_vid = USB_CDC_DEFAULT_VID;
static uint16_t       g_pid = USB_CDC_DEFAULT_PID;
static char           g_serial[32] = {0};
static SemaphoreHandle_t g_mutex = NULL;

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
    ESP_LOGI(TAG, "VID=0x%04X PID=0x%04X serial=%s",
             g_vid, g_pid, g_serial);
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
