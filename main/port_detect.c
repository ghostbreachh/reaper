/*
 * ============================================================================
 *  port_detect.c  —  Boot-time USB transport detection for ESP32-S3
 *
 *  Detects which USB function is active at boot:
 *    • USB-Serial-JTAG  → UART0 / COM port console
 *    • USB-OTG CDC-ACM  → phone control / JSON-RPC
 *    • Both / neither    → fallback to UART0
 *
 *  ESP32-S3 constraint: USB-Serial-JTAG and USB-OTG share one PHY.
 *  Only one can be active at a time on silicon. TinyUSB CDC must be
 *  disabled when USB-Serial-JTAG is in use, and vice-versa.
 *
 *  Detection strategy:
 *    1. Read USB-Serial-JTAG controller enable state
 *    2. Check TinyUSB CDC attach state if component is enabled
 *    3. If both appear present, prefer UART0 and report ambiguity
 *    4. If neither, fall back to UART0 and report WARNING
 * ============================================================================
 */

#include "port_detect.h"
#include "esp_log.h"
#include "esp_system.h"
#include "soc/usb_serial_jtag_reg.h"
#include "driver/usb_serial_jtag.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "port_detect";

/* Global boot-time detection result, populated once at startup. */
port_detect_result_t g_boot_port;

/* -------------------------------------------------------------------------
 *  Low-level: probe USB-Serial-JTAG controller enable state
 *
 *  USB_SERIAL_JTAG_CONF0 is mapped by soc/usb_serial_jtag_reg.h.
 *  Bit USB_SERIAL_JTAG_USB_PAD_ENABLE indicates the pad is active.
 * ----------------------------------------------------------------------- */
static bool usb_serial_jtag_is_enabled(void)
{
    uint32_t conf = READ_PERI_REG(USB_SERIAL_JTAG_CONF0_REG);
    return (conf & USB_SERIAL_JTAG_USB_PAD_ENABLE_M) != 0;
}

/* -------------------------------------------------------------------------
 *  Low-level: probe TinyUSB CDC-ACM attach state
 *
 *  Best-effort read: TinyUSB only exposes runtime state through its tud_* API
 *  when the component is enabled. When disabled, treat CDC as absent.
 * ----------------------------------------------------------------------- */
static bool cdc_acm_is_present(void)
{
#ifdef CONFIG_TINYUSB_CDC_ENABLED
    return tud_cdc_connected();
#else
    return false;
#endif
}

/* -------------------------------------------------------------------------
 *  Public API
 * ----------------------------------------------------------------------- */
esp_err_t boot_port_detect(port_detect_result_t *out_result)
{
    if (out_result == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(out_result, 0, sizeof(*out_result));

    bool jtag = usb_serial_jtag_is_enabled();
    bool cdc  = cdc_acm_is_present();

    out_result->usb_serial_jtag_present = jtag;
    out_result->cdc_acm_present         = cdc;
    out_result->both_active             = jtag && cdc;

    if (jtag && !cdc) {
        out_result->active = PORT_TRANSPORT_UART0;
        out_result->reason = PORT_REASON_JTAG_ONLY;
    } else if (cdc && !jtag) {
        out_result->active = PORT_TRANSPORT_CDC;
        out_result->reason = PORT_REASON_CDC_ONLY;
    } else if (jtag && cdc) {
        out_result->active = PORT_TRANSPORT_UART0;
        out_result->reason = PORT_REASON_BOTH;
    } else {
        out_result->active = PORT_TRANSPORT_UART0;
        out_result->reason = PORT_REASON_FALLBACK;
    }

    ESP_LOGI(TAG,
             "detect complete: jtag=%d cdc=%d active=%s reason=0x%02X",
             jtag, cdc,
             port_transport_name(out_result->active),
             out_result->reason);

    return ESP_OK;
}

const char *port_transport_name(port_transport_t t)
{
    switch (t) {
        case PORT_TRANSPORT_UART0: return "UART0 (USB-Serial-JTAG / COM)";
        case PORT_TRANSPORT_CDC:   return "USB-OTG CDC-ACM";
        case PORT_TRANSPORT_BOTH:  return "BOTH (ambiguous)";
        case PORT_TRANSPORT_UNKNOWN:
        default:                   return "UNKNOWN";
    }
}

void port_print_banner(const port_detect_result_t *res)
{
    if (res == NULL) {
        return;
    }

    printf("\n");
    printf("  ┌─ " GRY "USB Transport Detection" R0 "\n");
    printf("  │\n");

    if (res->usb_serial_jtag_present) {
        printf("  │  " GRN "✔" R0 "  USB-Serial-JTAG / COM port detected\n");
    } else {
        printf("  │  " YLW "⚠" R0 "  USB-Serial-JTAG / COM port: not detected\n");
    }

    if (res->cdc_acm_present) {
        printf("  │  " GRN "✔" R0 "  USB-OTG CDC-ACM detected (phone-ready)\n");
    } else {
        printf("  │  " YLW "⚠" R0 "  USB-OTG CDC-ACM: not detected\n");
    }

    printf("  │\n");
    printf("  │  Active transport : " WHT "%s" R0 "\n",
           port_transport_name(res->active));
    printf("  │  Reason code      : 0x%02X\n", res->reason);

    if (res->both_active) {
        printf("  │\n");
        printf("  │  " RED "!" R0 "  Both USB functions reported active. "
               "PHY conflict possible on silicon.\n");
        printf("  │      Only one can be used at a time. Defaulting to COM.\n");
    }

    if (res->active == PORT_TRANSPORT_UART0 && !res->usb_serial_jtag_present) {
        printf("  │\n");
        printf("  │  " YLW "fallback" R0 "  No transport detected; using UART0 as safe default.\n");
    }

    printf("  │\n");
}
