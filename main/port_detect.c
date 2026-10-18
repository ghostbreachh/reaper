/*
 * ============================================================================
 *  port_detect.c  —  Boot-time USB transport detection for ESP32-S3
 * ============================================================================
 */

#include "port_detect.h"

#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_system.h"

#if __has_include("soc/usb_serial_jtag_reg.h")
#include "soc/usb_serial_jtag_reg.h"
#endif
#if __has_include("driver/usb_serial_jtag.h")
#include "driver/usb_serial_jtag.h"
#endif

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* Fallback color macros if not defined in common_types.h */
#ifndef GRY
#define GRY "\033[90m"
#define GRN "\033[32m"
#define YLW "\033[33m"
#define RED "\033[31m"
#define WHT "\033[37m"
#define R0  "\033[0m"
#endif

static const char *TAG = "port_detect";

/* Global boot-time detection result, populated once at startup. */
port_detect_result_t g_boot_port;

/* -------------------------------------------------------------------------
 *  Low-level: probe USB-Serial-JTAG controller enable state
 * ----------------------------------------------------------------------- */
static bool usb_serial_jtag_is_enabled(void)
{
    /* 
     * Primary check: Kconfig. If the firmware was compiled for JTAG console,
     * it is the intended transport.
     */
#if defined(CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG) || defined(CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG_ENABLED)
    return true;
#else
    /* Fallback: Direct register check */
    #ifdef USB_SERIAL_JTAG_CONF0_REG
        uint32_t conf = READ_PERI_REG(USB_SERIAL_JTAG_CONF0_REG);
        #ifdef USB_SERIAL_JTAG_USB_PAD_ENABLE_M
            return (conf & USB_SERIAL_JTAG_USB_PAD_ENABLE_M) != 0;
        #else
            return (conf & BIT(17)) != 0; /* USB_PAD_ENABLE is typically bit 17 */
        #endif
    #else
        return false;
    #endif
#endif
}

/* -------------------------------------------------------------------------
 *  Low-level: probe TinyUSB CDC-ACM enable state
 *
 *  NOTE: We DO NOT use tud_cdc_connected() here. That function checks if 
 *  the host has enumerated and opened the port, which takes hundreds of 
 *  milliseconds. At boot time, it will almost always return false.
 *  Instead, we check Kconfig to see if the firmware was BUILT for CDC.
 * ----------------------------------------------------------------------- */
static bool cdc_acm_is_enabled(void)
{
#if defined(CONFIG_TINYUSB_CDC_ENABLED) || defined(CONFIG_ESP_CONSOLE_USB_CDC)
    return true;
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
    bool cdc  = cdc_acm_is_enabled();

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
        /* 
         * ESP32-S3 hardware constraint: USB-Serial-JTAG and USB-OTG share 
         * the same PHY. They cannot be active simultaneously. If Kconfig 
         * somehow enabled both, JTAG usually wins at the hardware level.
         */
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
        printf("  │  " RED "!" R0 "  Both USB functions reported active in Kconfig. "
               "PHY conflict possible on silicon.\n");
        printf("  │      Only one can be used at a time. Defaulting to COM.\n");
    }

    if (res->active == PORT_TRANSPORT_UART0 && !res->usb_serial_jtag_present) {
        printf("  │\n");
        printf("  │  " YLW "fallback" R0 "  No transport detected; using UART0 as safe default.\n");
    }

    printf("  │\n");
}

port_transport_t port_detect_get_active(void)
{
    return g_boot_port.active;
}
