/*
 * ============================================================================
 *  cli_transport.c  —  Unified CLI backend with dual-transport abstraction
 *
 *  Responsibilities
 *  ────────────────
 *  1. Provide a transport-agnostic CLI core that reads commands from either
 *     UART0 (COM port) or CDC-ACM (phone OTG) without changing the parser.
 *  2. Implement two concrete transports:
 *       - UART0 transport: uses the ESP-IDF UART0 driver, echoes typed chars.
 *       - CDC-ACM transport: uses TinyUSB CDC, honours line coding.
 *  3. Allow runtime transport switching via cli_transport_switch().
 *  4. Expose the shared command dispatch entry point used by both transports.
 *
 *  Design
 *  ──────
 *  The transport interface is a vtable of 6 function pointers:
 *    init, deinit, connected, read_line, write, printf
 *
 *  The CLI core calls these through `cli_transport_get()` and never touches
 *  UART or CDC directly. Command parsing and dispatch live in one place.
 * ============================================================================
 */

#include "cli_transport.h"
#include "cli_module.h"
#include "port_detect.h"
#include "esp_log.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

static const char *TAG = "cli";

/* -------------------------------------------------------------------------
 *  Shared command state
 * ----------------------------------------------------------------------- */
static const cli_transport_t *g_active = NULL;
static port_transport_t g_current_transport = PORT_TRANSPORT_UART0;

/* -------------------------------------------------------------------------
 *  UART0 transport implementation
 * ----------------------------------------------------------------------- */
#define UART0_UART       UART_NUM_0
#define UART0_BAUD       115200
#define UART0_RX_BUF     1024
#define UART0_TXD        GPIO_NUM_43
#define UART0_RXD        GPIO_NUM_44

static esp_err_t uart0_init(void)
{
    esp_err_t ret = uart_driver_install(UART0_UART, UART0_RX_BUF, 0, 0, NULL, 0);
    if (ret == ESP_ERR_INVALID_STATE) {
        ESP_LOGI(TAG, "UART0 driver already installed (console VFS)");
        ret = ESP_OK;
    }
    if (ret != ESP_OK) return ret;

    uart_config_t cfg = {
        .baud_rate  = UART0_BAUD,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    ret = uart_param_config(UART0_UART, &cfg);
    if (ret != ESP_OK) ESP_LOGW(TAG, "uart_param_config: %s", esp_err_to_name(ret));

    ret = uart_set_pin(UART0_UART, UART0_TXD, UART0_RXD,
                       UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (ret != ESP_OK) ESP_LOGW(TAG, "uart_set_pin: %s", esp_err_to_name(ret));

    ESP_LOGI(TAG, "UART0 transport ready @ %d baud (TXD=%d RXD=%d)",
             UART0_BAUD, UART0_TXD, UART0_RXD);
    return ESP_OK;
}

static esp_err_t uart0_deinit(void)
{
    uart_driver_delete(UART0_UART);
    return ESP_OK;
}

static bool uart0_connected(void)
{
    return true;
}

static int uart0_read_line(char *buf, size_t cap, uint32_t timeout_ms)
{
    if (cap == 0) return -1;
    size_t i = 0;
    bool got_any = false;

    for (;;) {
        uint8_t c = 0;
        int n = uart_read_bytes(UART0_UART, &c, 1, pdMS_TO_TICKS(timeout_ms));
        if (n != 1) {
            return (i > 0) ? (int)i : -1;
        }

        if (c == '\r' || c == '\n') {
            if (!got_any) continue;
            buf[i] = '\0';
            uart_write_bytes(UART0_UART, (const uint8_t *)"\r\n", 2);
            return (int)i;
        }

        got_any = true;

        if (c == 0x08 || c == 0x7F) {
            if (i > 0) {
                i--;
                uart_write_bytes(UART0_UART, (const uint8_t *)"\b \b", 3);
            }
            continue;
        }

        if (c < 0x20) continue;

        if (i < cap - 1) {
            buf[i++] = (char)c;
            uart_write_bytes(UART0_UART, &c, 1);
        }
    }
}

static int uart0_write(const void *data, size_t len)
{
    return uart_write_bytes(UART0_UART, (const uint8_t *)data, (int)len);
}

static int uart0_printf(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > (int)sizeof(buf)) n = sizeof(buf);
    return uart0_write(buf, (size_t)n);
}

static const cli_transport_t g_uart0_transport = {
    .init       = uart0_init,
    .deinit     = uart0_deinit,
    .connected  = uart0_connected,
    .read_line  = uart0_read_line,
    .write      = uart0_write,
    .printf     = uart0_printf,
};

/* -------------------------------------------------------------------------
 *  CDC-ACM transport implementation
 * ----------------------------------------------------------------------- */
static esp_err_t cdc_init(void)
{
    ESP_LOGI(TAG, "CDC-ACM transport ready");
    return ESP_OK;
}

static esp_err_t cdc_deinit(void)
{
    return ESP_OK;
}

static bool cdc_connected(void)
{
#ifdef CONFIG_TINYUSB_CDC_ENABLED
    return tud_cdc_connected();
#else
    return false;
#endif
}

static int cdc_read_line(char *buf, size_t cap, uint32_t timeout_ms)
{
    if (cap == 0) return -1;
    size_t i = 0;

    for (;;) {
        uint8_t c = 0;
        int32_t n = tud_cdc_read(&c, 1, pdMS_TO_TICKS(timeout_ms));
        if (n < 1) {
            return (i > 0) ? (int)i : -1;
        }

        if (c == '\r' || c == '\n') {
            buf[i] = '\0';
            return (int)i;
        }

        if (c == 0x08 || c == 0x7F) {
            if (i > 0) i--;
            continue;
        }

        if (c < 0x20) continue;

        if (i < cap - 1) {
            buf[i++] = (char)c;
        }
    }
}

static int cdc_write(const void *data, size_t len)
{
    tud_cdc_write(data, len);
    tud_cdc_write_flush();
    return (int)len;
}

static int cdc_printf(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > (int)sizeof(buf)) n = sizeof(buf);
    return cdc_write(buf, (size_t)n);
}

static const cli_transport_t g_cdc_transport = {
    .init       = cdc_init,
    .deinit     = cdc_deinit,
    .connected  = cdc_connected,
    .read_line  = cdc_read_line,
    .write      = cdc_write,
    .printf     = cdc_printf,
};

/* -------------------------------------------------------------------------
 *  Public API
 * ----------------------------------------------------------------------- */
const cli_transport_t *cli_transport_get(void)
{
    return g_active;
}

esp_err_t cli_transport_switch(port_transport_t new_transport)
{
    if (g_active) {
        g_active->deinit();
        g_active = NULL;
    }

    switch (new_transport) {
        case PORT_TRANSPORT_CDC:
            g_active = &g_cdc_transport;
            break;
        case PORT_TRANSPORT_UART0:
        default:
            g_active = &g_uart0_transport;
            break;
    }

    g_current_transport = new_transport;
    esp_err_t ret = g_active->init();
    if (ret != ESP_OK) {
        g_active = NULL;
        return ret;
    }

    ESP_LOGI(TAG, "switched transport to: %s",
             (new_transport == PORT_TRANSPORT_CDC) ? "CDC-ACM" : "UART0");
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Shared command loop — reads from the active transport and dispatches.
 * ----------------------------------------------------------------------- */
static void cli_command_loop(void)
{
    char line[CLI_LINE_MAX];

    while (1) {
        watchdog_task_refresh("cli_task");
        const cli_transport_t *t = cli_transport_get();
        if (!t || !t->connected()) {
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }

        if (t == &g_uart0_transport) {
            t->printf(CLR_CYN "toolkit> " CLR_RST);
        }

        int rc = t->read_line(line, sizeof(line), 500);
        if (rc < 0) continue;
        if (rc == 0) continue;

        cli_dispatch_command(0, &line);
    }
}

/* -------------------------------------------------------------------------
 *  Boot entry — starts the command loop on core 1.
 * ----------------------------------------------------------------------- */
static void cli_task(void *arg)
{
    watchdog_task_refresh("cli_task");
    (void)arg;
    cli_command_loop();
}

esp_err_t cli_start(void)
{
    /* Initialise ONLY the transport selected by boot_port_detect. */
    port_transport_t desired = (g_boot_port.active == PORT_TRANSPORT_CDC)
                                    ? PORT_TRANSPORT_CDC
                                    : PORT_TRANSPORT_UART0;

    esp_err_t ret = cli_transport_switch(desired);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "transport init failed: %s", esp_err_to_name(ret));
        return ret;
    }

    if (xTaskCreatePinnedToCore(cli_task, "cli_task", 8192, NULL, 3, NULL, 1) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create CLI task");
        return ESP_FAIL;
    }

    return ESP_OK;
}
