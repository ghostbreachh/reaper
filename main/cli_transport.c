/*
 * ============================================================================
 *  cli_transport.c  —  Unified CLI backend with dual-transport abstraction
 * ============================================================================
 */

#include "cli_transport.h"
#include "usb_cdc.h"
#include "cli_module.h"
#include "port_detect.h"
#include "jsonrpc.h" /* Required for JSON-RPC routing */

#include "esp_log.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>  /* For read/write on STDIN/STDOUT */
#include <ctype.h>

static const char *TAG = "cli";

/* -------------------------------------------------------------------------
 *  Shared command state
 * ----------------------------------------------------------------------- */
static const cli_transport_t *g_active = NULL;
static port_transport_t g_current_transport = PORT_TRANSPORT_UART0;

/* -------------------------------------------------------------------------
 *  UART0 transport implementation (Console/VFS safe)
 * ----------------------------------------------------------------------- */
#define UART0_BAUD       115200

static esp_err_t uart0_init(void)
{
    /* 
     * We do NOT call uart_driver_install or uart_param_config here.
     * UART0 is already initialized by ESP-IDF startup code for console output.
     * Using POSIX read/write on STDIN/STDOUT safely shares the UART with ESP_LOG.
     */
    ESP_LOGI(TAG, "UART0 transport ready (VFS/Console mode) @ %d baud", UART0_BAUD);
    return ESP_OK;
}

static esp_err_t uart0_deinit(void)
{
    /* Cannot safely delete the console UART driver while ESP_LOG is active */
    return ESP_OK;
}

static bool uart0_connected(void)
{
    return true; /* Console UART is always "connected" */
}

static int uart0_read_line(char *buf, size_t cap, uint32_t timeout_ms)
{
    if (cap == 0) return -1;
    size_t i = 0;
    bool got_any = false;
    
    TickType_t start_tick = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    while (1) {
        uint8_t c = 0;
        /* Use POSIX read instead of uart_read_bytes to avoid VFS conflicts */
        int n = read(STDIN_FILENO, &c, 1);
        
        if (n == 1) {
            start_tick = xTaskGetTickCount(); /* Reset timeout on activity */
            
            if (c == '\r' || c == '\n') {
                if (!got_any) continue;
                buf[i] = '\0';
                write(STDOUT_FILENO, "\r\n", 2);
                return (int)i;
            }

            got_any = true;

            if (c == 0x08 || c == 0x7F) { /* Backspace / DEL */
                if (i > 0) {
                    i--;
                    write(STDOUT_FILENO, "\b \b", 3);
                }
                continue;
            }

            if (c < 0x20) continue; /* Ignore other control chars */

            if (i < cap - 1) {
                buf[i++] = (char)c;
                write(STDOUT_FILENO, &c, 1); /* Echo */
            }
        } else {
            /* No data available, check timeout */
            if ((xTaskGetTickCount() - start_tick) >= timeout_ticks) {
                return (i > 0) ? (int)i : -1;
            }
            vTaskDelay(pdMS_TO_TICKS(10)); /* Yield to avoid busy-waiting */
        }
    }
}

static int uart0_write(const void *data, size_t len)
{
    /* Use POSIX write instead of uart_write_bytes */
    return (int)write(STDOUT_FILENO, data, len);
}

static int uart0_printf(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    
    if (n < 0) return -1;
    if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1; /* Safe truncation */
    
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
    
    TickType_t start_tick = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    while (1) {
        if (tud_cdc_available()) {
            uint8_t c = 0;
            /* tud_cdc_read does NOT take a timeout parameter */
            uint32_t n = tud_cdc_read(&c, 1);
            if (n == 1) {
                start_tick = xTaskGetTickCount(); /* Reset timeout on activity */
                
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
        } else {
            /* No data available, check timeout */
            if ((xTaskGetTickCount() - start_tick) >= timeout_ticks) {
                return (i > 0) ? (int)i : -1;
            }
            vTaskDelay(pdMS_TO_TICKS(10)); /* Yield to avoid busy-waiting */
        }
    }
}

static int cdc_write(const void *data, size_t len)
{
    esp_err_t rc = usb_cdc_write((const uint8_t *)data, len);
    if (rc == ESP_OK) {
        return (int)len;
    }
    if (rc == ESP_ERR_CANCEL) {
        usb_cdc_break_clear();
    }
    return -1;
}

static int cdc_printf(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    
    if (n < 0) return -1;
    if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1; /* Safe truncation */
    
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
        if (usb_cdc_break_signaled()) {
            usb_cdc_break_clear();
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        
        /* watchdog_task_refresh("cli_task"); // Assuming this exists */
        
        const cli_transport_t *t = cli_transport_get();
        if (!t || !t->connected()) {
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }

        if (t == &g_uart0_transport) {
            t->printf("\033[36mtoolkit> \033[0m"); /* Cyan prompt */
        }

        int rc = t->read_line(line, sizeof(line), 500);
        if (rc <= 0) continue;

        /* 
         * MULTIPLEXER: 
         * If the line starts with '{', assume it's a JSON-RPC request from the phone app.
         * Otherwise, treat it as a standard text CLI command.
         */
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        
        if (*p == '{') {
            /* Route to JSON-RPC dispatcher */
            /* TODO: Ensure jsonrpc_handle_message is implemented in jsonrpc.c */
            jsonrpc_handle_message(p); 
        } else {
            /* Route to text CLI dispatcher */
            /* Note: Passing 0 for argc is unusual. Ensure cli_module expects this. */
            cli_dispatch_command(0, &line);
        }
    }
}

/* -------------------------------------------------------------------------
 *  Boot entry — starts the command loop on core 1.
 * ----------------------------------------------------------------------- */
static void cli_task(void *arg)
{
    /* watchdog_task_refresh("cli_task"); */
    (void)arg;
    cli_command_loop();
}

esp_err_t cli_start(void)
{
    /* 
     * Determine active transport. 
     * Assuming port_detect_get_active() exists, or pass it from main.c 
     */
    port_transport_t desired = port_detect_get_active(); 
    /* Fallback if getter doesn't exist: 
       port_transport_t desired = PORT_TRANSPORT_UART0; 
    */

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
