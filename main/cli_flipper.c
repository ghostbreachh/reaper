#include "cli_flipper.h"
#include "cli_module.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "driver/uart.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "flipper";

#define FLIPPER_UART       UART_NUM_1
#define FLIPPER_BAUD       115200
#define FLIPPER_RX_BUF     2048
#define FLIPPER_TX_BUF     1024
#define FLIPPER_RXD        GPIO_NUM_19
#define FLIPPER_TXD        GPIO_NUM_20

#define FLIPPER_TIMEOUT_US 5000000ULL /* 5 seconds */

static atomic_bool g_connected = false;
static atomic_uint_least64_t g_last_rx_us = 0;
static TaskHandle_t g_task = NULL;
static atomic_bool g_running = false;

/* =========================================================================
 *  Background Task
 * ========================================================================= */

static void flipper_task(void *arg)
{
    (void)arg;
    char line[256];
    
    while (atomic_load(&g_running)) {
        int n = cli_flipper_read_line(line, sizeof(line), 1000);
        if (n > 0) {
            atomic_store(&g_last_rx_us, esp_timer_get_time());
            atomic_store(&g_connected, true);
            
            /* Safe tokenization using ctype.h */
            int argc = 0;
            char *argv[16];
            char *p = line;
            
            while (*p && argc < 16) {
                while (isspace((unsigned char)*p)) p++;
                if (*p == '\0') break;
                argv[argc++] = p;
                while (*p && !isspace((unsigned char)*p)) p++;
                if (*p) *p++ = '\0';
            }
            
            if (argc > 0) {
                cli_dispatch_command(argc, argv);
            }
        } else {
            /* Check for connection timeout */
            if (atomic_load(&g_connected)) {
                uint64_t last_rx = atomic_load(&g_last_rx_us);
                if (esp_timer_get_time() - last_rx > FLIPPER_TIMEOUT_US) {
                    atomic_store(&g_connected, false);
                }
            }
        }
    }
    
    vTaskDelete(NULL);
}

/* =========================================================================
 *  Public API
 * ========================================================================= */

esp_err_t cli_flipper_init(void)
{
    if (atomic_load(&g_running)) return ESP_OK;

    atomic_store(&g_running, true);
    atomic_store(&g_connected, false);
    atomic_store(&g_last_rx_us, 0);

    uart_config_t cfg = {
        .baud_rate  = FLIPPER_BAUD,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    
    esp_err_t rc = uart_param_config(FLIPPER_UART, &cfg);
    if (rc != ESP_OK) goto fail;

    rc = uart_set_pin(FLIPPER_UART, FLIPPER_TXD, FLIPPER_RXD,
                      UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (rc != ESP_OK) goto fail;

    rc = uart_driver_install(FLIPPER_UART, FLIPPER_RX_BUF, FLIPPER_TX_BUF,
                             0, NULL, 0);
    if (rc != ESP_OK && rc != ESP_ERR_INVALID_STATE) goto fail;

    if (xTaskCreatePinnedToCore(flipper_task, "flipper", 3072, NULL, 4,
                                &g_task, 0) != pdPASS) {
        rc = ESP_ERR_NO_MEM;
        goto fail;
    }

    ESP_LOGI(TAG, "Flipper UART1 init @ %d baud (TXD=%d RXD=%d)",
             FLIPPER_BAUD, FLIPPER_TXD, FLIPPER_RXD);
    return ESP_OK;

fail:
    atomic_store(&g_running, false);
    return rc;
}

esp_err_t cli_flipper_deinit(void)
{
    if (!atomic_load(&g_running)) return ESP_OK;

    atomic_store(&g_running, false);
    
    if (g_task != NULL) {
        /* Wait for task to exit cleanly before deleting UART driver */
        vTaskDelay(pdMS_TO_TICKS(500));
        g_task = NULL;
    }
    
    uart_driver_delete(FLIPPER_UART);
    atomic_store(&g_connected, false);
    return ESP_OK;
}

bool cli_flipper_connected(void)
{
    return atomic_load(&g_connected);
}

int cli_flipper_read_line(char *buf, size_t cap, uint32_t timeout_ms)
{
    if (cap == 0 || buf == NULL) return -1;
    size_t i = 0;
    
    for (;;) {
        uint8_t c = 0;
        int n = uart_read_bytes(FLIPPER_UART, &c, 1, pdMS_TO_TICKS(timeout_ms));
        if (n != 1) {
            return (i > 0) ? (int)i : -1;
        }
        
        if (c == '\r' || c == '\n') {
            if (i == 0) continue;
            buf[i] = '\0';
            return (int)i;
        }
        
        if (c == 0x08 || c == 0x7F) { /* Backspace / DEL */
            if (i > 0) i--;
            continue;
        }
        
        if (i < cap - 1) {
            buf[i++] = (char)c;
        }
    }
}

int cli_flipper_write(const void *data, size_t len)
{
    if (data == NULL || len == 0) return 0;
    return uart_write_bytes(FLIPPER_UART, (const uint8_t *)data, len);
}

int cli_flipper_printf(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    
    if (n > 0) {
        if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1;
        cli_flipper_write(buf, (size_t)n);
    }
    return n;
}

esp_err_t cli_flipper_send_event(const char *json)
{
    if (json == NULL) return ESP_ERR_INVALID_ARG;
    
    /* FIXED: Use printf to avoid manual length calculation errors */
    cli_flipper_printf("{\"event\":%s}\r\n", json);
    
    return ESP_OK;
}
