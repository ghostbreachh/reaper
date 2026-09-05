#include "cli_flipper.h"
#include "cli_transport.h"
#include "cli_module.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "esp_log.h"
#include "esp_err.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"

static const char *TAG = "flipper";

#define FLIPPER_UART       UART_NUM_1
#define FLIPPER_BAUD       115200
#define FLIPPER_RX_BUF     2048
#define FLIPPER_TX_BUF     1024
#define FLIPPER_RXD        GPIO_NUM_19
#define FLIPPER_TXD        GPIO_NUM_20

static bool g_connected;
static uint64_t g_last_rx_us;
static TaskHandle_t g_task;
static atomic_bool g_running;

static void flipper_task(void *arg)
{
    (void)arg;
    char line[256];
    while (atomic_load(&g_running)) {
        int n = cli_flipper_read_line(line, sizeof(line), pdMS_TO_TICKS(1000));
        if (n > 0) {
            g_last_rx_us = esp_timer_get_time();
            g_connected = true;
            /* Dispatch through CLI parser */
            char out[256];
            int argc = 0;
            char *argv[16];
            char *p = line;
            while (*p && argc < 16) {
                while (*p == " " || *p == "\t") p++;
                if (*p == "\0") break;
                argv[argc++] = p;
                while (*p && *p != " " && *p != "\t") p++;
                if (*p) *p++ = '\0';
            }
            cli_dispatch_command(argc, argv);
        } else if (g_connected && esp_timer_get_time() - g_last_rx_us > 5000000ULL) {
            g_connected = false;
        }
    }
    vTaskDelete(NULL);
}

esp_err_t cli_flipper_init(void)
{
    atomic_store(&g_running, true);
    g_connected = false;
    g_last_rx_us = 0;

    uart_config_t cfg = {
        .baud_rate  = FLIPPER_BAUD,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    esp_err_t rc = uart_param_config(FLIPPER_UART, &cfg);
    if (rc != ESP_OK) return rc;

    rc = uart_set_pin(FLIPPER_UART, FLIPPER_TXD, FLIPPER_RXD,
                      UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (rc != ESP_OK) return rc;

    rc = uart_driver_install(FLIPPER_UART, FLIPPER_RX_BUF, FLIPPER_TX_BUF,
                             0, NULL, 0);
    if (rc != ESP_OK && rc != ESP_ERR_INVALID_STATE) return rc;

    if (xTaskCreatePinnedToCore(flipper_task, "flipper", 3072, NULL, 4,
                                &g_task, 0) != pdPASS) {
        atomic_store(&g_running, false);
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "Flipper UART1 init @ %d baud (TXD=%d RXD=%d)",
             FLIPPER_BAUD, FLIPPER_TXD, FLIPPER_RXD);
    return ESP_OK;
}

esp_err_t cli_flipper_deinit(void)
{
    atomic_store(&g_running, false);
    if (g_task != NULL) {
        vTaskDelay(pdMS_TO_TICKS(500));
        g_task = NULL;
    }
    uart_driver_delete(FLIPPER_UART);
    g_connected = false;
    return ESP_OK;
}

bool cli_flipper_connected(void)
{
    return g_connected;
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
        if (c == 0x08 || c == 0x7F) {
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
    if (n > 0) cli_flipper_write(buf, (size_t)n);
    return n;
}

esp_err_t cli_flipper_send_event(const char *json)
{
    if (json == NULL) return ESP_ERR_INVALID_ARG;
    cli_flipper_write("{\"event\":", 10);
    cli_flipper_write(json, strlen(json));
    cli_flipper_write("}\r\n", 4);
    return ESP_OK;
}
