#include "cli_transport.h"
#include "usb_cdc.h"
#include "cli_module.h"
#include "port_detect.h"
#include "jsonrpc.h"

#include "esp_log.h"
#include "driver/uart.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>

#if defined(CONFIG_TINYUSB_CDC_ENABLED) && __has_include("tusb.h")
#include "tusb.h"
#define REAPER_HAS_TUSB_CDC 1
#else
#define REAPER_HAS_TUSB_CDC 0
#endif

static const char *TAG = "cli";

static const cli_transport_t *g_active = NULL;
static port_transport_t g_current_transport = PORT_TRANSPORT_UART0;
static SemaphoreHandle_t g_transport_lock = NULL;

/* =========================================================================
 *  UART0 Transport (POSIX VFS)
 * ========================================================================= */

static esp_err_t uart0_init(void)
{
    /* 
     * CRITICAL FIX: Set STDIN to non-blocking so read() doesn't freeze the task.
     */
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (flags != -1) {
        fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    }
    
    ESP_LOGI(TAG, "UART0 transport ready (VFS/Console mode)");
    return ESP_OK;
}

static esp_err_t uart0_deinit(void) { return ESP_OK; }
static bool uart0_connected(void) { return true; }

static int uart0_read_line(char *buf, size_t cap, uint32_t timeout_ms)
{
    if (cap == 0) return -1;
    size_t i = 0;
    bool got_any = false;
    
    TickType_t start_tick = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    while (1) {
        uint8_t c = 0;
        int n = read(STDIN_FILENO, &c, 1);
        
        if (n == 1) {
            start_tick = xTaskGetTickCount(); 
            
            if (c == '\r' || c == '\n') {
                if (!got_any) continue;
                buf[i] = '\0';
                write(STDOUT_FILENO, "\r\n", 2);
                return (int)i;
            }

            got_any = true;

            if (c == 0x08 || c == 0x7F) { 
                if (i > 0) {
                    i--;
                    write(STDOUT_FILENO, "\b \b", 3);
                }
                continue;
            }

            if (c < 0x20) continue; 

            if (i < cap - 1) {
                buf[i++] = (char)c;
                write(STDOUT_FILENO, &c, 1); 
            }
        } else {
            /* read() returns -1 with EAGAIN when no data is available in O_NONBLOCK */
            if ((xTaskGetTickCount() - start_tick) >= timeout_ticks) {
                return (i > 0) ? (int)i : -1;
            }
            vTaskDelay(pdMS_TO_TICKS(10)); 
        }
    }
}

static int uart0_write(const void *data, size_t len)
{
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
    if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1;
    return uart0_write(buf, (size_t)n);
}

static const cli_transport_t g_uart0_transport = {
    .init = uart0_init, .deinit = uart0_deinit, .connected = uart0_connected,
    .read_line = uart0_read_line, .write = uart0_write, .printf = uart0_printf,
};

/* =========================================================================
 *  CDC-ACM Transport (TinyUSB)
 * ========================================================================= */

static esp_err_t cdc_init(void) { return ESP_OK; }
static esp_err_t cdc_deinit(void) { return ESP_OK; }

static bool cdc_connected(void)
{
#if REAPER_HAS_TUSB_CDC
    return tud_cdc_connected();
#else
    return false;
#endif
}

static int cdc_read_line(char *buf, size_t cap, uint32_t timeout_ms)
{
#if REAPER_HAS_TUSB_CDC
    if (cap == 0) return -1;
    size_t i = 0;
    
    TickType_t start_tick = xTaskGetTickCount();
    TickType_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);

    while (1) {
        if (tud_cdc_available()) {
            uint8_t c = 0;
            uint32_t n = tud_cdc_read(&c, 1);
            if (n == 1) {
                start_tick = xTaskGetTickCount(); 
                
                if (c == '\r' || c == '\n') {
                    buf[i] = '\0';
                    tud_cdc_write("\r\n", 2);
                    tud_cdc_write_flush();
                    return (int)i;
                }

                if (c == 0x08 || c == 0x7F) {
                    if (i > 0) {
                        i--;
                        tud_cdc_write("\b \b", 3);
                        tud_cdc_write_flush();
                    }
                    continue;
                }

                if (c < 0x20) continue;

                if (i < cap - 1) {
                    buf[i++] = (char)c;
                    tud_cdc_write(&c, 1); /* Echo */
                    tud_cdc_write_flush();
                }
            }
        } else {
            if ((xTaskGetTickCount() - start_tick) >= timeout_ticks) {
                return (i > 0) ? (int)i : -1;
            }
            vTaskDelay(pdMS_TO_TICKS(10)); 
        }
    }
#else
    return -1;
#endif
}

static int cdc_write(const void *data, size_t len)
{
    esp_err_t rc = usb_cdc_write((const uint8_t *)data, len);
    if (rc == ESP_OK) return (int)len;
    if (rc == ESP_ERR_CANCEL) usb_cdc_break_clear();
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
    if (n >= (int)sizeof(buf)) n = sizeof(buf) - 1;
    return cdc_write(buf, (size_t)n);
}

static const cli_transport_t g_cdc_transport = {
    .init = cdc_init, .deinit = cdc_deinit, .connected = cdc_connected,
    .read_line = cdc_read_line, .write = cdc_write, .printf = cdc_printf,
};

/* =========================================================================
 *  Public API & Command Loop
 * ========================================================================= */

const cli_transport_t *cli_transport_get(void) { return g_active; }

esp_err_t cli_transport_switch(port_transport_t new_transport)
{
    if (g_transport_lock == NULL) {
        g_transport_lock = xSemaphoreCreateMutex();
        if (!g_transport_lock) return ESP_ERR_NO_MEM;
    }

    xSemaphoreTake(g_transport_lock, portMAX_DELAY);
    
    if (g_active) {
        g_active->deinit();
        g_active = NULL;
    }

    const cli_transport_t *new_active = (new_transport == PORT_TRANSPORT_CDC) 
                                        ? &g_cdc_transport : &g_uart0_transport;
    
    esp_err_t ret = new_active->init();
    if (ret == ESP_OK) {
        g_active = new_active;
        g_current_transport = new_transport;
    }
    
    xSemaphoreGive(g_transport_lock);
    return ret;
}

/* Safe tokenizer to prevent memory corruption in cli_dispatch_command */
static int tokenize_line(char *line, char **argv, int max_args)
{
    int argc = 0;
    char *p = line;
    while (*p && argc < max_args) {
        while (isspace((unsigned char)*p)) p++;
        if (*p == '\0') break;
        argv[argc++] = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        if (*p) *p++ = '\0';
    }
    return argc;
}

static void cli_command_loop(void)
{
    char line[CLI_LINE_MAX];
    char *argv[CLI_MAX_ARGS];

    while (1) {
        if (usb_cdc_break_signaled()) {
            usb_cdc_break_clear();
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        
        xSemaphoreTake(g_transport_lock, portMAX_DELAY);
        const cli_transport_t *t = g_active;
        xSemaphoreGive(g_transport_lock);

        if (!t || !t->connected()) {
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }

        if (t == &g_uart0_transport) {
            t->printf("\033[36mtoolkit> \033[0m"); 
        }

        int rc = t->read_line(line, sizeof(line), 500);
        if (rc <= 0) continue;

        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        
        if (*p == '{') {
            jsonrpc_handle_message(p); 
        } else {
            int argc = tokenize_line(line, argv, CLI_MAX_ARGS);
            if (argc > 0) {
                cli_dispatch_command(argc, argv);
            }
        }
    }
}

static void cli_task(void *arg)
{
    (void)arg;
    cli_command_loop();
}

esp_err_t cli_start(void)
{
    if (g_transport_lock == NULL) {
        g_transport_lock = xSemaphoreCreateMutex();
        if (!g_transport_lock) return ESP_ERR_NO_MEM;
    }

    /* Use the global boot detection result */
    port_transport_t desired = g_boot_port.active; 

    esp_err_t ret = cli_transport_switch(desired);
    if (ret != ESP_OK) return ret;

    if (xTaskCreatePinnedToCore(cli_task, "cli_task", 8192, NULL, 3, NULL, 1) != pdPASS) {
        return ESP_FAIL;
    }

    return ESP_OK;
}
