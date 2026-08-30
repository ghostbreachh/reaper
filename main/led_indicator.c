#include "led_indicator.h"
#include "led_strip.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdbool.h>
#include <stdatomic.h>

#define RGB_GPIO 48

static led_strip_handle_t g_led_strip = NULL;
static atomic_int g_current_state = ATOMIC_VAR_INIT(LED_STATE_IDLE);
static atomic_bool g_custom_color_set = ATOMIC_VAR_INIT(false);
static Color g_custom_color = {0, 0, 0};
static bool g_helper_init_done = false;

static const Color PALETTE[] = {
    {255, 30, 0},
    {0, 220, 60},
    {0, 220, 255},
    {180, 0, 255}
};

static const int PALETTE_COUNT = sizeof(PALETTE) / sizeof(PALETTE[0]);

static inline uint8_t lerp_u8(uint8_t start, uint8_t end, uint16_t t_256)
{
    return (uint8_t)(((uint32_t)start * (256 - t_256) +
                      (uint32_t)end * t_256) >> 8);
}

static void led_task_loop(void *arg)
{
    watchdog_task_refresh(TAG);
    int step = 0;
    int palette_idx = 0;
    bool scan_direction = true;
    uint16_t pulse_t = 0;

    while (1) {
        if (usb_cdc_break_signaled()) {
            usb_cdc_break_clear();
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
        watchdog_task_refresh(TAG);
        if (g_led_strip == NULL) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        led_state_t state = (led_state_t)atomic_load(&g_current_state);

        switch (state) {
        case LED_STATE_OFF:
            led_strip_clear(g_led_strip);
            break;

        case LED_STATE_IDLE: {
            Color c1 = PALETTE[palette_idx];
            Color c2 = PALETTE[(palette_idx + 1) % PALETTE_COUNT];

            uint8_t r = lerp_u8(c1.r, c2.r, pulse_t);
            uint8_t g = lerp_u8(c1.g, c2.g, pulse_t);
            uint8_t b = lerp_u8(c1.b, c2.b, pulse_t);

            uint32_t scale = (pulse_t <= 128) ? pulse_t : (256 - pulse_t);
            r = (uint8_t)(((uint32_t)r * (scale + 30)) / 158);
            g = (uint8_t)(((uint32_t)g * (scale + 30)) / 158);
            b = (uint8_t)(((uint32_t)b * (scale + 30)) / 158);

            led_strip_set_pixel(g_led_strip, 0, r, g, b);
            led_strip_refresh(g_led_strip);

            pulse_t += 4;
            if (pulse_t >= 256) {
                pulse_t = 0;
                palette_idx = (palette_idx + 1) % PALETTE_COUNT;
            }
            vTaskDelay(pdMS_TO_TICKS(25));
            break;
        }

        case LED_STATE_SCANNING: {
            if (scan_direction) {
                step += 15;
                if (step >= 255) {
                    step = 255;
                    scan_direction = false;
                }
            } else {
                step -= 15;
                if (step <= 10) {
                    step = 10;
                    scan_direction = true;
                }
            }

            led_strip_set_pixel(g_led_strip, 0, 0, (uint8_t)step, (uint8_t)(255 - step / 2));
            led_strip_refresh(g_led_strip);
            vTaskDelay(pdMS_TO_TICKS(30));
            break;
        }

        case LED_STATE_CONNECTED:
            led_strip_set_pixel(g_led_strip, 0, 0, 255, 60);
            led_strip_refresh(g_led_strip);
            vTaskDelay(pdMS_TO_TICKS(200));
            break;

        case LED_STATE_ERROR:
            step = (step + 1) % 2;
            if (step) {
                led_strip_set_pixel(g_led_strip, 0, 255, 0, 0);
            } else {
                led_strip_clear(g_led_strip);
            }
            led_strip_refresh(g_led_strip);
            vTaskDelay(pdMS_TO_TICKS(150));
            break;

        case LED_STATE_CUSTOM:
            if (atomic_load(&g_custom_color_set)) {
                led_strip_set_pixel(
                    g_led_strip,
                    0,
                    g_custom_color.r,
                    g_custom_color.g,
                    g_custom_color.b
                );
                led_strip_refresh(g_led_strip);
            }
            vTaskDelay(pdMS_TO_TICKS(100));
            break;
        }
    }
}

esp_err_t helper_init(void)
{
    if (g_helper_init_done) {
        return ESP_OK;
    }

    led_strip_config_t strip_config = {
        .strip_gpio_num = RGB_GPIO,
        .max_leds = 1,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
        .led_model = LED_MODEL_WS2812,
        .flags.invert_out = false,
    };

    led_strip_rmt_config_t rmt_config = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10 * 1000 * 1000,
        .flags.with_dma = false,
    };

    esp_err_t err = led_strip_new_rmt_device(&strip_config, &rmt_config, &g_led_strip);
    if (err != ESP_OK) {
        ESP_LOGE("led", "Failed to create LED strip: %s", esp_err_to_name(err));
        g_led_strip = NULL;
    } else {
        led_strip_clear(g_led_strip);
    }

    xTaskCreatePinnedToCore(led_task_loop, "led_task", 2048, NULL, 1, NULL, 1);

    g_helper_init_done = true;
    ESP_LOGI("led", "LED Indicator Module initialized");
    return ESP_OK;
}

void led_set_state(led_state_t state)
{
    atomic_store(&g_current_state, state);
}

void led_set_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    g_custom_color.r = r;
    g_custom_color.g = g;
    g_custom_color.b = b;
    atomic_store(&g_custom_color_set, true);
    atomic_store(&g_current_state, LED_STATE_CUSTOM);
}
