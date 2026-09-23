#include "led_indicator.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

#include "esp_log.h"
#include "esp_err.h"

#include "led_strip.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "led";

#define RGB_GPIO 48

static led_strip_handle_t g_led_strip = NULL;
static TaskHandle_t g_led_task = NULL;

static atomic_int g_current_state = ATOMIC_VAR_INIT(LED_STATE_IDLE);

/*
 * Pack RGB into one atomic value:
 *
 * bits 23..16 = R
 * bits 15..8  = G
 * bits 7..0   = B
 */
static atomic_uint_fast32_t g_custom_rgb = ATOMIC_VAR_INIT(0);
static atomic_bool g_custom_color_set = ATOMIC_VAR_INIT(false);

static SemaphoreHandle_t g_init_lock = NULL;
static bool g_init_done = false;

static const Color PALETTE[] = {
    {255, 30, 0},
    {0, 220, 60},
    {0, 220, 255},
    {180, 0, 255}
};

static const int PALETTE_COUNT = sizeof(PALETTE) / sizeof(PALETTE[0]);

static inline uint8_t lerp_u8(uint8_t start, uint8_t end, uint16_t t_256)
{
    return (uint8_t)(((uint32_t)start * (256u - t_256) +
                      (uint32_t)end * t_256) >> 8);
}

static inline uint32_t pack_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    return ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
}

static inline void unpack_rgb(uint32_t rgb, uint8_t *r, uint8_t *g, uint8_t *b)
{
    *r = (uint8_t)((rgb >> 16) & 0xFFu);
    *g = (uint8_t)((rgb >> 8) & 0xFFu);
    *b = (uint8_t)(rgb & 0xFFu);
}

static void led_apply_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    if (g_led_strip == NULL) {
        return;
    }

    led_strip_set_pixel(g_led_strip, 0, r, g, b);
    led_strip_refresh(g_led_strip);
}

static void led_apply_off(void)
{
    if (g_led_strip == NULL) {
        return;
    }

    led_strip_clear(g_led_strip);
}

static void led_task_loop(void *arg)
{
    (void)arg;

    int step = 0;
    int palette_idx = 0;
    bool scan_direction = true;
    uint16_t pulse_t = 0;

    while (1) {
        if (g_led_strip == NULL) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        led_state_t state = (led_state_t)atomic_load(&g_current_state);

        switch (state) {
            case LED_STATE_OFF:
                led_apply_off();
                vTaskDelay(pdMS_TO_TICKS(200));
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

                led_apply_rgb(r, g, b);

                pulse_t += 4;
                if (pulse_t >= 256) {
                    pulse_t = 0;
                    palette_idx = (palette_idx + 1) % PALETTE_COUNT;
                }

                vTaskDelay(pdMS_TO_TICKS(25));
                break;
            }

            case LED_STATE_SCANNING:
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

                led_apply_rgb(0, (uint8_t)step, (uint8_t)(255 - step / 2));
                vTaskDelay(pdMS_TO_TICKS(30));
                break;

            case LED_STATE_CONNECTED:
                led_apply_rgb(0, 255, 60);
                vTaskDelay(pdMS_TO_TICKS(200));
                break;

            case LED_STATE_ERROR:
                step = (step + 1) % 2;
                if (step) {
                    led_apply_rgb(255, 0, 0);
                } else {
                    led_apply_off();
                }
                vTaskDelay(pdMS_TO_TICKS(150));
                break;

            case LED_STATE_CUSTOM:
                if (atomic_load(&g_custom_color_set)) {
                    uint8_t r, g, b;
                    uint32_t rgb = atomic_load(&g_custom_rgb);
                    unpack_rgb(rgb, &r, &g, &b);
                    led_apply_rgb(r, g, b);
                }
                vTaskDelay(pdMS_TO_TICKS(100));
                break;

            default:
                atomic_store(&g_current_state, LED_STATE_ERROR);
                vTaskDelay(pdMS_TO_TICKS(100));
                break;
        }
    }
}

esp_err_t led_indicator_init(void)
{
    if (g_init_lock == NULL) {
        g_init_lock = xSemaphoreCreateMutex();
        if (g_init_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    if (xSemaphoreTake(g_init_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    if (g_init_done) {
        xSemaphoreGive(g_init_lock);
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
        ESP_LOGE(TAG, "Failed to create LED strip: %s", esp_err_to_name(err));
        g_led_strip = NULL;
        xSemaphoreGive(g_init_lock);
        return err;
    }

    led_strip_clear(g_led_strip);

    BaseType_t task_ok = xTaskCreatePinnedToCore(
        led_task_loop,
        "led_task",
        2048,
        NULL,
        1,
        &g_led_task,
        1
    );

    if (task_ok != pdPASS) {
        ESP_LOGE(TAG, "Failed to create LED task");
        led_strip_del(g_led_strip);
        g_led_strip = NULL;
        xSemaphoreGive(g_init_lock);
        return ESP_ERR_NO_MEM;
    }

    atomic_store(&g_current_state, LED_STATE_IDLE);
    atomic_store(&g_custom_color_set, false);
    atomic_store(&g_custom_rgb, 0);

    g_init_done = true;

    xSemaphoreGive(g_init_lock);

    ESP_LOGI(TAG, "LED Indicator Module initialized");
    return ESP_OK;
}

/* Backward-compatible wrapper. */
esp_err_t helper_init(void)
{
    return led_indicator_init();
}

void led_set_state(led_state_t state)
{
    atomic_store(&g_current_state, state);
}

void led_set_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    atomic_store(&g_custom_rgb, pack_rgb(r, g, b));
    atomic_store(&g_custom_color_set, true);
    atomic_store(&g_current_state, LED_STATE_CUSTOM);
}
