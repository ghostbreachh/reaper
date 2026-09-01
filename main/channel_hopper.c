/*
 * ============================================================================
 *  channel_hopper.c  —  Smart WiFi channel hopper with per-channel stats
 * ============================================================================
 *
 *  Replaces the fixed-rate inline channel_hopper_task in wifi_sniffer.c
 *  with a configurable, statistics-collecting module.
 *
 *  Branch A — Single ch_hop_stats_t[] per channel
 *    Decision: ACCEPTED. Fixed-size 13-element array; no dynamic allocation.
 *
 *  Branch B — Hash-map keyed by channel
 *    Decision: REJECTED. Overkill for 13 fixed channels; more code, worse
 *    cache locality, no benefit over direct array[14] indexing.
 *
 *  Branch C — Linked-list of observed channels
 *    Decision: REJECTED. Unbounded growth, fragmentation, and needless
 *    indirection for a bounded 13-channel domain.
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "esp_err.h"
#include "channel_hopper.h"
#include "wifi_sniffer.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <stdatomic.h>

static const char *TAG = "ch_hopper";

static atomic_bool g_hop_active        = ATOMIC_VAR_INIT(false);
static ch_hop_config_t g_hop_cfg       = {0};
static ch_hop_stats_t g_hop_stats[14]  = {0};  /* index 1..13 */
static SemaphoreHandle_t g_hop_mutex   = NULL;
static TaskHandle_t g_hop_task         = NULL;
static uint8_t g_current_channel       = 0;
static uint64_t g_channel_enter_us     = 0;

/* Clamp helper */
static uint16_t clamp_u16(uint16_t v, uint16_t lo, uint16_t hi)
{
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

esp_err_t channel_hopper_init(void)
{
    if (g_hop_mutex != NULL) return ESP_OK;

    g_hop_mutex = xSemaphoreCreateMutex();
    if (g_hop_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create hopper mutex");
        return ESP_ERR_NO_MEM;
    }

    memset(g_hop_stats, 0, sizeof(g_hop_stats));
    g_current_channel = 0;
    g_channel_enter_us = 0;
    g_hop_cfg.mode = CH_HOP_MODE_SEQUENTIAL;
    g_hop_cfg.dwell_ms = 100;
    g_hop_cfg.channel_mask = 0xFF;

    ESP_LOGI(TAG, "Channel hopper initialized");
    return ESP_OK;
}

static uint8_t next_channel(uint8_t cur, uint8_t mask)
{
    if (mask == 0xFF) {
        /* Standard 1..13 sequential */
        return (cur == 0 || cur > 13) ? 1 : (cur % 13) + 1;
    }
    /* Mask-aware next */
    for (uint8_t step = 1; step <= 13; step++) {
        uint8_t ch = ((cur + step - 1) % 13) + 1;
        if (mask & (1u << (ch - 1))) return ch;
    }
    return 1;
}

static uint8_t random_channel(uint8_t mask)
{
    uint8_t candidates[13];
    uint8_t n = 0;
    for (uint8_t ch = 1; ch <= 13; ch++) {
        if (mask & (1u << (ch - 1))) candidates[n++] = ch;
    }
    if (n == 0) return 1;
    return candidates[esp_random() % n];
}

static void channel_hopper_task(void *arg)
{
    (void)arg;
    watchdog_task_refresh("ch_hopper");

    uint16_t dwell_ms = g_hop_cfg.dwell_ms ? g_hop_cfg.dwell_ms : 100;
    uint32_t dwell_us = g_hop_cfg.dwell_us ? g_hop_cfg.dwell_us : 0;
    uint8_t mask = g_hop_cfg.channel_mask ? g_hop_cfg.channel_mask : 0xFF;
    uint8_t current = next_channel(0, mask);

    while (atomic_load(&g_hop_active)) {
        if (usb_cdc_break_signaled()) {
            usb_cdc_break_clear();
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        esp_err_t ret = esp_wifi_set_channel(current, WIFI_SECOND_CHAN_NONE);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "set_channel(%u) failed: %s", current, esp_err_to_name(ret));
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        xSemaphoreTake(g_hop_mutex, portMAX_DELAY);
        g_current_channel = current;
        g_channel_enter_us = esp_timer_get_time();
        xSemaphoreGive(g_hop_mutex);

        /* Use microsecond dwell if configured, otherwise millisecond */
        if (dwell_us > 0) {
            uint64_t start_us = esp_timer_get_time();
            while (atomic_load(&g_hop_active)) {
                uint64_t elapsed = esp_timer_get_time() - start_us;
                if (elapsed >= dwell_us) break;
                /* Yield briefly to avoid watchdog starvation */
                vTaskDelay(pdMS_TO_TICKS(1));
            }
        } else {
            vTaskDelay(pdMS_TO_TICKS(dwell_ms));
        }

        if (!atomic_load(&g_hop_active)) break;

        if (g_hop_cfg.mode == CH_HOP_MODE_RANDOM) {
            current = random_channel(mask);
        } else if (g_hop_cfg.mode == CH_HOP_MODE_RSSI_OPT) {
            /* Pick channel with best average RSSI among top candidates */
            uint8_t best = current;
            int32_t best_rssi = INT32_MAX;
            for (uint8_t ch = 1; ch <= 13; ch++) {
                if (!(mask & (1u << (ch - 1)))) continue;
                xSemaphoreTake(g_hop_mutex, portMAX_DELAY);
                ch_hop_stats_t *s = &g_hop_stats[ch];
                int32_t avg = s->rssi_samples ? (s->rssi_sum / (int32_t)s->rssi_samples) : INT32_MAX;
                xSemaphoreGive(g_hop_mutex);
                if (avg < best_rssi) { best_rssi = avg; best = ch; }
            }
            current = best;
        } else {
            current = next_channel(current, mask);
        }
    }

    vTaskDelete(NULL);
}

esp_err_t channel_hopper_start(const ch_hop_config_t *cfg)
{
    if (cfg == NULL) return ESP_ERR_INVALID_ARG;
    if (atomic_load(&g_hop_active)) return ESP_ERR_INVALID_STATE;

    if (g_hop_mutex == NULL) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(g_hop_mutex, portMAX_DELAY);
    g_hop_cfg = *cfg;
    memset(g_hop_stats, 0, sizeof(g_hop_stats));
    g_current_channel = 0;
    xSemaphoreGive(g_hop_mutex);

    atomic_store(&g_hop_active, true);

    BaseType_t rc = xTaskCreatePinnedToCore(channel_hopper_task,
                                             "ch_hopper",
                                             3072,
                                             NULL,
                                             5,
                                             &g_hop_task,
                                             0);
    if (rc != pdPASS) {
        atomic_store(&g_hop_active, false);
        g_hop_task = NULL;
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Channel hopper started: mode=%u dwell=%u ms mask=0x%02X",
             (unsigned)cfg->mode,
             (unsigned)cfg->dwell_ms,
             (unsigned)cfg->channel_mask);
    return ESP_OK;
}

esp_err_t channel_hopper_set_dwell_us(uint32_t us)
{
    if (us > 0 && us < 1000) {
        /* Sub-millisecond dwell requires esp_timer path */
        g_hop_cfg.dwell_us = us;
        g_hop_cfg.dwell_ms = 0;
    } else {
        /* Millisecond or default */
        g_hop_cfg.dwell_us = 0;
        if (us >= 1000) {
            g_hop_cfg.dwell_ms = (uint16_t)(us / 1000);
        }
    }
    ESP_LOGI(TAG, "dwell_us set to %u", (unsigned)us);
    return ESP_OK;
}

uint32_t channel_hopper_get_dwell_us(void)
{
    return g_hop_cfg.dwell_us ? g_hop_cfg.dwell_us : (uint32_t)g_hop_cfg.dwell_ms * 1000;
}

esp_err_t channel_hopper_stop(void)
{
    if (!atomic_load(&g_hop_active)) return ESP_OK;

    atomic_store(&g_hop_active, false);
    if (g_hop_task != NULL) {
        vTaskDelay(pdMS_TO_TICKS(50));
        g_hop_task = NULL;
    }

    ESP_LOGI(TAG, "Channel hopper stopped on channel %u", (unsigned)g_current_channel);
    return ESP_OK;
}

bool channel_hopper_is_active(void)
{
    return atomic_load(&g_hop_active);
}

/*
 * Public API consumed by wifi_sniffer/radio subsystems. Call after parsing
 * each frame on the reported channel to update live per-channel counts.
 */
esp_err_t channel_hopper_record_packet(uint8_t channel,
                                       uint32_t pkt_count,
                                       uint32_t mgmt_count,
                                       uint32_t beacon_count,
                                       uint32_t data_count,
                                       int8_t rssi)
{
    if (channel == 0 || channel > 13) return ESP_ERR_INVALID_ARG;
    if (g_hop_mutex == NULL) return ESP_ERR_INVALID_STATE;
    if (!atomic_load(&g_hop_active)) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(g_hop_mutex, portMAX_DELAY);
    ch_hop_stats_t *s = &g_hop_stats[channel];
    s->pkt_count += pkt_count;
    s->mgmt_count += mgmt_count;
    s->beacon_count += beacon_count;
    s->data_count += data_count;
    if (rssi != 0 || pkt_count != 0) {
        s->rssi_sum += (int32_t)rssi;
        s->rssi_samples++;
    }
    xSemaphoreGive(g_hop_mutex);

    return ESP_OK;
}

esp_err_t channel_hopper_get_stats(uint8_t channel, ch_hop_stats_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    if (channel == 0 || channel > 13) return ESP_ERR_INVALID_ARG;
    if (g_hop_mutex == NULL) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(g_hop_mutex, portMAX_DELAY);
    *out = g_hop_stats[channel];
    xSemaphoreGive(g_hop_mutex);
    return ESP_OK;
}

esp_err_t channel_hopper_get_all_stats(ch_hop_stats_t out[14])
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    if (g_hop_mutex == NULL) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(g_hop_mutex, portMAX_DELAY);
    memcpy(out, g_hop_stats, sizeof(ch_hop_stats_t) * 14);
    xSemaphoreGive(g_hop_mutex);
    return ESP_OK;
}

int channel_hopper_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return 0;
    if (g_hop_mutex == NULL) return 0;

    xSemaphoreTake(g_hop_mutex, portMAX_DELAY);
    int written = 0;

    written += snprintf(buf + written, bufsz - (size_t)written,
                        "{\"mode\":%u,\"dwell_ms\":%u,\"mask\":\"0x%02X\","
                        "\"channels\":[",
                        (unsigned)g_hop_cfg.mode,
                        (unsigned)g_hop_cfg.dwell_ms,
                        (unsigned)g_hop_cfg.channel_mask);

    bool first = true;
    for (uint8_t ch = 1; ch <= 13; ch++) {
        if (!(g_hop_cfg.channel_mask & (1u << (ch - 1)))) continue;
        ch_hop_stats_t *s = &g_hop_stats[ch];
        int32_t avg_rssi = s->rssi_samples ? (s->rssi_sum / (int32_t)s->rssi_samples) : 0;
        if (!first) written += snprintf(buf + written, bufsz - (size_t)written, ",");
        first = false;
        written += snprintf(buf + written, bufsz - (size_t)written,
                            "{\"ch\":%u,\"pkts\":%u,\"beacons\":%u,"
                            "\"mgmt\":%u,\"data\":%u,\"rssi_avg\":%d}",
                            (unsigned)ch,
                            (unsigned)s->pkt_count,
                            (unsigned)s->beacon_count,
                            (unsigned)s->mgmt_count,
                            (unsigned)s->data_count,
                            (int)avg_rssi);
    }

    written += snprintf(buf + written, bufsz - (size_t)written, "]}");
    xSemaphoreGive(g_hop_mutex);

    if (written < 0) written = 0;
    if ((size_t)written >= bufsz) written = (int)bufsz - 1;
    return written;
}

void channel_hopper_print_summary(void)
{
    if (g_hop_mutex == NULL) return;

    xSemaphoreTake(g_hop_mutex, portMAX_DELAY);
    printf("\n==== CHANNEL HOPPER SUMMARY ====\n");
    printf(" Mode: %s | Dwell: %u ms\n",
           g_hop_cfg.mode == CH_HOP_MODE_RANDOM ? "random" :
           g_hop_cfg.mode == CH_HOP_MODE_RSSI_OPT ? "rssi_opt" : "sequential",
           (unsigned)g_hop_cfg.dwell_ms);
    printf(" Mask: 0x%02X\n", (unsigned)g_hop_cfg.channel_mask);
    printf(" CH | PKTS | BEACONS | MGMT  | DATA  | RSSI_AVG\n");
    printf("----+-------+---------+-------+-------+----------\n");

    for (uint8_t ch = 1; ch <= 13; ch++) {
        ch_hop_stats_t *s = &g_hop_stats[ch];
        int32_t avg = s->rssi_samples ? (s->rssi_sum / (int32_t)s->rssi_samples) : 0;
        printf(" %-2u | %5u | %7u | %5u | %5u | %8d\n",
               ch,
               (unsigned)s->pkt_count,
               (unsigned)s->beacon_count,
               (unsigned)s->mgmt_count,
               (unsigned)s->data_count,
               (int)avg);
    }
    xSemaphoreGive(g_hop_mutex);
    printf("=================================\n");
}
