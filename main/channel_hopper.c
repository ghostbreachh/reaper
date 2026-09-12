/*
 * ============================================================================
 *  channel_hopper.c  —  Smart Wi-Fi channel hopper with per-channel stats
 * ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <stdatomic.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_err.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_heap_caps.h"

#include "channel_hopper.h"
#include "wifi_sniffer.h"
#include "usb_cdc.h"
#include "watchdog.h"

static const char *TAG = "ch_hopper";

#define DEFAULT_DWELL_MS        100
#define MIN_DWELL_MS            10
#define MAX_DWELL_MS            30000

#define ADAPTIVE_MIN_MS         10
#define ADAPTIVE_MAX_MS         1000

#define HOP_TASK_STACK          4096
#define HOP_TASK_PRIO           5
#define HOP_TASK_CORE           0

#define STOP_TIMEOUT_MS         1000
#define DWELL_WAIT_CHUNK_MS     5

static atomic_bool g_hop_active = ATOMIC_VAR_INIT(false);

static ch_hop_config_t g_hop_cfg = {
    .mode = CH_HOP_MODE_SEQUENTIAL,
    .dwell_ms = DEFAULT_DWELL_MS,
    .channel_mask = CH_HOP_MASK_ALL,
    .dwell_us = 0,
};

static ch_hop_stats_t g_hop_stats[14] = {0}; /* index 1..13 */

static SemaphoreHandle_t g_cfg_mutex = NULL;
static SemaphoreHandle_t g_stop_ack_sem = NULL;

/*
 * Stats updates happen from the Wi-Fi worker hot path.
 * Use a spinlock/critical section instead of a full mutex.
 */
static portMUX_TYPE g_stats_spin = portMUX_INITIALIZER_UNLOCKED;

static TaskHandle_t g_hop_task = NULL;
static _Atomic uint8_t g_current_channel = 0;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static bool channel_valid(uint8_t channel)
{
    return channel >= CH_HOP_CHANNEL_MIN && channel <= CH_HOP_CHANNEL_MAX;
}

static uint16_t clamp_u16(uint16_t v, uint16_t lo, uint16_t hi)
{
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static const char *mode_str(ch_hop_mode_t mode)
{
    switch (mode) {
        case CH_HOP_MODE_RANDOM:     return "random";
        case CH_HOP_MODE_RSSI_OPT:   return "rssi_opt";
        case CH_HOP_MODE_ADAPTIVE:   return "adaptive";
        case CH_HOP_MODE_SEQUENTIAL:
        default:                     return "sequential";
    }
}

/*
 * Legacy compatibility:
 * Original code used uint8_t channel_mask where 0xFF meant "all channels".
 * That cannot represent channels 9-13, so we now use uint16_t.
 *
 * Treat 0x00FF as legacy "all channels".
 */
static uint16_t normalize_mask(uint16_t mask)
{
    if (mask == 0 || mask == 0x00FFu) {
        return CH_HOP_MASK_ALL;
    }
    return mask & CH_HOP_MASK_ALL;
}

static void normalize_config(ch_hop_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }

    if (cfg->mode > CH_HOP_MODE_ADAPTIVE) {
        cfg->mode = CH_HOP_MODE_SEQUENTIAL;
    }

    cfg->channel_mask = normalize_mask(cfg->channel_mask);

    if (cfg->dwell_us > 0) {
        cfg->dwell_ms = 0;
    } else {
        if (cfg->dwell_ms == 0) {
            cfg->dwell_ms = DEFAULT_DWELL_MS;
        }
        cfg->dwell_ms = clamp_u16(cfg->dwell_ms, MIN_DWELL_MS, MAX_DWELL_MS);
    }
}

static esp_err_t get_config_snapshot(ch_hop_config_t *out)
{
    if (out == NULL || g_cfg_mutex == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_cfg_mutex, portMAX_DELAY);
    *out = g_hop_cfg;
    xSemaphoreGive(g_cfg_mutex);

    normalize_config(out);
    return ESP_OK;
}

static bool break_requested(void)
{
    if (usb_cdc_break_signaled()) {
        usb_cdc_break_clear();
        return true;
    }
    return false;
}

/* -------------------------------------------------------------------------
 *  Stats helpers
 * ----------------------------------------------------------------------- */

static void stats_reset_all(void)
{
    taskENTER_CRITICAL(&g_stats_spin);
    memset(g_hop_stats, 0, sizeof(g_hop_stats));
    taskEXIT_CRITICAL(&g_stats_spin);
}

static void stats_copy_all(ch_hop_stats_t out[14])
{
    taskENTER_CRITICAL(&g_stats_spin);
    memcpy(out, g_hop_stats, sizeof(g_hop_stats));
    taskEXIT_CRITICAL(&g_stats_spin);
}

static void stats_enter_channel(uint8_t channel)
{
    if (!channel_valid(channel)) {
        return;
    }

    uint64_t now = esp_timer_get_time();

    taskENTER_CRITICAL(&g_stats_spin);
    g_hop_stats[channel].window_pkt_count = 0;
    g_hop_stats[channel].window_start_us = now;
    taskEXIT_CRITICAL(&g_stats_spin);
}

static void stats_leave_channel(uint8_t channel, uint32_t default_dwell_ms)
{
    if (!channel_valid(channel)) {
        return;
    }

    taskENTER_CRITICAL(&g_stats_spin);

    ch_hop_stats_t *s = &g_hop_stats[channel];

    uint32_t pkts = s->window_pkt_count;
    uint32_t dwell = s->adaptive_dwell_ms;

    if (dwell == 0) {
        dwell = default_dwell_ms;
    }

    if (dwell == 0) {
        dwell = DEFAULT_DWELL_MS;
    }

    /*
     * Simple adaptive policy:
     *
     *   very busy channel  -> stay longer
     *   moderately busy    -> stay slightly longer
     *   quiet channel      -> reduce dwell
     */
    if (pkts > 64) {
        dwell += 25;
    } else if (pkts > 32) {
        dwell += 10;
    } else if (pkts < 4) {
        dwell /= 2;
    } else if (pkts < 12) {
        dwell = (dwell * 8) / 10;
    }

    if (dwell < ADAPTIVE_MIN_MS) {
        dwell = ADAPTIVE_MIN_MS;
    }

    if (dwell > ADAPTIVE_MAX_MS) {
        dwell = ADAPTIVE_MAX_MS;
    }

    s->adaptive_dwell_ms = dwell;
    s->window_pkt_count = 0;
    s->window_start_us = 0;

    taskEXIT_CRITICAL(&g_stats_spin);
}

/* -------------------------------------------------------------------------
 *  Channel selection
 * ----------------------------------------------------------------------- */

static uint8_t next_channel(uint8_t cur, uint16_t mask)
{
    if (mask == CH_HOP_MASK_ALL) {
        return (cur == 0 || cur > CH_HOP_CHANNEL_MAX)
                   ? CH_HOP_CHANNEL_MIN
                   : (cur % CH_HOP_CHANNEL_MAX) + 1;
    }

    for (uint8_t step = 1; step <= CH_HOP_CHANNEL_MAX; step++) {
        uint8_t ch = ((cur + step - 1) % CH_HOP_CHANNEL_MAX) + 1;
        if (mask & (1u << (ch - 1))) {
            return ch;
        }
    }

    return CH_HOP_CHANNEL_MIN;
}

static uint8_t random_channel(uint16_t mask)
{
    uint8_t candidates[CH_HOP_CHANNEL_MAX];
    uint8_t n = 0;

    for (uint8_t ch = CH_HOP_CHANNEL_MIN; ch <= CH_HOP_CHANNEL_MAX; ch++) {
        if (mask & (1u << (ch - 1))) {
            candidates[n++] = ch;
        }
    }

    if (n == 0) {
        return CH_HOP_CHANNEL_MIN;
    }

    return candidates[esp_random() % n];
}

static uint8_t select_best_rssi_channel(uint8_t cur, uint16_t mask)
{
    ch_hop_stats_t stats[14];
    stats_copy_all(stats);

    uint8_t best = 0;
    int32_t best_rssi = INT32_MIN;

    for (uint8_t ch = CH_HOP_CHANNEL_MIN; ch <= CH_HOP_CHANNEL_MAX; ch++) {
        if (!(mask & (1u << (ch - 1)))) {
            continue;
        }

        const ch_hop_stats_t *s = &stats[ch];

        if (s->rssi_samples == 0) {
            continue;
        }

        int32_t avg = s->rssi_sum / (int32_t)s->rssi_samples;

        /*
         * Higher RSSI is better:
         *   -40 dBm > -85 dBm
         */
        if (avg > best_rssi) {
            best_rssi = avg;
            best = ch;
        }
    }

    if (best == 0) {
        return next_channel(cur, mask);
    }

    return best;
}

/* -------------------------------------------------------------------------
 *  Dwell / delay helpers
 * ----------------------------------------------------------------------- */

static bool wait_ms_interruptible(uint32_t ms)
{
    uint32_t elapsed = 0;

    while (elapsed < ms && atomic_load(&g_hop_active)) {
        if (break_requested()) {
            return false;
        }

        uint32_t chunk = ms - elapsed;
        if (chunk > DWELL_WAIT_CHUNK_MS) {
            chunk = DWELL_WAIT_CHUNK_MS;
        }

        if (chunk == 0) {
            break;
        }

        vTaskDelay(pdMS_TO_TICKS(chunk));
        elapsed += chunk;

        watchdog_task_refresh(TAG);
    }

    return atomic_load(&g_hop_active);
}

static bool wait_dwell(const ch_hop_config_t *cfg, uint8_t channel)
{
    if (cfg == NULL) {
        return false;
    }

    /*
     * Microsecond dwell override.
     * For < 1 ms, vTaskDelay is too coarse, so busy-wait.
     */
    if (cfg->dwell_us > 0) {
        if (cfg->dwell_us < 1000) {
            uint64_t start = esp_timer_get_time();

            while ((uint64_t)(esp_timer_get_time() - start) < cfg->dwell_us) {
                if (!atomic_load(&g_hop_active)) {
                    return false;
                }
            }

            watchdog_task_refresh(TAG);
            return atomic_load(&g_hop_active);
        }

        return wait_ms_interruptible((uint32_t)(cfg->dwell_us / 1000));
    }

    uint32_t dwell_ms = cfg->dwell_ms;

    if (cfg->mode == CH_HOP_MODE_ADAPTIVE) {
        uint32_t adaptive = 0;

        taskENTER_CRITICAL(&g_stats_spin);
        adaptive = g_hop_stats[channel].adaptive_dwell_ms;
        taskEXIT_CRITICAL(&g_stats_spin);

        if (adaptive > 0) {
            dwell_ms = adaptive;
        }
    }

    return wait_ms_interruptible(dwell_ms);
}

/* -------------------------------------------------------------------------
 *  Hopper task
 * ----------------------------------------------------------------------- */

static void channel_hopper_task(void *arg)
{
    (void)arg;

    ch_hop_config_t cfg;

    if (get_config_snapshot(&cfg) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read config snapshot");
        if (g_stop_ack_sem != NULL) {
            xSemaphoreGive(g_stop_ack_sem);
        }
        vTaskDelete(NULL);
        return;
    }

    uint16_t mask = cfg.channel_mask;

    /*
     * Honor fixed channel if wifi_sniffer has one set.
     */
    uint8_t current = atomic_load(&g_wifi_fixed_channel);
    if (!channel_valid(current)) {
        current = next_channel(0, mask);
    }

    while (atomic_load(&g_hop_active)) {
        watchdog_task_refresh(TAG);

        if (break_requested()) {
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        if (get_config_snapshot(&cfg) != ESP_OK) {
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        mask = cfg.channel_mask;

        uint8_t fixed = atomic_load(&g_wifi_fixed_channel);
        if (channel_valid(fixed)) {
            current = fixed;
        }

        esp_err_t ret = esp_wifi_set_channel(current, WIFI_SECOND_CHAN_NONE);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "esp_wifi_set_channel(%u) failed: %s",
                     current, esp_err_to_name(ret));
            wait_ms_interruptible(20);
            continue;
        }

        atomic_store(&g_current_channel, current);
        stats_enter_channel(current);

        bool dwell_ok = wait_dwell(&cfg, current);

        stats_leave_channel(current, cfg.dwell_ms);

        if (!dwell_ok || !atomic_load(&g_hop_active)) {
            break;
        }

        fixed = atomic_load(&g_wifi_fixed_channel);
        if (channel_valid(fixed)) {
            current = fixed;
            continue;
        }

        switch (cfg.mode) {
            case CH_HOP_MODE_RANDOM:
                current = random_channel(mask);
                break;

            case CH_HOP_MODE_RSSI_OPT:
                current = select_best_rssi_channel(current, mask);
                break;

            case CH_HOP_MODE_ADAPTIVE:
            case CH_HOP_MODE_SEQUENTIAL:
            default:
                current = next_channel(current, mask);
                break;
        }
    }

    if (g_stop_ack_sem != NULL) {
        xSemaphoreGive(g_stop_ack_sem);
    }

    vTaskDelete(NULL);
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t channel_hopper_init(void)
{
    if (g_cfg_mutex != NULL) {
        return ESP_OK;
    }

    g_cfg_mutex = xSemaphoreCreateMutex();
    g_stop_ack_sem = xSemaphoreCreateBinary();

    if (g_cfg_mutex == NULL || g_stop_ack_sem == NULL) {
        if (g_cfg_mutex != NULL) {
            vSemaphoreDelete(g_cfg_mutex);
            g_cfg_mutex = NULL;
        }

        if (g_stop_ack_sem != NULL) {
            vSemaphoreDelete(g_stop_ack_sem);
            g_stop_ack_sem = NULL;
        }

        ESP_LOGE(TAG, "Failed to create hopper sync objects");
        return ESP_ERR_NO_MEM;
    }

    stats_reset_all();

    xSemaphoreTake(g_cfg_mutex, portMAX_DELAY);
    g_hop_cfg.mode = CH_HOP_MODE_SEQUENTIAL;
    g_hop_cfg.dwell_ms = DEFAULT_DWELL_MS;
    g_hop_cfg.channel_mask = CH_HOP_MASK_ALL;
    g_hop_cfg.dwell_us = 0;
    xSemaphoreGive(g_cfg_mutex);

    atomic_store(&g_current_channel, 0);

    ESP_LOGI(TAG, "Channel hopper initialized");
    return ESP_OK;
}

esp_err_t channel_hopper_start(const ch_hop_config_t *cfg)
{
    if (cfg == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (atomic_load(&g_hop_active)) {
        return ESP_ERR_INVALID_STATE;
    }

    if (g_cfg_mutex == NULL) {
        esp_err_t ret = channel_hopper_init();
        if (ret != ESP_OK) {
            return ret;
        }
    }

    ch_hop_config_t local_cfg = *cfg;
    normalize_config(&local_cfg);

    xSemaphoreTake(g_cfg_mutex, portMAX_DELAY);
    g_hop_cfg = local_cfg;
    xSemaphoreGive(g_cfg_mutex);

    stats_reset_all();
    atomic_store(&g_current_channel, 0);

    if (g_stop_ack_sem != NULL) {
        xSemaphoreTake(g_stop_ack_sem, 0); /* drain stale ack */
    }

    atomic_store(&g_hop_active, true);

    BaseType_t rc = xTaskCreatePinnedToCore(
        channel_hopper_task,
        "ch_hopper",
        HOP_TASK_STACK,
        NULL,
        HOP_TASK_PRIO,
        &g_hop_task,
        HOP_TASK_CORE
    );

    if (rc != pdPASS) {
        atomic_store(&g_hop_active, false);
        g_hop_task = NULL;
        ESP_LOGE(TAG, "Failed to create hopper task");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG,
             "Channel hopper started: mode=%s dwell_ms=%u dwell_us=%" PRIu32 " mask=0x%04X",
             mode_str(local_cfg.mode),
             (unsigned)local_cfg.dwell_ms,
             local_cfg.dwell_us,
             (unsigned)local_cfg.channel_mask);

    return ESP_OK;
}

esp_err_t channel_hopper_stop(void)
{
    if (!atomic_load(&g_hop_active)) {
        return ESP_OK;
    }

    /*
     * If called from the hopper task itself, exit directly.
     */
    if (g_hop_task != NULL && g_hop_task == xTaskGetCurrentTaskHandle()) {
        atomic_store(&g_hop_active, false);
        if (g_stop_ack_sem != NULL) {
            xSemaphoreGive(g_stop_ack_sem);
        }
        vTaskDelete(NULL);
        return ESP_OK;
    }

    atomic_store(&g_hop_active, false);

    if (g_stop_ack_sem != NULL) {
        if (xSemaphoreTake(g_stop_ack_sem, pdMS_TO_TICKS(STOP_TIMEOUT_MS)) != pdTRUE) {
            ESP_LOGW(TAG, "Hopper stop timed out; task may still be exiting");
        }
    }

    g_hop_task = NULL;

    ESP_LOGI(TAG, "Channel hopper stopped on channel %u",
             (unsigned)atomic_load(&g_current_channel));

    return ESP_OK;
}

bool channel_hopper_is_active(void)
{
    return atomic_load(&g_hop_active);
}

/* -------------------------------------------------------------------------
 *  Configuration
 * ----------------------------------------------------------------------- */

esp_err_t channel_hopper_set_dwell_us(uint32_t us)
{
    if (g_cfg_mutex == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_cfg_mutex, portMAX_DELAY);

    if (us == 0) {
        g_hop_cfg.dwell_us = 0;
        g_hop_cfg.dwell_ms = DEFAULT_DWELL_MS;
    } else if (us < 1000) {
        g_hop_cfg.dwell_us = us;
        g_hop_cfg.dwell_ms = 0;
    } else {
        uint32_t ms = us / 1000;
        g_hop_cfg.dwell_us = 0;
        g_hop_cfg.dwell_ms = clamp_u16((uint16_t)ms, MIN_DWELL_MS, MAX_DWELL_MS);
    }

    uint32_t effective_us = g_hop_cfg.dwell_us
                                ? g_hop_cfg.dwell_us
                                : (uint32_t)g_hop_cfg.dwell_ms * 1000;

    xSemaphoreGive(g_cfg_mutex);

    ESP_LOGI(TAG, "Dwell set to %" PRIu32 " us", effective_us);
    return ESP_OK;
}

uint32_t channel_hopper_get_dwell_us(void)
{
    if (g_cfg_mutex == NULL) {
        return DEFAULT_DWELL_MS * 1000;
    }

    xSemaphoreTake(g_cfg_mutex, portMAX_DELAY);
    uint32_t ret = g_hop_cfg.dwell_us
                       ? g_hop_cfg.dwell_us
                       : (uint32_t)g_hop_cfg.dwell_ms * 1000;
    xSemaphoreGive(g_cfg_mutex);

    return ret;
}

uint32_t channel_hopper_adaptive_dwell(uint8_t channel)
{
    if (!channel_valid(channel)) {
        return 0;
    }

    uint32_t adaptive = 0;

    taskENTER_CRITICAL(&g_stats_spin);
    adaptive = g_hop_stats[channel].adaptive_dwell_ms;
    taskEXIT_CRITICAL(&g_stats_spin);

    if (adaptive > 0) {
        return adaptive;
    }

    ch_hop_config_t cfg;
    if (get_config_snapshot(&cfg) == ESP_OK) {
        return cfg.dwell_ms;
    }

    return DEFAULT_DWELL_MS;
}

/* -------------------------------------------------------------------------
 *  Packet statistics feed
 * ----------------------------------------------------------------------- */

esp_err_t channel_hopper_record_packet(uint8_t channel,
                                       uint32_t pkt_count,
                                       uint32_t mgmt_count,
                                       uint32_t beacon_count,
                                       uint32_t data_count,
                                       int8_t rssi)
{
    if (!channel_valid(channel)) {
        return ESP_ERR_INVALID_ARG;
    }

    /*
     * This is called from the Wi-Fi worker hot path.
     * If hopper is stopped, silently ignore rather than creating error churn.
     */
    if (!atomic_load(&g_hop_active)) {
        return ESP_OK;
    }

    taskENTER_CRITICAL(&g_stats_spin);

    ch_hop_stats_t *s = &g_hop_stats[channel];

    s->pkt_count += pkt_count;
    s->mgmt_count += mgmt_count;
    s->beacon_count += beacon_count;
    s->data_count += data_count;
    s->window_pkt_count += pkt_count;

    if (pkt_count > 0) {
        s->rssi_sum += (int32_t)rssi * (int32_t)pkt_count;
        s->rssi_samples += pkt_count;
    }

    taskEXIT_CRITICAL(&g_stats_spin);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Stats export
 * ----------------------------------------------------------------------- */

esp_err_t channel_hopper_get_stats(uint8_t channel, ch_hop_stats_t *out)
{
    if (out == NULL || !channel_valid(channel)) {
        return ESP_ERR_INVALID_ARG;
    }

    taskENTER_CRITICAL(&g_stats_spin);
    *out = g_hop_stats[channel];
    taskEXIT_CRITICAL(&g_stats_spin);

    return ESP_OK;
}

esp_err_t channel_hopper_get_all_stats(ch_hop_stats_t out[14])
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    stats_copy_all(out);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  JSON export
 * ----------------------------------------------------------------------- */

static int json_append(char *buf, size_t bufsz, size_t *off, const char *fmt, ...)
{
    if (buf == NULL || bufsz == 0 || off == NULL || *off >= bufsz) {
        return 0;
    }

    va_list args;
    va_start(args, fmt);

    int n = vsnprintf(buf + *off, bufsz - *off, fmt, args);

    va_end(args);

    if (n < 0) {
        return -1;
    }

    if ((size_t)n >= bufsz - *off) {
        *off = bufsz - 1;
        return 0;
    }

    *off += (size_t)n;
    return n;
}

int channel_hopper_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return 0;
    }

    ch_hop_config_t cfg;
    if (get_config_snapshot(&cfg) != ESP_OK) {
        return 0;
    }

    ch_hop_stats_t stats[14];
    stats_copy_all(stats);

    size_t off = 0;

    if (json_append(buf, bufsz, &off,
                    "{\"mode\":%u,\"mode_name\":\"%s\","
                    "\"dwell_ms\":%u,\"dwell_us\":%" PRIu32 ","
                    "\"mask\":\"0x%04X\",\"channels\":[",
                    (unsigned)cfg.mode,
                    mode_str(cfg.mode),
                    (unsigned)cfg.dwell_ms,
                    cfg.dwell_us,
                    (unsigned)cfg.channel_mask) < 0) {
        return 0;
    }

    bool first = true;

    for (uint8_t ch = CH_HOP_CHANNEL_MIN; ch <= CH_HOP_CHANNEL_MAX; ch++) {
        if (!(cfg.channel_mask & (1u << (ch - 1)))) {
            continue;
        }

        const ch_hop_stats_t *s = &stats[ch];

        int32_t avg_rssi = 0;
        if (s->rssi_samples > 0) {
            avg_rssi = s->rssi_sum / (int32_t)s->rssi_samples;
        }

        if (!first) {
            if (json_append(buf, bufsz, &off, ",") < 0) {
                break;
            }
        }

        first = false;

        if (json_append(buf, bufsz, &off,
                        "{\"ch\":%u,\"pkts\":%" PRIu32 ","
                        "\"beacons\":%" PRIu32 ","
                        "\"mgmt\":%" PRIu32 ","
                        "\"data\":%" PRIu32 ","
                        "\"rssi_avg\":%" PRId32 ","
                        "\"adaptive_dwell\":%" PRIu32 "}",
                        (unsigned)ch,
                        s->pkt_count,
                        s->beacon_count,
                        s->mgmt_count,
                        s->data_count,
                        avg_rssi,
                        s->adaptive_dwell_ms) < 0) {
            break;
        }

        if (off >= bufsz - 1) {
            break;
        }
    }

    json_append(buf, bufsz, &off, "]}");

    return (int)off;
}

/* -------------------------------------------------------------------------
 *  Console summary
 * ----------------------------------------------------------------------- */

void channel_hopper_print_summary(void)
{
    ch_hop_config_t cfg;
    if (get_config_snapshot(&cfg) != ESP_OK) {
        return;
    }

    ch_hop_stats_t stats[14];
    stats_copy_all(stats);

    printf("\n==== CHANNEL HOPPER SUMMARY ====\n");
    printf(" Mode       : %s\n", mode_str(cfg.mode));
    printf(" Dwell      : %u ms", (unsigned)cfg.dwell_ms);

    if (cfg.dwell_us > 0) {
        printf(" (%" PRIu32 " us override)", cfg.dwell_us);
    }

    printf("\n");
    printf(" Mask       : 0x%04X\n", (unsigned)cfg.channel_mask);
    printf(" Active     : %s\n", atomic_load(&g_hop_active) ? "yes" : "no");
    printf(" Current CH : %u\n", (unsigned)atomic_load(&g_current_channel));

    printf("\n");
    printf(" CH | PKTS    | BEACONS | MGMT    | DATA    | RSSI_AVG | ADAPT_MS\n");
    printf("----+---------+---------+---------+---------+----------+----------\n");

    for (uint8_t ch = CH_HOP_CHANNEL_MIN; ch <= CH_HOP_CHANNEL_MAX; ch++) {
        const ch_hop_stats_t *s = &stats[ch];

        int32_t avg = 0;
        if (s->rssi_samples > 0) {
            avg = s->rssi_sum / (int32_t)s->rssi_samples;
        }

        printf(" %-2u | %7" PRIu32 " | %7" PRIu32 " | %7" PRIu32
               " | %7" PRIu32 " | %8" PRId32 " | %8" PRIu32 "\n",
               ch,
               s->pkt_count,
               s->beacon_count,
               s->mgmt_count,
               s->data_count,
               avg,
               s->adaptive_dwell_ms);
    }

    printf("================================\n");
}
