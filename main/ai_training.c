#include "ai_training.h"

#include "ai_classifier.h"
#include "ai_fingerprint.h"
#include "ai_ble_profiler.h"
#include "ai_anomaly.h"
#include "ai_rogue_detector.h"
#include "storage_sd.h"
#include "common_types.h"

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/time.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "ai_train";

#define AI_TRAIN_DLT_IEEE802_11     105u
#define AI_TRAIN_DLT_USER0          147u

#define AI_TRAIN_FLUSH_EVERY        32u
#define AI_TRAIN_CLOSE_TIMEOUT_MS   3000u

typedef struct {
    bool active;
    bool closing;
    uint8_t users;

    FILE *pcap;
    FILE *labels;

    char pcap_path[128];
    char label_path[128];

    uint32_t linktype;

    uint32_t pkt_count;
    uint32_t label_count;
    uint32_t dropped_count;
    uint32_t flush_counter;
} train_capture_t;

static bool g_init_done = false;
static ai_train_mode_t g_mode = AI_TRAIN_MODE_OFF;

static train_capture_t g_wifi_cap;
static train_capture_t g_ble_cap;

static SemaphoreHandle_t g_lock = NULL;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static const char *mode_to_str(ai_train_mode_t mode)
{
    switch (mode) {
        case AI_TRAIN_MODE_WIFI: return "wifi";
        case AI_TRAIN_MODE_BLE:  return "ble";
        case AI_TRAIN_MODE_BOTH: return "both";
        default:                 return "off";
    }
}

static void put_u16_le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static void put_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static bool wifi_frame_get_bssid(const uint8_t *frame, size_t frame_len, uint8_t out[6])
{
    if (frame == NULL || frame_len < 24 || out == NULL) {
        return false;
    }

    uint16_t fc = (uint16_t)(frame[0] | ((uint16_t)frame[1] << 8));
    uint8_t type = (uint8_t)((fc >> 2) & 0x03u);

    bool to_ds = (fc & 0x0100u) != 0;
    bool from_ds = (fc & 0x0200u) != 0;

    if (type == 0) {
        /* Management frames: BSSID is addr3. */
        memcpy(out, frame + 16, 6);
        return true;
    }

    if (type == 2) {
        if (!to_ds && !from_ds) {
            memcpy(out, frame + 16, 6);
            return true;
        }

        if (to_ds && !from_ds) {
            memcpy(out, frame + 4, 6);
            return true;
        }

        if (!to_ds && from_ds) {
            memcpy(out, frame + 10, 6);
            return true;
        }
    }

    return false;
}

static bool rogue_check_mac(const uint8_t *mac)
{
    if (mac == NULL) {
        return false;
    }

    uint8_t count = ai_rogue_detector_alert_count();

    for (uint8_t i = 0; i < count; i++) {
        ai_rogue_alert_t alert;

        if (ai_rogue_detector_get_alert(i, &alert) != ESP_OK) {
            continue;
        }

        if (memcmp(alert.bssid, mac, 6) == 0) {
            return true;
        }
    }

    return false;
}

/* -------------------------------------------------------------------------
 *  PCAP I/O
 * ----------------------------------------------------------------------- */

static bool pcap_write_header(FILE *f, uint32_t linktype)
{
    if (f == NULL) {
        return false;
    }

    uint8_t hdr[24];

    put_u32_le(hdr + 0, 0xA1B2C3D4u); /* magic */
    put_u16_le(hdr + 4, 2);           /* version major */
    put_u16_le(hdr + 6, 4);           /* version minor */
    put_u32_le(hdr + 8, 0);           /* thiszone */
    put_u32_le(hdr + 12, 0);          /* sigfigs */
    put_u32_le(hdr + 16, 65535u);     /* snaplen */
    put_u32_le(hdr + 20, linktype);   /* network */

    return fwrite(hdr, 1, sizeof(hdr), f) == sizeof(hdr);
}

static bool pcap_write_record(FILE *f,
                              const uint8_t *data,
                              size_t len,
                              uint32_t ts_sec,
                              uint32_t ts_usec)
{
    if (f == NULL || data == NULL || len == 0 || len > 65535u) {
        return false;
    }

    uint8_t hdr[16];

    put_u32_le(hdr + 0, ts_sec);
    put_u32_le(hdr + 4, ts_usec);
    put_u32_le(hdr + 8, (uint32_t)len);
    put_u32_le(hdr + 12, (uint32_t)len);

    if (fwrite(hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        return false;
    }

    if (fwrite(data, 1, len, f) != len) {
        return false;
    }

    return true;
}

/* -------------------------------------------------------------------------
 *  Capture lifecycle
 * ----------------------------------------------------------------------- */

static esp_err_t capture_open(train_capture_t *cap,
                              const char *suffix,
                              uint32_t linktype,
                              int64_t timestamp)
{
    memset(cap, 0, sizeof(*cap));

    snprintf(cap->pcap_path,
             sizeof(cap->pcap_path),
             "/sd/train_%" PRId64 "_%s.pcap",
             timestamp,
             suffix);

    snprintf(cap->label_path,
             sizeof(cap->label_path),
             "/sd/train_%" PRId64 "_%s.json",
             timestamp,
             suffix);

    cap->pcap = fopen(cap->pcap_path, "wb");
    if (cap->pcap == NULL) {
        ESP_LOGE(TAG, "Failed to open %s", cap->pcap_path);
        return ESP_FAIL;
    }

    if (!pcap_write_header(cap->pcap, linktype)) {
        ESP_LOGE(TAG, "Failed to write PCAP header to %s", cap->pcap_path);
        fclose(cap->pcap);
        cap->pcap = NULL;
        return ESP_FAIL;
    }

    cap->labels = fopen(cap->label_path, "w");
    if (cap->labels == NULL) {
        ESP_LOGE(TAG, "Failed to open %s", cap->label_path);
        fclose(cap->pcap);
        cap->pcap = NULL;
        return ESP_FAIL;
    }

    fprintf(cap->labels, "[");

    cap->linktype = linktype;
    cap->active = false;
    cap->closing = false;
    cap->users = 0;

    return ESP_OK;
}

static void capture_activate(train_capture_t *cap)
{
    if (g_lock == NULL || cap == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    if (cap->pcap != NULL && cap->labels != NULL) {
        cap->active = true;
        cap->closing = false;
        cap->users = 0;
    }

    xSemaphoreGive(g_lock);
}

static void capture_stop(train_capture_t *cap)
{
    if (g_lock == NULL || cap == NULL) {
        return;
    }

    bool need_close = false;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    if (cap->active || cap->closing || cap->pcap != NULL || cap->labels != NULL) {
        cap->closing = true;
        need_close = true;
    }

    xSemaphoreGive(g_lock);

    if (!need_close) {
        return;
    }

    TickType_t start = xTaskGetTickCount();

    while (true) {
        uint8_t users = 0;

        xSemaphoreTake(g_lock, portMAX_DELAY);
        users = cap->users;
        xSemaphoreGive(g_lock);

        if (users == 0) {
            break;
        }

        if ((xTaskGetTickCount() - start) > pdMS_TO_TICKS(AI_TRAIN_CLOSE_TIMEOUT_MS)) {
            ESP_LOGW(TAG, "Capture close timeout; forcing close");
            break;
        }

        vTaskDelay(pdMS_TO_TICKS(5));
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    cap->active = false;
    cap->closing = false;

    if (cap->labels != NULL) {
        fprintf(cap->labels, "\n]\n");
        fclose(cap->labels);
        cap->labels = NULL;
    }

    if (cap->pcap != NULL) {
        fclose(cap->pcap);
        cap->pcap = NULL;
    }

    cap->users = 0;

    xSemaphoreGive(g_lock);
}

static bool capture_acquire(train_capture_t *cap)
{
    if (g_lock == NULL || cap == NULL) {
        return false;
    }

    bool ok = false;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    if (g_init_done && cap->active && !cap->closing &&
        cap->pcap != NULL && cap->labels != NULL) {
        cap->users++;
        ok = true;
    }

    xSemaphoreGive(g_lock);

    return ok;
}

static void capture_release(train_capture_t *cap)
{
    if (g_lock == NULL || cap == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    if (cap->users > 0) {
        cap->users--;
    }

    xSemaphoreGive(g_lock);
}

/* -------------------------------------------------------------------------
 *  Label writing
 * ----------------------------------------------------------------------- */

static void write_label_to_capture(train_capture_t *cap,
                                   const uint8_t *data,
                                   size_t len,
                                   uint32_t ts_sec,
                                   uint32_t ts_usec,
                                   const ai_train_label_t *label)
{
    if (g_lock == NULL || cap == NULL || label == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    if (!cap->active || cap->closing || cap->pcap == NULL || cap->labels == NULL) {
        cap->dropped_count++;
        xSemaphoreGive(g_lock);
        return;
    }

    if (!pcap_write_record(cap->pcap, data, len, ts_sec, ts_usec)) {
        cap->dropped_count++;
        cap->closing = true;
        xSemaphoreGive(g_lock);
        return;
    }

    cap->pkt_count++;

    if (cap->label_count > 0) {
        fprintf(cap->labels, ",\n");
    } else {
        fprintf(cap->labels, "\n");
    }

    char mac_str[20] = "";

    if (label->mac_len == 6) {
        snprintf(mac_str,
                 sizeof(mac_str),
                 "%02X:%02X:%02X:%02X:%02X:%02X",
                 label->mac[0],
                 label->mac[1],
                 label->mac[2],
                 label->mac[3],
                 label->mac[4],
                 label->mac[5]);
    }

    int rc = fprintf(cap->labels,
                     "{\"ts\":%" PRIu64
                     ",\"ch\":%u"
                     ",\"rssi\":%d"
                     ",\"pkt_cls\":%u"
                     ",\"pkt_conf\":%.2f"
                     ",\"dev_cls\":%u"
                     ",\"anomaly\":%s"
                     ",\"anom_score\":%.4f"
                     ",\"rogue\":%s"
                     ",\"flags\":%u"
                     ",\"mac\":\"%s\"}",
                     label->timestamp_us,
                     (unsigned)label->channel,
                     (int)label->rssi,
                     (unsigned)label->pkt_class,
                     (double)label->pkt_confidence,
                     (unsigned)label->device_class,
                     label->is_anomaly ? "true" : "false",
                     (double)label->anomaly_score,
                     label->is_rogue ? "true" : "false",
                     (unsigned)label->flags,
                     mac_str);

    if (rc < 0) {
        cap->dropped_count++;
        cap->closing = true;
        xSemaphoreGive(g_lock);
        return;
    }

    cap->label_count++;
    cap->flush_counter++;

    if ((cap->flush_counter % AI_TRAIN_FLUSH_EVERY) == 0) {
        fflush(cap->pcap);
        fflush(cap->labels);
    }

    xSemaphoreGive(g_lock);
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t ai_train_init(void)
{
    if (g_init_done) {
        return ESP_OK;
    }

    if (g_lock == NULL) {
        g_lock = xSemaphoreCreateMutex();
        if (g_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(&g_wifi_cap, 0, sizeof(g_wifi_cap));
    memset(&g_ble_cap, 0, sizeof(g_ble_cap));

    g_mode = AI_TRAIN_MODE_OFF;
    g_init_done = true;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Training capture initialized");
    return ESP_OK;
}

void ai_train_deinit(void)
{
    ai_train_stop();

    if (g_lock != NULL) {
        xSemaphoreTake(g_lock, portMAX_DELAY);
        g_init_done = false;
        xSemaphoreGive(g_lock);
    }

    ESP_LOGI(TAG, "Training capture deinitialized");
}

/* -------------------------------------------------------------------------
 *  Start / stop
 * ----------------------------------------------------------------------- */

esp_err_t ai_train_start(ai_train_mode_t mode)
{
    if (!g_init_done || g_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (mode == AI_TRAIN_MODE_OFF) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!storage_is_ready()) {
        ESP_LOGW(TAG, "SD card not ready; cannot start training capture");
        return ESP_ERR_INVALID_STATE;
    }

    ai_train_stop();

    bool need_wifi = (mode == AI_TRAIN_MODE_WIFI || mode == AI_TRAIN_MODE_BOTH);
    bool need_ble = (mode == AI_TRAIN_MODE_BLE || mode == AI_TRAIN_MODE_BOTH);

    int64_t timestamp = esp_timer_get_time();

    esp_err_t ret = ESP_OK;

    if (need_wifi) {
        ret = capture_open(&g_wifi_cap, "wifi", AI_TRAIN_DLT_IEEE802_11, timestamp);
        if (ret != ESP_OK) {
            goto fail;
        }
    }

    if (need_ble) {
        ret = capture_open(&g_ble_cap, "ble", AI_TRAIN_DLT_USER0, timestamp);
        if (ret != ESP_OK) {
            goto fail;
        }
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    g_mode = mode;
    xSemaphoreGive(g_lock);

    if (need_wifi) {
        capture_activate(&g_wifi_cap);
    }

    if (need_ble) {
        capture_activate(&g_ble_cap);
    }

    ESP_LOGI(TAG, "Training capture started: mode=%s", mode_to_str(mode));
    return ESP_OK;

fail:
    capture_stop(&g_wifi_cap);
    capture_stop(&g_ble_cap);

    xSemaphoreTake(g_lock, portMAX_DELAY);
    g_mode = AI_TRAIN_MODE_OFF;
    xSemaphoreGive(g_lock);

    return ret;
}

esp_err_t ai_train_stop(void)
{
    if (!g_init_done || g_lock == NULL) {
        return ESP_OK;
    }

    ai_train_mode_t mode;

    xSemaphoreTake(g_lock, portMAX_DELAY);
    mode = g_mode;
    g_mode = AI_TRAIN_MODE_OFF;
    xSemaphoreGive(g_lock);

    capture_stop(&g_wifi_cap);
    capture_stop(&g_ble_cap);

    xSemaphoreTake(g_lock, portMAX_DELAY);

    uint32_t wifi_pkts = g_wifi_cap.pkt_count;
    uint32_t wifi_labels = g_wifi_cap.label_count;
    uint32_t wifi_dropped = g_wifi_cap.dropped_count;

    uint32_t ble_pkts = g_ble_cap.pkt_count;
    uint32_t ble_labels = g_ble_cap.label_count;
    uint32_t ble_dropped = g_ble_cap.dropped_count;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG,
             "Training capture stopped: mode=%s wifi=%" PRIu32 "/%" PRIu32
             " ble=%" PRIu32 "/%" PRIu32 " dropped=%" PRIu32,
             mode_to_str(mode),
             wifi_pkts,
             wifi_labels,
             ble_pkts,
             ble_labels,
             wifi_dropped + ble_dropped);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Wi-Fi labeling
 * ----------------------------------------------------------------------- */

esp_err_t ai_train_label_wifi(const uint8_t *mac,
                              const uint8_t *frame,
                              size_t frame_len,
                              uint8_t channel,
                              int8_t rssi,
                              uint64_t timestamp_us)
{
    if (!g_init_done || g_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (frame == NULL || frame_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    train_capture_t *cap = &g_wifi_cap;

    if (!capture_acquire(cap)) {
        return ESP_ERR_INVALID_STATE;
    }

    /*
     * AI labeling happens outside the capture lock.
     */
    ai_classify_result_t cls_res;
    memset(&cls_res, 0, sizeof(cls_res));

    ai_classifier_predict_meta(frame, frame_len, rssi, channel, &cls_res);

    ai_anomaly_result_t anom_res;
    memset(&anom_res, 0, sizeof(anom_res));

    uint16_t len16 = (frame_len > 65535u) ? 65535u : (uint16_t)frame_len;

    if (ai_anomaly_feed(rssi, len16, timestamp_us) == ESP_OK) {
        ai_anomaly_get_result(&anom_res);
    }

    uint8_t derived_mac[6] = {0};
    const uint8_t *use_mac = NULL;

    if (mac != NULL) {
        use_mac = mac;
    } else if (wifi_frame_get_bssid(frame, frame_len, derived_mac)) {
        use_mac = derived_mac;
    }

    bool is_rogue = rogue_check_mac(use_mac);

    ai_train_label_t label;
    memset(&label, 0, sizeof(label));

    label.timestamp_us = timestamp_us;
    label.channel = channel;
    label.rssi = rssi;
    label.pkt_class = (uint8_t)cls_res.cls;
    label.pkt_confidence = cls_res.confidence;
    label.device_class = AI_FP_UNKNOWN;
    label.is_anomaly = anom_res.is_anomaly;
    label.anomaly_score = anom_res.score;
    label.is_rogue = is_rogue;
    label.flags = 0;

    if (use_mac != NULL) {
        memcpy(label.mac, use_mac, 6);
        label.mac_len = 6;
    }

    uint32_t ts_sec = (uint32_t)(timestamp_us / 1000000ULL);
    uint32_t ts_usec = (uint32_t)(timestamp_us % 1000000ULL);

    write_label_to_capture(cap, frame, frame_len, ts_sec, ts_usec, &label);

    capture_release(cap);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  BLE labeling
 * ----------------------------------------------------------------------- */

esp_err_t ai_train_label_ble(const uint8_t *mac,
                             const uint8_t *adv_data,
                             size_t adv_len,
                             int8_t rssi,
                             uint64_t timestamp_us)
{
    if (!g_init_done || g_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (adv_data == NULL || adv_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    train_capture_t *cap = &g_ble_cap;

    if (!capture_acquire(cap)) {
        return ESP_ERR_INVALID_STATE;
    }

    /*
     * Build a minimal ble_info_t for the profiler.
     */
    ble_info_t info;
    memset(&info, 0, sizeof(info));

    if (mac != NULL) {
        memcpy(info.mac, mac, 6);
    }

    info.rssi = rssi;

    ai_ble_profile_t profile;
    memset(&profile, 0, sizeof(profile));

    ai_ble_profiler_classify(&info, adv_data, adv_len, &profile);

    ai_anomaly_result_t anom_res;
    memset(&anom_res, 0, sizeof(anom_res));

    uint16_t len16 = (adv_len > 65535u) ? 65535u : (uint16_t)adv_len;

    if (ai_anomaly_feed(rssi, len16, timestamp_us) == ESP_OK) {
        ai_anomaly_get_result(&anom_res);
    }

    ai_train_label_t label;
    memset(&label, 0, sizeof(label));

    label.timestamp_us = timestamp_us;
    label.channel = 0;
    label.rssi = rssi;
    label.pkt_class = 0;
    label.pkt_confidence = 0.0f;
    label.device_class = (uint8_t)profile.cls;
    label.is_anomaly = anom_res.is_anomaly;
    label.anomaly_score = anom_res.score;
    label.is_rogue = false;
    label.flags = 0;

    if (mac != NULL) {
        memcpy(label.mac, mac, 6);
        label.mac_len = 6;
    }

    uint32_t ts_sec = (uint32_t)(timestamp_us / 1000000ULL);
    uint32_t ts_usec = (uint32_t)(timestamp_us % 1000000ULL);

    write_label_to_capture(cap, adv_data, adv_len, ts_sec, ts_usec, &label);

    capture_release(cap);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Status
 * ----------------------------------------------------------------------- */

ai_train_mode_t ai_train_get_mode(void)
{
    if (g_lock == NULL) {
        return AI_TRAIN_MODE_OFF;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    ai_train_mode_t mode = g_mode;
    xSemaphoreGive(g_lock);

    return mode;
}

esp_err_t ai_train_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    ai_train_mode_t mode;

    bool wifi_active;
    char wifi_pcap[128];
    char wifi_labels[128];
    uint32_t wifi_pkt;
    uint32_t wifi_label;
    uint32_t wifi_drop;

    bool ble_active;
    char ble_pcap[128];
    char ble_labels[128];
    uint32_t ble_pkt;
    uint32_t ble_label;
    uint32_t ble_drop;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    mode = g_mode;

    wifi_active = g_wifi_cap.active;
    snprintf(wifi_pcap, sizeof(wifi_pcap), "%s", g_wifi_cap.pcap_path);
    snprintf(wifi_labels, sizeof(wifi_labels), "%s", g_wifi_cap.label_path);
    wifi_pkt = g_wifi_cap.pkt_count;
    wifi_label = g_wifi_cap.label_count;
    wifi_drop = g_wifi_cap.dropped_count;

    ble_active = g_ble_cap.active;
    snprintf(ble_pcap, sizeof(ble_pcap), "%s", g_ble_cap.pcap_path);
    snprintf(ble_labels, sizeof(ble_labels), "%s", g_ble_cap.label_path);
    ble_pkt = g_ble_cap.pkt_count;
    ble_label = g_ble_cap.label_count;
    ble_drop = g_ble_cap.dropped_count;

    xSemaphoreGive(g_lock);

    int w = snprintf(
        buf,
        bufsz,
        "{\"mode\":\"%s\","
        "\"wifi\":{\"active\":%s,\"pcap\":\"%s\",\"labels\":\"%s\","
        "\"packets\":%" PRIu32 ",\"labels\":%" PRIu32 ",\"dropped\":%" PRIu32 "},"
        "\"ble\":{\"active\":%s,\"pcap\":\"%s\",\"labels\":\"%s\","
        "\"packets\":%" PRIu32 ",\"labels\":%" PRIu32 ",\"dropped\":%" PRIu32 "}}",
        mode_to_str(mode),
        wifi_active ? "true" : "false",
        wifi_pcap,
        wifi_labels,
        wifi_pkt,
        wifi_label,
        wifi_drop,
        ble_active ? "true" : "false",
        ble_pcap,
        ble_labels,
        ble_pkt,
        ble_label,
        ble_drop
    );

    if (w < 0 || (size_t)w >= bufsz) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}
