#include "ai_training.h"
#include "ai_classifier.h"
#include "ai_fingerprint.h"
#include "ai_ble_profiler.h"
#include "ai_anomaly.h"
#include "ai_rogue_detector.h"
#include "storage_sd.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <inttypes.h>

/* ============================================================================
 *  TRAINING DATA CAPTURE (labeled PCAP export)
 * ============================================================================
 *
 *  Branch A — Full ML pipeline export (model-ready tensors)
 *    Decision: REJECTED. Overkill; PCAP + JSON labels is enough.
 *  Branch B — PCAP + sidecar JSON labels for training
 *    Decision: ACCEPTED. Raw PCAP captures go to /sd/train_*.pcap,
 *              machine-readable labels go to /sd/train_*.json.
 *  Branch C — SPIFFS-only capture
 *    Decision: REJECTED. SD cards provide orders of magnitude more space
 *              for capture datasets.
 */

static const char *TAG = "ai_train";

static ai_train_mode_t g_mode = AI_TRAIN_MODE_OFF;
static bool             g_init_done = false;
static FILE            *g_pcap_file = NULL;
static FILE            *g_label_file = NULL;
static char             g_pcap_path[128] = {0};
static char             g_label_path[128] = {0};
static uint32_t         g_pkt_count = 0;
static uint32_t         g_label_count = 0;
static uint32_t         g_dropped_count = 0;

static bool is_wifi_capture(void)
{
    return g_mode == AI_TRAIN_MODE_WIFI || g_mode == AI_TRAIN_MODE_BOTH;
}

static bool is_ble_capture(void)
{
    return g_mode == AI_TRAIN_MODE_BLE || g_mode == AI_TRAIN_MODE_BOTH;
}

esp_err_t ai_train_init(void)
{
    if (g_init_done) return ESP_OK;

    memset(g_pcap_path, 0, sizeof(g_pcap_path));
    memset(g_label_path, 0, sizeof(g_label_path));
    g_pcap_file = NULL;
    g_label_file = NULL;
    g_mode = AI_TRAIN_MODE_OFF;
    g_pkt_count = g_label_count = g_dropped_count = 0;
    g_init_done = true;
    ESP_LOGI(TAG, "training capture init");
    return ESP_OK;
}

esp_err_t ai_train_start(ai_train_mode_t mode)
{
    if (!g_init_done) return ESP_ERR_INVALID_STATE;
    if (mode == AI_TRAIN_MODE_OFF) return ESP_ERR_INVALID_ARG;

    /* Stop previous capture if any */
    ai_train_stop();

    g_mode = mode;
    int64_t t = esp_timer_get_time();
    snprintf(g_pcap_path, sizeof(g_pcap_path), "/sd/train_%" PRId64 ".pcap", t);
    snprintf(g_label_path, sizeof(g_label_path), "/sd/train_%" PRId64 ".json", t);

    if (!storage_is_ready()) {
        ESP_LOGW(TAG, "SD card not ready; cannot start capture");
        g_mode = AI_TRAIN_MODE_OFF;
        return ESP_ERR_INVALID_STATE;
    }

    g_pcap_file = fopen(g_pcap_path, "wb");
    if (g_pcap_file == NULL) {
        ESP_LOGE(TAG, "failed to open %s", g_pcap_path);
        g_mode = AI_TRAIN_MODE_OFF;
        return ESP_FAIL;
    }

    g_label_file = fopen(g_label_path, "w");
    if (g_label_file == NULL) {
        ESP_LOGE(TAG, "failed to open %s", g_label_path);
        fclose(g_pcap_file);
        g_pcap_file = NULL;
        g_mode = AI_TRAIN_MODE_OFF;
        return ESP_FAIL;
    }

    /* Write PCAP global header */
    uint8_t pcap_hdr[24] = {
        0xd4, 0xc3, 0xb2, 0xa1,  /* magic */
        0x02, 0x00, 0x04, 0x00,  /* version major/minor */
        0x00, 0x00, 0x00, 0x00,  /* thiszone */
        0x00, 0x00, 0x00, 0x00,  /* sigfigs */
        0x00, 0x00, 0x00, 0x00,  /* snaplen (filled below) */
        0x6d, 0x00, 0x00, 0x00   /* network = 109 for WiFi */
    };
    fwrite(pcap_hdr, 1, sizeof(pcap_hdr), g_pcap_file);

    /* Write JSON labels header */
    fprintf(g_label_file, "[\n");

    g_pkt_count = 0;
    g_label_count = 0;
    g_dropped_count = 0;

    ESP_LOGI(TAG, "training capture started: mode=%d pcap=%s labels=%s",
             mode, g_pcap_path, g_label_path);
    return ESP_OK;
}

esp_err_t ai_train_stop(void)
{
    if (g_mode == AI_TRAIN_MODE_OFF) return ESP_OK;

    if (g_label_file != NULL) {
        fprintf(g_label_file, "]\n");
        fclose(g_label_file);
        g_label_file = NULL;
    }
    if (g_pcap_file != NULL) {
        fclose(g_pcap_file);
        g_pcap_file = NULL;
    }

    ESP_LOGI(TAG, "training capture stopped: %u packets, %u labels, %u dropped",
             g_pkt_count, g_label_count, g_dropped_count);
    g_mode = AI_TRAIN_MODE_OFF;
    return ESP_OK;
}

static void write_pcap_record(const uint8_t *data, size_t len,
                              const struct timeval *tv)
{
    if (g_pcap_file == NULL || data == NULL || len == 0 || tv == NULL) return;

    uint8_t rec_hdr[16];
    uint32_t ts_sec = (uint32_t)tv->tv_sec;
    uint32_t ts_usec = (uint32_t)tv->tv_usec;
    uint32_t incl_len = (uint32_t)len;
    uint32_t orig_len = (uint32_t)len;

    memcpy(rec_hdr + 0, &ts_sec, 4);
    memcpy(rec_hdr + 4, &ts_usec, 4);
    memcpy(rec_hdr + 8, &incl_len, 4);
    memcpy(rec_hdr + 12, &orig_len, 4);

    fwrite(rec_hdr, 1, 16, g_pcap_file);
    fwrite(data, 1, len, g_pcap_file);
    g_pkt_count++;
}

static void write_label(const ai_train_label_t *label)
{
    if (g_label_file == NULL || label == NULL) return;

    fprintf(g_label_file,
        "{\"ts\":%" PRIu64 ",\"ch\":%d,\"rssi\":%d,"
        "\"pkt_cls\":%d,\"pkt_conf\":%.2f,"
        "\"dev_cls\":%d,\"anomaly\":%s,\"anom_score\":%.4f,"
        "\"rogue\":%s,\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\"%s}\n",
        label->timestamp_us,
        label->channel,
        (int)label->rssi,
        label->pkt_class,
        (double)label->pkt_confidence,
        label->device_class,
        label->is_anomaly ? "true" : "false",
        (double)label->anomaly_score,
        label->is_rogue ? "true" : "false",
        label->mac[0], label->mac[1], label->mac[2],
        label->mac[3], label->mac[4], label->mac[5],
        g_label_count > 0 ? "," : ""
    );
    g_label_count++;
}

esp_err_t ai_train_label_wifi(const uint8_t *mac, const uint8_t *frame,
                              size_t frame_len, uint8_t channel,
                              int8_t rssi, uint64_t timestamp_us)
{
    if (!is_wifi_capture() || g_pcap_file == NULL || g_label_file == NULL) {
        g_dropped_count++;
        return ESP_ERR_INVALID_STATE;
    }

    ai_classify_result_t cls_res;
    ai_classifier_predict(frame, frame_len, &cls_res);

    ai_anomaly_result_t anom_res;
    ai_anomaly_feed(rssi, (uint16_t)frame_len, timestamp_us);
    ai_anomaly_get_result(&anom_res);

    bool is_rogue = false;
    if (ai_rogue_detector_alert_count() > 0) {
        ai_rogue_alert_t alert;
        if (ai_rogue_detector_get_alert(0, &alert) == ESP_OK) {
            is_rogue = true;
        }
    }

    write_pcap_record(frame, frame_len,
                      &(struct timeval){timestamp_us / 1000000,
                                        (int)(timestamp_us % 1000000)});

    ai_train_label_t label;
    memset(&label, 0, sizeof(label));
    label.timestamp_us = timestamp_us;
    label.channel = channel;
    label.rssi = rssi;
    label.pkt_class = cls_res.cls;
    label.pkt_confidence = cls_res.confidence;
    label.device_class = AI_FP_UNKNOWN;
    label.is_anomaly = anom_res.is_anomaly;
    label.anomaly_score = anom_res.score;
    label.is_rogue = is_rogue;
    if (mac) { memcpy(label.mac, mac, 6); label.mac_len = 6; }
    write_label(&label);

    return ESP_OK;
}

esp_err_t ai_train_label_ble(const uint8_t *mac, const uint8_t *adv_data,
                             size_t adv_len, int8_t rssi,
                             uint64_t timestamp_us)
{
    if (!is_ble_capture() || g_pcap_file == NULL || g_label_file == NULL) {
        g_dropped_count++;
        return ESP_ERR_INVALID_STATE;
    }

    ai_ble_profile_t profile;
    ai_ble_profiler_classify(mac, adv_data, adv_len, &profile);

    ai_anomaly_result_t anom_res;
    ai_anomaly_feed(rssi, (uint16_t)adv_len, timestamp_us);
    ai_anomaly_get_result(&anom_res);

    write_pcap_record(adv_data, adv_len,
                      &(struct timeval){timestamp_us / 1000000,
                                        (int)(timestamp_us % 1000000)});

    ai_train_label_t label;
    memset(&label, 0, sizeof(label));
    label.timestamp_us = timestamp_us;
    label.channel = 0;
    label.rssi = rssi;
    label.pkt_class = 0;
    label.pkt_confidence = 0.0f;
    label.device_class = profile.cls;
    label.is_anomaly = anom_res.is_anomaly;
    label.anomaly_score = anom_res.score;
    label.is_rogue = false;
    if (mac) { memcpy(label.mac, mac, 6); label.mac_len = 6; }
    write_label(&label);

    return ESP_OK;
}

ai_train_mode_t ai_train_get_mode(void)
{
    return g_mode;
}

esp_err_t ai_train_json(char *buf, size_t bufsz)
{
    const char *mode_str = "off";
    switch (g_mode) {
        case AI_TRAIN_MODE_WIFI:  mode_str = "wifi"; break;
        case AI_TRAIN_MODE_BLE:   mode_str = "ble"; break;
        case AI_TRAIN_MODE_BOTH:  mode_str = "both"; break;
        default:                  mode_str = "off"; break;
    }

    int w = snprintf(buf, bufsz,
        "{\"mode\":\"%s\",\"pcap\":\"%s\",\"labels\":\"%s\","
        "\"packets\":%lu,\"labels_written\":%lu,\"dropped\":%lu}",
        mode_str,
        g_pcap_path,
        g_label_path,
        (unsigned long)g_pkt_count,
        (unsigned long)g_label_count,
        (unsigned long)g_dropped_count);
    if (w < 0 || (size_t)w >= bufsz) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

void ai_train_deinit(void)
{
    ai_train_stop();
    g_init_done = false;
    g_pkt_count = g_label_count = g_dropped_count = 0;
    ESP_LOGI(TAG, "training capture deinit");
}
