#include "export.h"
#include "pcap_ring.h"
#include "storage_sd.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_timer.h"
#include "esp_system.h"

static const char *TAG = "export";

static export_mode_t g_mode = EXPORT_MODE_OFF;
static FILE *g_file = NULL;
static SemaphoreHandle_t g_lock;
static uint32_t g_packets;
static uint32_t g_bytes;
static uint32_t g_dropped;
static char g_path[128];
static uint64_t g_start_us;

/* PCAP-NG block types */
#define PCAPNG_BTYPE_SHB 0x0A0D0D0A
#define PCAPNG_BTYPE_IDB 0x00000001
#define PCAPNG_BTYPE_EPB 0x00000006

static void close_file(void)
{
    if (g_file != NULL) {
        fclose(g_file);
        g_file = NULL;
    }
}

static uint32_t crc32c(const uint8_t *buf, size_t len)
{
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) crc = (crc >> 1) ^ 0x82F63B78;
            else crc >>= 1;
        }
    }
    return crc ^ 0xFFFFFFFF;
}

static esp_err_t write_pcap_ng_header(void)
{
    uint8_t shb[64] = {0};
    shb[0] = 0x0A; shb[1] = 0x0D; shb[2] = 0x0D; shb[3] = 0x0A;
    shb[4] = 0x00; shb[5] = 0x00; shb[6] = 0x00; shb[7] = 0x01;
    shb[8] = 0xFF; shb[9] = 0xFF; shb[10] = 0xFF; shb[11] = 0xFF;
    shb[12] = 0x00; shb[13] = 0x00; shb[14] = 0x00; shb[15] = 0x01;
    /* Section length = -1 */
    memset(shb + 16, 0xFF, 4);
    /* UTF-8 "REAPER" */
    const char *shb_options = "REAPER";
    memcpy(shb + 20, shb_options, 6);
    uint32_t block_total_len = 32 + 16;
    memcpy(shb + 28, &block_total_len, 4);
    memcpy(shb + 32, &block_total_len, 4);

    if (fwrite(shb, 1, 48, g_file) != 48) return ESP_ERR_NO_MEM;

    /* Interface Description Block: DLT=105 (802.11), 2304 snaplen */
    uint8_t idb[24] = {0};
    memcpy(idb, &(uint32_t){PCAPNG_BTYPE_IDB}, 4);
    uint32_t idb_len = 24;
    memcpy(idb + 4, &idb_len, 4);
    memset(idb + 8, 0, 4); /* reserved */
    uint16_t dlt = 105;
    memcpy(idb + 12, &dlt, 2);
    uint16_t snaplen = 2304;
    memcpy(idb + 14, &snaplen, 2);
    memcpy(idb + 16, &idb_len, 4);
    memcpy(idb + 20, &idb_len, 4);
    return fwrite(idb, 1, 24, g_file) == 24 ? ESP_OK : ESP_ERR_NO_MEM;
}

static esp_err_t write_pcap_ng_packet(const uint8_t *data, size_t len,
                                      uint8_t channel, int8_t rssi,
                                      uint64_t ts_us)
{
    uint32_t iface = 0;
    uint32_t ts_sec = (uint32_t)(ts_us / 1000000);
    uint32_t ts_frac = (uint32_t)((ts_us % 1000000) * 65536 / 1000000);
    uint32_t captured = (len > 2304) ? 2304 : (uint32_t)len;
    uint32_t orig_len = (uint32_t)len;

    uint16_t epb_hdr = 12 + 4 + 4 + 4 + 2 + 2 + 4 + 4;
    uint16_t padding = (4 - (epb_hdr + captured) % 4) % 4;
    uint32_t block_len = epb_hdr + captured + padding + 12;

    uint8_t epb[16 + captured + padding + 12];
    memcpy(epb, &(uint32_t){PCAPNG_BTYPE_EPB}, 4);
    memcpy(epb + 4, &block_len, 4);
    memcpy(epb + 8, &iface, 4);
    memcpy(epb + 12, &ts_sec, 4);
    memcpy(epb + 16, &ts_frac, 4);
    memcpy(epb + 20, &captured, 4);
    memcpy(epb + 24, &orig_len, 4);
    memcpy(epb + 28, &channel, 1);
    memcpy(epb + 29, &rssi, 1);
    memset(epb + 30, 0, 2);
    memcpy(epb + 32, data, captured);
    if (padding) memset(epb + 32 + captured, 0, padding);
    memcpy(epb + 32 + captured + padding, &block_len, 4);

    if (fwrite(epb, 1, block_len, g_file) != block_len) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

static esp_err_t write_pcap_header(void)
{
    uint8_t hdr[24] = {0};
    hdr[0] = 0xD4; hdr[1] = 0xC3; hdr[2] = 0xB2; hdr[3] = 0xA1;
    hdr[4] = 0x02; hdr[5] = 0x00; hdr[6] = 0x04; hdr[7] = 0x00;
    uint32_t ts_sec = (uint32_t)(g_start_us / 1000000);
    uint32_t ts_usec = (uint32_t)(g_start_us % 1000000);
    memcpy(hdr + 8, &ts_sec, 4);
    memcpy(hdr + 12, &ts_usec, 4);
    uint32_t snaplen = 2304;
    memcpy(hdr + 20, &snaplen, 4);
    uint16_t dlt = 105;
    memcpy(hdr + 22, &dlt, 2);
    return fwrite(hdr, 1, 24, g_file) == 24 ? ESP_OK : ESP_ERR_NO_MEM;
}

static esp_err_t write_pcap_record(const uint8_t *data, size_t len,
                                   uint8_t channel, int8_t rssi,
                                   uint64_t ts_us)
{
    uint32_t ts_sec = (uint32_t)(ts_us / 1000000);
    uint32_t ts_usec = (uint32_t)(ts_us % 1000000);
    uint32_t captured = (len > 2304) ? 2304 : (uint32_t)len;
    uint32_t orig_len = (uint32_t)len;

    uint8_t rec[16 + 2304];
    memcpy(rec, &ts_sec, 4);
    memcpy(rec + 4, &ts_usec, 4);
    memcpy(rec + 8, &captured, 4);
    memcpy(rec + 12, &orig_len, 4);
    if (captured > 0) memcpy(rec + 16, data, captured);
    size_t total = 16 + captured;
    if (total % 2) total++;
    if (fwrite(rec, 1, total, g_file) != total) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

static esp_err_t write_netxml_open(const char *path)
{
    g_file = fopen(path, "w");
    if (g_file == NULL) return ESP_ERR_NO_MEM;
    fprintf(g_file,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<!DOCTYPE detection-run SYSTEM \"http://www.kismet.org/dtd/detection-run-1.1.dtd\">\n"
            "<detection-run>\n");
    fflush(g_file);
    return ESP_OK;
}

static esp_err_t write_netxml_ap(const uint8_t *bssid, const char *ssid,
                                 int8_t rssi, uint8_t channel)
{
    if (g_file == NULL) return ESP_ERR_INVALID_STATE;
    fprintf(g_file,
            "<wireless-network type=\"infrastructure\">\n"
            "  <SSID essid=\"%s\"/>\n"
            "  <BSSID>%02X:%02X:%02X:%02X:%02X:%02X</BSSID>\n"
            "  <channel>%u</channel>\n"
            "  <signal>%d</signal>\n"
            "</wireless-network>\n",
            ssid ? ssid : "",
            bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
            (unsigned)channel, (int)rssi);
    fflush(g_file);
    return ESP_OK;
}

static esp_err_t write_netxml_close(void)
{
    if (g_file == NULL) return ESP_ERR_INVALID_STATE;
    fprintf(g_file, "</detection-run>\n");
    fflush(g_file);
    return ESP_OK;
}

esp_err_t export_init(void)
{
    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) return ESP_ERR_NO_MEM;
    g_mode = EXPORT_MODE_OFF;
    g_packets = 0;
    g_bytes = 0;
    g_dropped = 0;
    memset(g_path, 0, sizeof(g_path));
    ESP_LOGI(TAG, "export init");
    return ESP_OK;
}

esp_err_t export_start(export_mode_t mode, const char *base_path)
{
    if (mode == EXPORT_MODE_OFF) return export_stop();
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    close_file();
    g_packets = 0;
    g_bytes = 0;
    g_dropped = 0;
    g_start_us = esp_timer_get_time();
    g_mode = mode;

    snprintf(g_path, sizeof(g_path), "%s", base_path);
    esp_err_t rc = ESP_OK;

    switch (mode) {
        case EXPORT_MODE_PCAP:
            rc = storage_sd_mount();
            if (rc == ESP_OK) {
                g_file = fopen(g_path, "w");
                if (g_file == NULL) { rc = ESP_ERR_NO_MEM; break; }
                rc = write_pcap_header();
            }
            break;
        case EXPORT_MODE_PCAP_NG:
            rc = storage_sd_mount();
            if (rc == ESP_OK) {
                g_file = fopen(g_path, "w");
                if (g_file == NULL) { rc = ESP_ERR_NO_MEM; break; }
                rc = write_pcap_ng_header();
            }
            break;
        case EXPORT_MODE_NETXML:
            rc = storage_sd_mount();
            if (rc == ESP_OK) rc = write_netxml_open(g_path);
            break;
        case EXPORT_MODE_CSV:
            rc = storage_sd_mount();
            if (rc == ESP_OK) {
                g_file = fopen(g_path, "w");
                if (g_file == NULL) { rc = ESP_ERR_NO_MEM; break; }
                fprintf(g_file, "ts,channel,rssi,len,data\n");
                fflush(g_file);
            }
            break;
        case EXPORT_MODE_JSONL:
            rc = storage_sd_mount();
            if (rc == ESP_OK) {
                g_file = fopen(g_path, "w");
                if (g_file == NULL) { rc = ESP_ERR_NO_MEM; break; }
                fprintf(g_file, "[");
                fflush(g_file);
            }
            break;
        case EXPORT_MODE_ZST:
            rc = storage_sd_mount();
            if (rc == ESP_OK) {
                g_file = fopen(g_path, "w");
                if (g_file == NULL) { rc = ESP_ERR_NO_MEM; break; }
                fprintf(g_file, "ZSTREAM\n");
                fflush(g_file);
            }
            break;
        default:
            rc = ESP_ERR_INVALID_ARG;
            break;
    }

    if (rc != ESP_OK) {
        close_file();
        g_mode = EXPORT_MODE_OFF;
        memset(g_path, 0, sizeof(g_path));
    }
    xSemaphoreGive(g_lock);
    return rc;
}

esp_err_t export_stop(void)
{
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    if (g_file != NULL) {
        if (g_mode == EXPORT_MODE_NETXML) write_netxml_close();
        if (g_mode == EXPORT_MODE_JSONL) {
            fprintf(g_file, "]\n");
            fflush(g_file);
        }
        if (g_mode == EXPORT_MODE_ZST) {
            fprintf(g_file, "END\n");
            fflush(g_file);
        }
        close_file();
    }
    export_mode_t prev = g_mode;
    g_mode = EXPORT_MODE_OFF;
    ESP_LOGI(TAG, "export stop mode=%d packets=%u bytes=%u",
             prev, g_packets, g_bytes);
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t export_write_packet(const uint8_t *data, size_t len,
                              uint8_t channel, int8_t rssi,
                              uint64_t timestamp_us)
{
    if (g_mode == EXPORT_MODE_OFF || g_file == NULL) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(50)) != pdTRUE) {
        g_dropped++;
        return ESP_ERR_TIMEOUT;
    }

    esp_err_t rc = ESP_OK;
    switch (g_mode) {
        case EXPORT_MODE_PCAP:
            rc = write_pcap_record(data, len, channel, rssi, timestamp_us);
            break;
        case EXPORT_MODE_PCAP_NG:
            rc = write_pcap_ng_packet(data, len, channel, rssi, timestamp_us);
            break;
        case EXPORT_MODE_CSV: {
            fprintf(g_file, "%" PRIu64 ",%u,%d,%zu,", timestamp_us,
                    (unsigned)channel, (int)rssi, len);
            for (size_t i = 0; i < len && i < 64; i++) {
                fprintf(g_file, "%02X", data[i]);
            }
            fprintf(g_file, "\n");
            fflush(g_file);
            break;
        }
        case EXPORT_MODE_JSONL: {
            if (g_packets > 0) fprintf(g_file, ",");
            fprintf(g_file,
                    "\n{\"ts\":%" PRIu64 ",\"ch\":%u,\"rssi\":%d,\"len\":%zu,",
                    timestamp_us, (unsigned)channel, (int)rssi, len);
            fprintf(g_file, "\"data\":\"");
            for (size_t i = 0; i < len && i < 64; i++) {
                fprintf(g_file, "%02X", data[i]);
            }
            fprintf(g_file, "\"}");
            fflush(g_file);
            break;
        }
        case EXPORT_MODE_ZST: {
            /* Streaming zstd: raw hex for compatibility */
            fprintf(g_file, "%" PRIu64 ",%u,%d,%zu,",
                    timestamp_us, (unsigned)channel, (int)rssi, len);
            for (size_t i = 0; i < len && i < 64; i++) {
                fprintf(g_file, "%02X", data[i]);
            }
            fprintf(g_file, "\n");
            fflush(g_file);
            break;
        }
        default:
            rc = ESP_ERR_INVALID_STATE;
            break;
    }

    if (rc == ESP_OK) {
        g_packets++;
        g_bytes += (uint32_t)len;
    }
    xSemaphoreGive(g_lock);
    return rc;
}

esp_err_t export_write_event(const char *type, const char *json)
{
    if (g_mode == EXPORT_MODE_OFF || g_file == NULL) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(50)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    if (g_mode == EXPORT_MODE_JSONL) {
        if (g_packets > 0) fprintf(g_file, ",");
        fprintf(g_file, "\n{\"type\":\"%s\",%s", type, json + (json[0] == '{' ? 1 : 0));
        fprintf(g_file, "\"}");
        fflush(g_file);
    } else if (g_mode == EXPORT_MODE_CSV) {
        fprintf(g_file, "EVENT,%s,%s\n", type, json);
        fflush(g_file);
    } else if (g_mode == EXPORT_MODE_NETXML) {
        fprintf(g_file, "<event type=\"%s\" json=\"%s\"/>\n", type, json);
        fflush(g_file);
    }
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t export_get_stats(export_stats_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    out->mode = g_mode;
    out->active = (g_file != NULL);
    out->packets_written = g_packets;
    out->bytes_written = g_bytes;
    out->dropped = g_dropped;
    snprintf(out->path, sizeof(out->path), "%s", g_path);
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

esp_err_t export_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) return ESP_ERR_INVALID_ARG;
    export_stats_t st;
    esp_err_t rc = export_get_stats(&st);
    if (rc != ESP_OK) return rc;
    const char *mode_str =
        st.mode == EXPORT_MODE_PCAP ? "pcap" :
        st.mode == EXPORT_MODE_PCAP_NG ? "pcapng" :
        st.mode == EXPORT_MODE_NETXML ? "netxml" :
        st.mode == EXPORT_MODE_CSV ? "csv" :
        st.mode == EXPORT_MODE_JSONL ? "jsonl" :
        st.mode == EXPORT_MODE_ZST ? "zstd" : "off";
    int n = snprintf(buf, bufsz,
                     "{\"mode\":\"%s\",\"active\":%s,\"packets\":%u,\"bytes\":%u,"
                     "\"dropped\":%u,\"path\":\"%s\"}",
                     mode_str, st.active ? "true" : "false",
                     st.packets_written, st.bytes_written,
                     st.dropped, st.path);
    return (n < 0 || (size_t)n >= bufsz) ? ESP_ERR_NO_MEM : ESP_OK;
}

export_mode_t export_get_mode(void)
{
    return g_mode;
}

esp_err_t export_deinit(void)
{
    export_stop();
    if (g_lock != NULL) {
        vSemaphoreDelete(g_lock);
        g_lock = NULL;
    }
    return ESP_OK;
}
