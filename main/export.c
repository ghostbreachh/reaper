#include "export.h"
#include "storage_sd.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "export";

#define EXPORT_FLUSH_INTERVAL 32

static export_mode_t g_mode = EXPORT_MODE_OFF;
static FILE *g_file = NULL;
static SemaphoreHandle_t g_lock = NULL;

static uint32_t g_packets = 0;
static uint32_t g_bytes = 0;
static uint32_t g_dropped = 0;
static uint32_t g_since_flush = 0;
static char g_path[128] = {0};

/* -------------------------------------------------------------------------
 *  Protocol Structs (Packed for correct binary layout)
 * ----------------------------------------------------------------------- */

typedef struct __attribute__((packed)) {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t byte_order_magic;
    uint16_t major_version;
    uint16_t minor_version;
    int64_t  section_length;
    uint32_t opt_end;
    uint32_t block_total_length_2;
} pcapng_shb_t;

typedef struct __attribute__((packed)) {
    uint32_t block_type;
    uint32_t block_total_length;
    uint16_t linktype;
    uint16_t reserved;
    uint32_t snaplen;
    uint32_t opt_end;
    uint32_t block_total_length_2;
} pcapng_idb_t;

typedef struct __attribute__((packed)) {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t original_len;
} pcapng_epb_hdr_t;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static void close_file_locked(void)
{
    if (g_file != NULL) {
        fclose(g_file);
        g_file = NULL;
    }
    g_since_flush = 0;
}

static void flush_if_needed_locked(void)
{
    if (g_file != NULL) {
        g_since_flush++;
        if (g_since_flush >= EXPORT_FLUSH_INTERVAL) {
            fflush(g_file);
            g_since_flush = 0;
        }
    }
}

static esp_err_t write_pcap_header_locked(void)
{
    pcap_hdr_t hdr = {
        .magic_number = 0xA1B2C3D4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 2304,
        .network = 105 /* DLT_IEEE802_11 */
    };
    
    if (fwrite(&hdr, 1, sizeof(hdr), g_file) != sizeof(hdr)) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static esp_err_t write_pcap_record_locked(const uint8_t *data, size_t len, uint64_t ts_us)
{
    pcaprec_hdr_t rec = {
        .ts_sec = (uint32_t)(ts_us / 1000000),
        .ts_usec = (uint32_t)(ts_us % 1000000),
        .incl_len = (uint32_t)len,
        .orig_len = (uint32_t)len
    };
    
    if (fwrite(&rec, 1, sizeof(rec), g_file) != sizeof(rec)) return ESP_ERR_NO_MEM;
    if (len > 0 && fwrite(data, 1, len, g_file) != len) return ESP_ERR_NO_MEM;
    
    return ESP_OK;
}

static esp_err_t write_pcapng_header_locked(void)
{
    pcapng_shb_t shb = {
        .block_type = 0x0A0D0D0A,
        .block_total_length = sizeof(pcapng_shb_t),
        .byte_order_magic = 0x1A2B3C4D,
        .major_version = 1,
        .minor_version = 0,
        .section_length = -1,
        .opt_end = 0x00000000,
        .block_total_length_2 = sizeof(pcapng_shb_t)
    };
    
    if (fwrite(&shb, 1, sizeof(shb), g_file) != sizeof(shb)) return ESP_ERR_NO_MEM;

    pcapng_idb_t idb = {
        .block_type = 0x00000001,
        .block_total_length = sizeof(pcapng_idb_t),
        .linktype = 105,
        .reserved = 0,
        .snaplen = 2304,
        .opt_end = 0x00000000,
        .block_total_length_2 = sizeof(pcapng_idb_t)
    };
    
    if (fwrite(&idb, 1, sizeof(idb), g_file) != sizeof(idb)) return ESP_ERR_NO_MEM;
    
    return ESP_OK;
}

static esp_err_t write_pcapng_packet_locked(const uint8_t *data, size_t len, uint64_t ts_us)
{
    uint32_t padding = (4 - (len % 4)) % 4;
    uint32_t block_len = sizeof(pcapng_epb_hdr_t) + len + padding + 4; /* +4 for trailing block length */

    pcapng_epb_hdr_t hdr = {
        .block_type = 0x00000006,
        .block_total_length = block_len,
        .interface_id = 0,
        .timestamp_high = (uint32_t)(ts_us >> 32),
        .timestamp_low = (uint32_t)(ts_us & 0xFFFFFFFF),
        .captured_len = (uint32_t)len,
        .original_len = (uint32_t)len
    };

    if (fwrite(&hdr, 1, sizeof(hdr), g_file) != sizeof(hdr)) return ESP_ERR_NO_MEM;
    if (len > 0 && fwrite(data, 1, len, g_file) != len) return ESP_ERR_NO_MEM;
    
    if (padding > 0) {
        uint8_t pad[4] = {0};
        if (fwrite(pad, 1, padding, g_file) != padding) return ESP_ERR_NO_MEM;
    }
    
    if (fwrite(&block_len, 1, 4, g_file) != 4) return ESP_ERR_NO_MEM;
    
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t export_init(void)
{
    if (g_lock != NULL) return ESP_OK;
    
    g_lock = xSemaphoreCreateMutex();
    if (g_lock == NULL) return ESP_ERR_NO_MEM;
    
    g_mode = EXPORT_MODE_OFF;
    g_packets = 0;
    g_bytes = 0;
    g_dropped = 0;
    g_since_flush = 0;
    memset(g_path, 0, sizeof(g_path));
    
    ESP_LOGI(TAG, "Export module initialized");
    return ESP_OK;
}

esp_err_t export_start(export_mode_t mode, const char *base_path)
{
    if (mode == EXPORT_MODE_OFF) return export_stop();
    if (g_lock == NULL) return ESP_ERR_INVALID_STATE;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    close_file_locked();
    g_packets = 0;
    g_bytes = 0;
    g_dropped = 0;
    g_since_flush = 0;
    g_mode = mode;

    snprintf(g_path, sizeof(g_path), "%s", base_path ? base_path : "/sd/export");
    esp_err_t rc = storage_sd_mount();
    
    if (rc != ESP_OK && rc != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "SD mount failed: %s", esp_err_to_name(rc));
        g_mode = EXPORT_MODE_OFF;
        xSemaphoreGive(g_lock);
        return rc;
    }

    g_file = fopen(g_path, "wb");
    if (g_file == NULL) {
        ESP_LOGE(TAG, "Failed to open %s", g_path);
        g_mode = EXPORT_MODE_OFF;
        xSemaphoreGive(g_lock);
        return ESP_ERR_NO_MEM;
    }

    switch (mode) {
        case EXPORT_MODE_PCAP:
            rc = write_pcap_header_locked();
            break;
        case EXPORT_MODE_PCAP_NG:
            rc = write_pcapng_header_locked();
            break;
        case EXPORT_MODE_NETXML:
            fprintf(g_file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<detection-run>\n");
            break;
        case EXPORT_MODE_CSV:
            fprintf(g_file, "ts,channel,rssi,len,data\n");
            break;
        case EXPORT_MODE_JSONL:
            fprintf(g_file, "[");
            break;
        case EXPORT_MODE_ZST:
            fprintf(g_file, "ZSTREAM\n");
            break;
        default:
            rc = ESP_ERR_INVALID_ARG;
            break;
    }

    if (rc != ESP_OK) {
        close_file_locked();
        g_mode = EXPORT_MODE_OFF;
    }
    
    xSemaphoreGive(g_lock);
    return rc;
}

esp_err_t export_stop(void)
{
    if (g_lock == NULL) return ESP_OK;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    if (g_file != NULL) {
        if (g_mode == EXPORT_MODE_NETXML) fprintf(g_file, "</detection-run>\n");
        if (g_mode == EXPORT_MODE_JSONL) fprintf(g_file, "\n]\n");
        if (g_mode == EXPORT_MODE_ZST) fprintf(g_file, "END\n");
        
        fflush(g_file);
        close_file_locked();
    }
    
    export_mode_t prev = g_mode;
    g_mode = EXPORT_MODE_OFF;
    
    ESP_LOGI(TAG, "Export stopped mode=%d packets=%"PRIu32" bytes=%"PRIu32,
             prev, g_packets, g_bytes);
             
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Writers
 * ----------------------------------------------------------------------- */

esp_err_t export_write_packet(const uint8_t *data, size_t len,
                              uint8_t channel, int8_t rssi,
                              uint64_t timestamp_us)
{
    if (g_mode == EXPORT_MODE_OFF || g_lock == NULL) return ESP_ERR_INVALID_STATE;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(50)) != pdTRUE) {
        g_dropped++;
        return ESP_ERR_TIMEOUT;
    }
    
    if (g_file == NULL) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t rc = ESP_OK;
    
    switch (g_mode) {
        case EXPORT_MODE_PCAP:
            rc = write_pcap_record_locked(data, len, timestamp_us);
            break;
        case EXPORT_MODE_PCAP_NG:
            rc = write_pcapng_packet_locked(data, len, timestamp_us);
            break;
        case EXPORT_MODE_CSV:
            fprintf(g_file, "%" PRIu64 ",%u,%d,%zu,", timestamp_us, channel, rssi, len);
            for (size_t i = 0; i < len && i < 64; i++) fprintf(g_file, "%02X", data[i]);
            fprintf(g_file, "\n");
            break;
        case EXPORT_MODE_JSONL:
            if (g_packets > 0) fprintf(g_file, ",\n");
            fprintf(g_file, "{\"ts\":%" PRIu64 ",\"ch\":%u,\"rssi\":%d,\"len\":%zu,\"data\":\"",
                    timestamp_us, channel, rssi, len);
            for (size_t i = 0; i < len && i < 64; i++) fprintf(g_file, "%02X", data[i]);
            fprintf(g_file, "\"}");
            break;
        case EXPORT_MODE_ZST:
            fprintf(g_file, "%" PRIu64 ",%u,%d,%zu,", timestamp_us, channel, rssi, len);
            for (size_t i = 0; i < len && i < 64; i++) fprintf(g_file, "%02X", data[i]);
            fprintf(g_file, "\n");
            break;
        default:
            rc = ESP_ERR_INVALID_STATE;
            break;
    }

    if (rc == ESP_OK) {
        g_packets++;
        g_bytes += (uint32_t)len;
        flush_if_needed_locked();
    }
    
    xSemaphoreGive(g_lock);
    return rc;
}

esp_err_t export_write_event(const char *type, const char *json)
{
    if (g_mode == EXPORT_MODE_OFF || g_lock == NULL || !type || !json) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(50)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
    if (g_file == NULL) {
        xSemaphoreGive(g_lock);
        return ESP_ERR_INVALID_STATE;
    }

    if (g_mode == EXPORT_MODE_JSONL) {
        if (g_packets > 0) fprintf(g_file, ",\n");
        
        /* Safely merge JSON by stripping outer braces if present */
        const char *start = strchr(json, '{');
        const char *end = strrchr(json, '}');
        
        if (start && end && end > start) {
            fprintf(g_file, "{\"type\":\"%s\",%.*s}", type, (int)(end - start - 1), start + 1);
        } else {
            fprintf(g_file, "{\"type\":\"%s\",\"data\":\"%s\"}", type, json);
        }
        flush_if_needed_locked();
    } 
    else if (g_mode == EXPORT_MODE_CSV) {
        fprintf(g_file, "EVENT,%s,%s\n", type, json);
        flush_if_needed_locked();
    } 
    else if (g_mode == EXPORT_MODE_NETXML) {
        fprintf(g_file, "<event type=\"%s\" json=\"%s\"/>\n", type, json);
        flush_if_needed_locked();
    }
    
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Status
 * ----------------------------------------------------------------------- */

esp_err_t export_get_stats(export_stats_t *out)
{
    if (out == NULL || g_lock == NULL) return ESP_ERR_INVALID_ARG;
    
    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    
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
                     "{\"mode\":\"%s\",\"active\":%s,\"packets\":%"PRIu32",\"bytes\":%"PRIu32","
                     "\"dropped\":%"PRIu32",\"path\":\"%s\"}",
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
