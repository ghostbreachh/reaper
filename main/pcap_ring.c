/*
 * ============================================================================
 *  pcap_ring.c  —  Circular PCAP capture buffer with binary framing
 * ============================================================================
 *
 * Frame layout:
 *
 *   [uint32_t total_len][uint32_t crc32][pcaprec_hdr_t][payload]
 *
 * total_len includes the entire frame:
 *
 *   total_len = 4 + 4 + sizeof(pcaprec_hdr_t) + payload_len
 *
 * CRC32 is computed over:
 *
 *   pcaprec_hdr_t + payload
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdatomic.h>
#include <sys/time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"

#include "pcap_ring.h"
#include "storage_sd.h"

static const char *TAG = "pcap_ring";

#define PCAP_RING_DEFAULT_SIZE      (2u * 1024u * 1024u)
#define PCAP_EXPORT_CHUNK_SIZE      256u

#ifndef ESP_ERR_INVALID_CRC
#define ESP_ERR_INVALID_CRC ESP_ERR_INVALID_ARG
#endif

static uint8_t *g_pcap_ring_buf = NULL;
static size_t g_pcap_ring_capacity = 0;
static size_t g_pcap_ring_used = 0;
static size_t g_pcap_ring_head = 0;
static size_t g_pcap_ring_tail = 0;

static atomic_bool g_pcap_ring_active = ATOMIC_VAR_INIT(false);

static uint32_t g_pcap_ring_packets = 0;
static uint32_t g_pcap_ring_dropped_packets = 0;
static uint32_t g_pcap_ring_dropped_bytes = 0;

static SemaphoreHandle_t g_pcap_ring_mutex = NULL;

/* -------------------------------------------------------------------------
 *  CRC32
 * ----------------------------------------------------------------------- */

static uint32_t crc32_update_raw(uint32_t crc, const uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return crc;
    }

    for (size_t i = 0; i < len; i++) {
        crc ^= (uint32_t)buf[i];

        for (int j = 0; j < 8; j++) {
            if (crc & 1u) {
                crc = (crc >> 1) ^ 0xEDB88320u;
            } else {
                crc >>= 1;
            }
        }
    }

    return crc;
}

uint32_t pcap_ring_frame_crc32(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return 0;
    }

    uint32_t crc = 0xFFFFFFFFu;
    crc = crc32_update_raw(crc, buf, len);
    return crc ^ 0xFFFFFFFFu;
}

static uint32_t crc32_ring(size_t offset, size_t len)
{
    uint8_t chunk[PCAP_EXPORT_CHUNK_SIZE];
    uint32_t crc = 0xFFFFFFFFu;

    size_t done = 0;

    while (done < len) {
        size_t n = len - done;
        if (n > sizeof(chunk)) {
            n = sizeof(chunk);
        }

        pcap_ring_read_bytes_at(offset + done, chunk, n);
        crc = crc32_update_raw(crc, chunk, n);

        done += n;
    }

    return crc ^ 0xFFFFFFFFu;
}

/* -------------------------------------------------------------------------
 *  Ring primitives
 * ----------------------------------------------------------------------- */

static void pcap_ring_write_bytes(const uint8_t *src, size_t len)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0 ||
        src == NULL || len == 0) {
        return;
    }

    size_t first = (g_pcap_ring_capacity - g_pcap_ring_tail < len)
                       ? (g_pcap_ring_capacity - g_pcap_ring_tail)
                       : len;

    if (first > 0) {
        memcpy(g_pcap_ring_buf + g_pcap_ring_tail, src, first);
    }

    if (len > first) {
        memcpy(g_pcap_ring_buf, src + first, len - first);
    }

    g_pcap_ring_tail = (g_pcap_ring_tail + len) % g_pcap_ring_capacity;
}

static void pcap_ring_write_u32(uint32_t v)
{
    uint8_t bytes[4] = {
        (uint8_t)(v & 0xFFu),
        (uint8_t)((v >> 8) & 0xFFu),
        (uint8_t)((v >> 16) & 0xFFu),
        (uint8_t)((v >> 24) & 0xFFu),
    };

    pcap_ring_write_bytes(bytes, sizeof(bytes));
}

static void pcap_ring_read_bytes_at(size_t offset, uint8_t *dst, size_t len)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0 ||
        dst == NULL || len == 0) {
        return;
    }

    offset %= g_pcap_ring_capacity;

    size_t first = (g_pcap_ring_capacity - offset < len)
                       ? (g_pcap_ring_capacity - offset)
                       : len;

    if (first > 0) {
        memcpy(dst, g_pcap_ring_buf + offset, first);
    }

    if (len > first) {
        memcpy(dst + first, g_pcap_ring_buf, len - first);
    }
}

static uint32_t pcap_ring_read_u32_at(size_t offset)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        return 0;
    }

    uint8_t bytes[4] = {0};
    pcap_ring_read_bytes_at(offset, bytes, sizeof(bytes));

    return ((uint32_t)bytes[0]) |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static void pcap_ring_reset_counters_locked(void)
{
    g_pcap_ring_used = 0;
    g_pcap_ring_head = 0;
    g_pcap_ring_tail = 0;
    g_pcap_ring_packets = 0;
    g_pcap_ring_dropped_packets = 0;
    g_pcap_ring_dropped_bytes = 0;
}

/* -------------------------------------------------------------------------
 *  Space management
 * ----------------------------------------------------------------------- */

static bool pcap_ring_make_room(size_t needed)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        return false;
    }

    if (needed > g_pcap_ring_capacity) {
        return false;
    }

    while (g_pcap_ring_used + needed > g_pcap_ring_capacity &&
           g_pcap_ring_used > 0) {

        uint32_t total_len = pcap_ring_read_u32_at(g_pcap_ring_head);

        if (total_len < PCAP_FRAME_MIN_LEN ||
            total_len > g_pcap_ring_used ||
            total_len > g_pcap_ring_capacity) {

            ESP_LOGW(TAG, "Ring corruption detected; wiping ring");

            g_pcap_ring_dropped_bytes += (uint32_t)g_pcap_ring_used;
            g_pcap_ring_dropped_packets++;

            g_pcap_ring_head = 0;
            g_pcap_ring_tail = 0;
            g_pcap_ring_used = 0;
            break;
        }

        g_pcap_ring_head = (g_pcap_ring_head + total_len) % g_pcap_ring_capacity;
        g_pcap_ring_used -= total_len;

        g_pcap_ring_dropped_packets++;
        g_pcap_ring_dropped_bytes += total_len;
    }

    return g_pcap_ring_used + needed <= g_pcap_ring_capacity;
}

/* -------------------------------------------------------------------------
 *  Frame helpers
 * ----------------------------------------------------------------------- */

esp_err_t pcap_ring_build_frame(uint8_t *out, size_t out_sz,
                                const uint8_t *payload, size_t payload_len,
                                const struct timeval *tv)
{
    if (out == NULL || out_sz == 0 ||
        payload == NULL || payload_len == 0 ||
        tv == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (payload_len > PCAP_RING_MAX_PAYLOAD) {
        return ESP_ERR_INVALID_SIZE;
    }

    size_t total_len = sizeof(uint32_t) +
                       sizeof(uint32_t) +
                       sizeof(pcaprec_hdr_t) +
                       payload_len;

    if (total_len > out_sz) {
        return ESP_ERR_NO_MEM;
    }

    pcaprec_hdr_t rec = {
        .ts_sec = (uint32_t)tv->tv_sec,
        .ts_usec = (uint32_t)tv->tv_usec,
        .incl_len = (uint32_t)payload_len,
        .orig_len = (uint32_t)payload_len,
    };

    /* total_len */
    out[0] = (uint8_t)(total_len & 0xFFu);
    out[1] = (uint8_t)((total_len >> 8) & 0xFFu);
    out[2] = (uint8_t)((total_len >> 16) & 0xFFu);
    out[3] = (uint8_t)((total_len >> 24) & 0xFFu);

    /* pcap record + payload */
    memcpy(out + PCAP_FRAME_HDR_OFFSET, &rec, sizeof(rec));
    memcpy(out + PCAP_FRAME_HDR_OFFSET + sizeof(rec), payload, payload_len);

    /* CRC over record + payload */
    uint32_t crc = pcap_ring_frame_crc32(out + PCAP_FRAME_HDR_OFFSET,
                                         sizeof(rec) + payload_len);

    out[PCAP_FRAME_CRC_OFFSET + 0] = (uint8_t)(crc & 0xFFu);
    out[PCAP_FRAME_CRC_OFFSET + 1] = (uint8_t)((crc >> 8) & 0xFFu);
    out[PCAP_FRAME_CRC_OFFSET + 2] = (uint8_t)((crc >> 16) & 0xFFu);
    out[PCAP_FRAME_CRC_OFFSET + 3] = (uint8_t)((crc >> 24) & 0xFFu);

    return ESP_OK;
}

esp_err_t pcap_ring_parse_frame(const uint8_t *buf, size_t buf_len,
                                const uint8_t **out_payload,
                                size_t *out_payload_len,
                                uint32_t *out_crc)
{
    if (buf == NULL ||
        buf_len < PCAP_FRAME_MIN_LEN ||
        out_payload == NULL ||
        out_payload_len == NULL ||
        out_crc == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t total_len = ((uint32_t)buf[0]) |
                         ((uint32_t)buf[1] << 8) |
                         ((uint32_t)buf[2] << 16) |
                         ((uint32_t)buf[3] << 24);

    if (total_len < PCAP_FRAME_MIN_LEN || total_len > buf_len) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint32_t stored_crc = ((uint32_t)buf[PCAP_FRAME_CRC_OFFSET + 0]) |
                          ((uint32_t)buf[PCAP_FRAME_CRC_OFFSET + 1] << 8) |
                          ((uint32_t)buf[PCAP_FRAME_CRC_OFFSET + 2] << 16) |
                          ((uint32_t)buf[PCAP_FRAME_CRC_OFFSET + 3] << 24);

    uint32_t calc_crc = pcap_ring_frame_crc32(buf + PCAP_FRAME_HDR_OFFSET,
                                              total_len - PCAP_FRAME_HDR_OFFSET);

    *out_crc = stored_crc;

    if (stored_crc != calc_crc) {
        return ESP_ERR_INVALID_CRC;
    }

    pcaprec_hdr_t rec;
    memcpy(&rec, buf + PCAP_FRAME_HDR_OFFSET, sizeof(rec));

    uint32_t payload_len = total_len - PCAP_FRAME_HDR_OFFSET - sizeof(rec);

    if (rec.incl_len != payload_len || rec.orig_len != payload_len) {
        return ESP_ERR_INVALID_SIZE;
    }

    *out_payload = buf + PCAP_FRAME_HDR_OFFSET + sizeof(rec);
    *out_payload_len = payload_len;

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Store path
 * ----------------------------------------------------------------------- */

esp_err_t pcap_ring_store(const uint8_t *data, size_t len, const struct timeval *tv)
{
    if (!atomic_load(&g_pcap_ring_active) ||
        g_pcap_ring_buf == NULL ||
        g_pcap_ring_capacity == 0 ||
        g_pcap_ring_mutex == NULL ||
        data == NULL ||
        len == 0 ||
        tv == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (len > PCAP_RING_MAX_PAYLOAD) {
        return ESP_ERR_INVALID_SIZE;
    }

    pcaprec_hdr_t rec = {
        .ts_sec = (uint32_t)tv->tv_sec,
        .ts_usec = (uint32_t)tv->tv_usec,
        .incl_len = (uint32_t)len,
        .orig_len = (uint32_t)len,
    };

    uint32_t total_len = (uint32_t)(sizeof(uint32_t) +
                                    sizeof(uint32_t) +
                                    sizeof(rec) +
                                    len);

    if (total_len > g_pcap_ring_capacity) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint32_t crc = 0xFFFFFFFFu;
    crc = crc32_update_raw(crc, (const uint8_t *)&rec, sizeof(rec));
    crc = crc32_update_raw(crc, data, len);
    crc ^= 0xFFFFFFFFu;

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);

    if (!atomic_load(&g_pcap_ring_active) ||
        g_pcap_ring_buf == NULL ||
        g_pcap_ring_capacity == 0) {
        xSemaphoreGive(g_pcap_ring_mutex);
        return ESP_ERR_INVALID_STATE;
    }

    if (!pcap_ring_make_room(total_len)) {
        g_pcap_ring_dropped_packets++;
        g_pcap_ring_dropped_bytes += total_len;
        xSemaphoreGive(g_pcap_ring_mutex);
        return ESP_ERR_NO_MEM;
    }

    pcap_ring_write_u32(total_len);
    pcap_ring_write_u32(crc);
    pcap_ring_write_bytes((const uint8_t *)&rec, sizeof(rec));
    pcap_ring_write_bytes(data, len);

    g_pcap_ring_used += total_len;
    g_pcap_ring_packets++;

    xSemaphoreGive(g_pcap_ring_mutex);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t pcap_ring_init(size_t size_bytes)
{
    if (g_pcap_ring_mutex == NULL) {
        g_pcap_ring_mutex = xSemaphoreCreateMutex();
        if (g_pcap_ring_mutex == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    if (size_bytes == 0) {
        size_bytes = PCAP_RING_DEFAULT_SIZE;
    }

    if (size_bytes < PCAP_FRAME_MIN_LEN + 128) {
        size_bytes = PCAP_FRAME_MIN_LEN + 128;
    }

    atomic_store(&g_pcap_ring_active, false);

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);

    if (g_pcap_ring_buf != NULL && g_pcap_ring_capacity >= size_bytes) {
        pcap_ring_reset_counters_locked();
        xSemaphoreGive(g_pcap_ring_mutex);
        ESP_LOGI(TAG, "PCAP ring reused (%zu bytes)", g_pcap_ring_capacity);
        return ESP_OK;
    }

    if (g_pcap_ring_buf != NULL) {
        heap_caps_free(g_pcap_ring_buf);
        g_pcap_ring_buf = NULL;
        g_pcap_ring_capacity = 0;
        pcap_ring_reset_counters_locked();
    }

    g_pcap_ring_buf = heap_caps_malloc(size_bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (g_pcap_ring_buf == NULL) {
        xSemaphoreGive(g_pcap_ring_mutex);
        ESP_LOGE(TAG, "Failed to allocate %zu bytes in PSRAM", size_bytes);
        return ESP_ERR_NO_MEM;
    }

    g_pcap_ring_capacity = size_bytes;
    pcap_ring_reset_counters_locked();

    xSemaphoreGive(g_pcap_ring_mutex);

    ESP_LOGI(TAG, "PCAP ring initialized (%zu bytes)", size_bytes);
    return ESP_OK;
}

esp_err_t pcap_ring_start(uint32_t duration_sec)
{
    (void)duration_sec;

    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        esp_err_t ret = pcap_ring_init(PCAP_RING_DEFAULT_SIZE);
        if (ret != ESP_OK) {
            return ret;
        }
    }

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);
    pcap_ring_reset_counters_locked();
    atomic_store(&g_pcap_ring_active, true);
    xSemaphoreGive(g_pcap_ring_mutex);

    ESP_LOGI(TAG, "PCAP ring capture started");
    return ESP_OK;
}

void pcap_ring_stop(void)
{
    atomic_store(&g_pcap_ring_active, false);
    ESP_LOGI(TAG, "PCAP ring capture stopped");
}

bool pcap_ring_is_active(void)
{
    return atomic_load(&g_pcap_ring_active);
}

/* -------------------------------------------------------------------------
 *  Status
 * ----------------------------------------------------------------------- */

uint64_t pcap_ring_filled(void)
{
    if (g_pcap_ring_mutex == NULL) {
        return 0;
    }

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);
    uint64_t used = g_pcap_ring_used;
    xSemaphoreGive(g_pcap_ring_mutex);

    return used;
}

void pcap_ring_print_info(void)
{
    if (g_pcap_ring_mutex == NULL) {
        return;
    }

    size_t capacity;
    size_t used;
    uint32_t packets;
    uint32_t dropped_packets;
    uint32_t dropped_bytes;

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);
    capacity = g_pcap_ring_capacity;
    used = g_pcap_ring_used;
    packets = g_pcap_ring_packets;
    dropped_packets = g_pcap_ring_dropped_packets;
    dropped_bytes = g_pcap_ring_dropped_bytes;
    xSemaphoreGive(g_pcap_ring_mutex);

    bool active = atomic_load(&g_pcap_ring_active);

    printf("\nPCAP ring: %s\n", active ? "ACTIVE" : "idle");
    printf("  capacity: %zu bytes\n", capacity);
    printf("  used:     %zu bytes\n", used);
    printf("  packets:  %u\n", (unsigned)packets);
    printf("  dropped:  %u packets / %u bytes\n",
           (unsigned)dropped_packets,
           (unsigned)dropped_bytes);
}

/* -------------------------------------------------------------------------
 *  Export helpers
 * ----------------------------------------------------------------------- */

static bool file_write_ring_bytes(FILE *f, size_t offset, size_t len)
{
    uint8_t chunk[PCAP_EXPORT_CHUNK_SIZE];

    size_t done = 0;

    while (done < len) {
        size_t n = len - done;
        if (n > sizeof(chunk)) {
            n = sizeof(chunk);
        }

        pcap_ring_read_bytes_at(offset + done, chunk, n);

        if (fwrite(chunk, 1, n, f) != n) {
            return false;
        }

        done += n;
    }

    return true;
}

typedef struct {
    uint32_t exported;
    uint32_t skipped;
} pcap_export_counts_t;

static esp_err_t export_pcap_stream_locked(FILE *f, pcap_export_counts_t *counts)
{
    if (f == NULL || g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    pcap_file_header_t hdr = {
        .magic = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = PCAP_RING_MAX_PAYLOAD,
        .network = 105,
    };

    if (fwrite(&hdr, 1, sizeof(hdr), f) != sizeof(hdr)) {
        return ESP_FAIL;
    }

    size_t cursor = g_pcap_ring_head;
    size_t remaining = g_pcap_ring_used;

    uint32_t exported = 0;
    uint32_t skipped = 0;

    while (remaining > 0) {
        uint32_t total_len = pcap_ring_read_u32_at(cursor);

        if (total_len < PCAP_FRAME_MIN_LEN ||
            total_len > remaining ||
            total_len > g_pcap_ring_capacity) {
            skipped++;
            break;
        }

        uint32_t stored_crc = pcap_ring_read_u32_at(cursor + PCAP_FRAME_CRC_OFFSET);
        uint32_t calc_crc = crc32_ring(cursor + PCAP_FRAME_HDR_OFFSET,
                                       total_len - PCAP_FRAME_HDR_OFFSET);

        bool valid = (stored_crc == calc_crc);

        if (valid) {
            pcaprec_hdr_t rec;
            pcap_ring_read_bytes_at(cursor + PCAP_FRAME_HDR_OFFSET,
                                    (uint8_t *)&rec,
                                    sizeof(rec));

            uint32_t payload_len = total_len - PCAP_FRAME_HDR_OFFSET - sizeof(rec);

            if (rec.incl_len != payload_len || rec.orig_len != payload_len) {
                valid = false;
            } else {
                if (fwrite(&rec, 1, sizeof(rec), f) != sizeof(rec)) {
                    skipped++;
                    break;
                }

                if (!file_write_ring_bytes(f,
                                           cursor + PCAP_FRAME_HDR_OFFSET + sizeof(rec),
                                           payload_len)) {
                    skipped++;
                    break;
                }

                exported++;
            }
        } else {
            skipped++;
        }

        cursor = (cursor + total_len) % g_pcap_ring_capacity;
        remaining -= total_len;
    }

    if (counts != NULL) {
        counts->exported = exported;
        counts->skipped = skipped;
    }

    return ESP_OK;
}

static esp_err_t pcap_ring_export_to_FILE(FILE *f)
{
    if (g_pcap_ring_mutex == NULL ||
        g_pcap_ring_buf == NULL ||
        g_pcap_ring_capacity == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    bool was_active = atomic_load(&g_pcap_ring_active);

    if (was_active) {
        atomic_store(&g_pcap_ring_active, false);
    }

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);

    pcap_export_counts_t counts = {0};
    esp_err_t ret = export_pcap_stream_locked(f, &counts);

    xSemaphoreGive(g_pcap_ring_mutex);

    if (was_active) {
        atomic_store(&g_pcap_ring_active, true);
    }

    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "Export complete: %lu frames exported, %lu skipped",
                 (unsigned long)counts.exported,
                 (unsigned long)counts.skipped);
    }

    return ret;
}

/* -------------------------------------------------------------------------
 *  Public export API
 * ----------------------------------------------------------------------- */

esp_err_t pcap_ring_save(const char *path)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    if (path == NULL) {
        path = "/sd/pcap_ring.pcap";
    }

    if (strncmp(path, "/sd/", 4) == 0 && !storage_is_ready()) {
        return ESP_ERR_INVALID_STATE;
    }

    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open PCAP export path: %s", path);
        return ESP_FAIL;
    }

    esp_err_t ret = pcap_ring_export_to_FILE(f);

    fclose(f);

    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "PCAP ring exported to %s", path);
    }

    return ret;
}

esp_err_t pcap_ring_export_serial(void)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    if (g_pcap_ring_used == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    /*
     * Warning:
     *
     * This writes binary PCAP data to stdout.
     *
     * This is only safe if stdout is redirected to a file or consumed by a
     * host tool. It is not suitable for JSON-RPC transport directly.
     * For phone transfer, use chunked base64/JSON-RPC or file transfer.
     */
    esp_err_t ret = pcap_ring_export_to_FILE(stdout);

    fflush(stdout);

    return ret;
}

void pcap_ring_wipe(void)
{
    if (g_pcap_ring_mutex == NULL) {
        return;
    }

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);
    pcap_ring_reset_counters_locked();
    xSemaphoreGive(g_pcap_ring_mutex);
}
