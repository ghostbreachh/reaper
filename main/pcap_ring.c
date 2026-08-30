/*
 * ============================================================================
 *  pcap_ring.c  —  Circular PCAP capture buffer with binary framing
 * ============================================================================
 *
 *  T2T Step 3.2 — Research & Brainstorming
 *
 *  Branch A — Raw PCAP records without framing
 *    Decision: REJECTED. Host-side parser cannot detect truncation, corruption,
 *    or record boundaries without explicit length/CRC.
 *
 *  Branch B — Length-prefixed frames only
 *    Decision: REJECTED. No integrity check; bitflips on SPIFFS/serial go
 *    undetected.
 *
 *  Branch C — Length-prefixed + CRC32 framed binary PCAP records
 *    Decision: ACCEPTED. Provides atomic record framing with corruption
 *    detection; companion app and host tools can recover cleanly from errors.
 * ============================================================================
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"

#include "pcap_ring.h"
#include "esp_system.h"

static const char *TAG = "pcap_ring";

#define WIFI_MAX_PAYLOAD 2304

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

/*============================================================================*/
static void pcap_ring_write_bytes(const uint8_t *src, size_t len)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0 || src == NULL || len == 0) {
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

/*============================================================================*/
static void pcap_ring_write_u32(uint32_t v)
{
    uint8_t bytes[4] = {
        (uint8_t)(v & 0xFF),
        (uint8_t)((v >> 8) & 0xFF),
        (uint8_t)((v >> 16) & 0xFF),
        (uint8_t)((v >> 24) & 0xFF)
    };
    pcap_ring_write_bytes(bytes, sizeof(bytes));
}

/*============================================================================*/
static void pcap_ring_read_bytes_at(size_t offset, uint8_t *dst, size_t len)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0 || dst == NULL || len == 0) {
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

/*============================================================================*/
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

/*============================================================================*/
static bool pcap_ring_make_room(size_t needed)
{
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        return false;
    }

    while (g_pcap_ring_used + needed > g_pcap_ring_capacity && g_pcap_ring_used > 0) {
        uint32_t frame_len = pcap_ring_read_u32_at(g_pcap_ring_head);
        size_t total_len = frame_len;
        if (total_len > g_pcap_ring_used || total_len > g_pcap_ring_capacity) {
            break;
        }
        g_pcap_ring_head = (g_pcap_ring_head + total_len) % g_pcap_ring_capacity;
        g_pcap_ring_used -= total_len;
        g_pcap_ring_dropped_packets++;
        g_pcap_ring_dropped_bytes += total_len;
    }

    return (g_pcap_ring_used + needed <= g_pcap_ring_capacity);
}

/*============================================================================*/
uint32_t pcap_ring_frame_crc32(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) {
        return 0;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint32_t)buf[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1u) {
                crc = (crc >> 1) ^ 0xEDB88320u;
            } else {
                crc = crc >> 1;
            }
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/*============================================================================*/
esp_err_t pcap_ring_build_frame(uint8_t *out, size_t out_sz,
                                const uint8_t *payload, size_t payload_len,
                                const struct timeval *tv)
{
    if (out == NULL || out_sz == 0 || payload == NULL || payload_len == 0 || tv == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t total = PCAP_FRAME_HDR_OFFSET + sizeof(pcaprec_hdr_t) + payload_len;
    if (total > out_sz) {
        return ESP_ERR_NO_MEM;
    }

    pcaprec_hdr_t rec = {
        .ts_sec = (uint32_t)tv->tv_sec,
        .ts_usec = (uint32_t)tv->tv_usec,
        .incl_len = (uint32_t)payload_len,
        .orig_len = (uint32_t)payload_len
    };

    uint8_t *p = out;
    /* length = full frame size including leading length field */
    uint32_t length = (uint32_t)(sizeof(uint32_t) + sizeof(uint32_t) + sizeof(pcaprec_hdr_t) + payload_len);
    p[0] = (uint8_t)(length & 0xFF);
    p[1] = (uint8_t)((length >> 8) & 0xFF);
    p[2] = (uint8_t)((length >> 16) & 0xFF);
    p[3] = (uint8_t)((length >> 24) & 0xFF);

    /* CRC zeroed before compute */
    memset(p + PCAP_FRAME_CRC_OFFSET, 0, sizeof(uint32_t));

    /* PCAP record */
    memcpy(p + PCAP_FRAME_HDR_OFFSET, &rec, sizeof(rec));
    memcpy(p + PCAP_FRAME_HDR_OFFSET + sizeof(rec), payload, payload_len);

    /* Compute CRC over everything after the length field */
    uint32_t crc = pcap_ring_frame_crc32(p + sizeof(uint32_t),
                                         length - sizeof(uint32_t));
    p[PCAP_FRAME_CRC_OFFSET + 0] = (uint8_t)(crc & 0xFF);
    p[PCAP_FRAME_CRC_OFFSET + 1] = (uint8_t)((crc >> 8) & 0xFF);
    p[PCAP_FRAME_CRC_OFFSET + 2] = (uint8_t)((crc >> 16) & 0xFF);
    p[PCAP_FRAME_CRC_OFFSET + 3] = (uint8_t)((crc >> 24) & 0xFF);

    return ESP_OK;
}

/*============================================================================*/
esp_err_t pcap_ring_parse_frame(const uint8_t *buf, size_t buf_len,
                                const uint8_t **out_payload,
                                size_t *out_payload_len,
                                uint32_t *out_crc)
{
    if (buf == NULL || buf_len < PCAP_FRAME_HDR_OFFSET + sizeof(pcaprec_hdr_t) ||
        out_payload == NULL || out_payload_len == NULL || out_crc == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Read length */
    uint32_t length = ((uint32_t)buf[0]) |
                      ((uint32_t)buf[1] << 8) |
                      ((uint32_t)buf[2] << 16) |
                      ((uint32_t)buf[3] << 24);

    if (length < sizeof(uint32_t) + sizeof(pcaprec_hdr_t) || length > buf_len) {
        return ESP_ERR_INVALID_SIZE;
    }

    /* Extract stored CRC */
    uint32_t stored_crc = ((uint32_t)buf[4]) |
                          ((uint32_t)buf[5] << 8) |
                          ((uint32_t)buf[6] << 16) |
                          ((uint32_t)buf[7] << 24);

    /* Compute CRC over payload */
    uint32_t calc_crc = pcap_ring_frame_crc32(buf + PCAP_FRAME_CRC_OFFSET,
                                              length - PCAP_FRAME_CRC_OFFSET);

    *out_crc = stored_crc;
    if (stored_crc != calc_crc) {
        return ESP_ERR_CRC;
    }

    *out_payload = buf + PCAP_FRAME_HDR_OFFSET;
    *out_payload_len = length - sizeof(uint32_t) - sizeof(pcaprec_hdr_t);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t pcap_ring_store(const uint8_t *data, size_t len, const struct timeval *tv)
{
    if (!atomic_load(&g_pcap_ring_active) || g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0 || data == NULL || len == 0 || tv == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (g_pcap_ring_mutex == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);

    /* Build binary frame */
    uint8_t frame[PCAP_FRAME_HDR_OFFSET + sizeof(pcaprec_hdr_t) + WIFI_MAX_PAYLOAD];
    esp_err_t rc = pcap_ring_build_frame(frame, sizeof(frame), data, len, tv);
    if (rc != ESP_OK) {
        xSemaphoreGive(g_pcap_ring_mutex);
        return rc;
    }

    /* Read actual frame length from built frame */
    uint32_t frame_len = ((uint32_t)frame[0]) |
                         ((uint32_t)frame[1] << 8) |
                         ((uint32_t)frame[2] << 16) |
                         ((uint32_t)frame[3] << 24);

    if (!pcap_ring_make_room(frame_len)) {
        xSemaphoreGive(g_pcap_ring_mutex);
        return ESP_ERR_NO_MEM;
    }

    pcap_ring_write_bytes(frame, frame_len);
    g_pcap_ring_used += frame_len;
    g_pcap_ring_packets++;

    xSemaphoreGive(g_pcap_ring_mutex);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t pcap_ring_init(size_t size_bytes)
{
    if (g_pcap_ring_mutex == NULL) {
        g_pcap_ring_mutex = xSemaphoreCreateMutex();
        if (g_pcap_ring_mutex == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    if (size_bytes == 0) {
        size_bytes = 2u * 1024u * 1024u;
    }

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);

    if (g_pcap_ring_buf != NULL && g_pcap_ring_capacity != 0) {
        if (g_pcap_ring_capacity >= size_bytes) {
            g_pcap_ring_tail = g_pcap_ring_head = 0;
            g_pcap_ring_used = 0;
            g_pcap_ring_packets = 0;
            g_pcap_ring_dropped_packets = 0;
            g_pcap_ring_dropped_bytes = 0;
            xSemaphoreGive(g_pcap_ring_mutex);
            return ESP_OK;
        }
        heap_caps_free(g_pcap_ring_buf);
        g_pcap_ring_buf = NULL;
        g_pcap_ring_capacity = 0;
        g_pcap_ring_used = 0;
        g_pcap_ring_head = 0;
        g_pcap_ring_tail = 0;
        g_pcap_ring_packets = 0;
        g_pcap_ring_dropped_packets = 0;
        g_pcap_ring_dropped_bytes = 0;
    }

    g_pcap_ring_buf = heap_caps_malloc(size_bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (g_pcap_ring_buf == NULL) {
        xSemaphoreGive(g_pcap_ring_mutex);
        return ESP_ERR_NO_MEM;
    }

    g_pcap_ring_capacity = size_bytes;
    g_pcap_ring_used = 0;
    g_pcap_ring_head = 0;
    g_pcap_ring_tail = 0;
    g_pcap_ring_packets = 0;
    g_pcap_ring_dropped_packets = 0;
    g_pcap_ring_dropped_bytes = 0;

    xSemaphoreGive(g_pcap_ring_mutex);
    ESP_LOGI(TAG, "PCAP ring initialized (%zu bytes)", size_bytes);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t pcap_ring_start(uint32_t duration_sec)
{
    (void)duration_sec;
    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        esp_err_t ret = pcap_ring_init(2u * 1024u * 1024u);
        if (ret != ESP_OK) {
            return ret;
        }
    }

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);
    g_pcap_ring_head = 0;
    g_pcap_ring_tail = 0;
    g_pcap_ring_used = 0;
    g_pcap_ring_packets = 0;
    g_pcap_ring_dropped_packets = 0;
    g_pcap_ring_dropped_bytes = 0;
    atomic_store(&g_pcap_ring_active, true);
    xSemaphoreGive(g_pcap_ring_mutex);

    ESP_LOGI(TAG, "PCAP ring capture started");
    return ESP_OK;
}

/*============================================================================*/
void pcap_ring_stop(void)
{
    atomic_store(&g_pcap_ring_active, false);
    ESP_LOGI(TAG, "PCAP ring capture stopped");
}

/*============================================================================*/
bool pcap_ring_is_active(void)
{
    return atomic_load(&g_pcap_ring_active);
}

/*============================================================================*/
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

/*============================================================================*/
void pcap_ring_print_info(void)
{
    if (g_pcap_ring_mutex == NULL) {
        return;
    }

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);
    printf("\nPCAP ring: %s\n", atomic_load(&g_pcap_ring_active) ? "ACTIVE" : "idle");
    printf("  capacity: %zu bytes\n", g_pcap_ring_capacity);
    printf("  used:     %zu bytes\n", g_pcap_ring_used);
    printf("  packets:  %u\n", (unsigned int)g_pcap_ring_packets);
    printf("  dropped:  %u packets / %u bytes\n",
           (unsigned int)g_pcap_ring_dropped_packets,
           (unsigned int)g_pcap_ring_dropped_bytes);
    xSemaphoreGive(g_pcap_ring_mutex);
}

/*============================================================================*/
esp_err_t pcap_ring_save(const char *path)
{
    if (g_pcap_ring_mutex == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    if (path == NULL) {
        path = "/sd/pcap_ring.pcap";
    }

    if (storage_is_ready() == false && strncmp(path, "/sd/", 4) == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open PCAP ring export: %s", path);
        return ESP_FAIL;
    }

    pcap_file_header_t hdr = {
        .magic = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = WIFI_MAX_PAYLOAD,
        .network = 105
    };
    fwrite(&hdr, 1, sizeof(hdr), f);

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);
    size_t cursor = g_pcap_ring_head;
    size_t remaining = g_pcap_ring_used;
    uint8_t rec_buf[WIFI_MAX_PAYLOAD];
    while (remaining > 0) {
        uint32_t frame_len = pcap_ring_read_u32_at(cursor);
        size_t total_len = sizeof(uint32_t) + frame_len;
        if (total_len > remaining || frame_len == 0 || frame_len > sizeof(rec_buf)) {
            break;
        }

        uint8_t frame_hdr[PCAP_FRAME_HDR_OFFSET];
        pcap_ring_read_bytes_at(cursor, frame_hdr, sizeof(frame_hdr));

        const uint8_t *payload;
        size_t payload_len;
        uint32_t stored_crc;
        esp_err_t rc = pcap_ring_parse_frame(frame_hdr, sizeof(frame_hdr),
                                             &payload, &payload_len, &stored_crc);
        if (rc == ESP_OK) {
            fwrite(payload, 1, payload_len, f);
        } else {
            /* Corrupted frame; skip */
            ESP_LOGW(TAG, "skipping corrupted frame at offset %zu: %s",
                     (size_t)cursor, esp_err_to_name(rc));
        }

        cursor = (cursor + total_len) % g_pcap_ring_capacity;
        remaining -= total_len;
    }
    xSemaphoreGive(g_pcap_ring_mutex);
    fclose(f);
    ESP_LOGI(TAG, "PCAP ring exported to %s", path);
    return ESP_OK;
}

/*============================================================================*/
esp_err_t pcap_ring_export_serial(void)
{
    if (g_pcap_ring_mutex == NULL || g_pcap_ring_buf == NULL || g_pcap_ring_capacity == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);
    if (g_pcap_ring_used == 0) {
        xSemaphoreGive(g_pcap_ring_mutex);
        return ESP_ERR_INVALID_STATE;
    }

    printf("PCAP_BEGIN\n");
    fflush(stdout);

    size_t cursor = g_pcap_ring_head;
    size_t remaining = g_pcap_ring_used;
    uint8_t frame_hdr[PCAP_FRAME_HDR_OFFSET];
    while (remaining > 0) {
        uint32_t frame_len = pcap_ring_read_u32_at(cursor);
        size_t total_len = sizeof(uint32_t) + frame_len;
        if (total_len > remaining || frame_len == 0) {
            break;
        }

        pcap_ring_read_bytes_at(cursor, frame_hdr, sizeof(frame_hdr));

        const uint8_t *payload;
        size_t payload_len;
        uint32_t stored_crc;
        esp_err_t rc = pcap_ring_parse_frame(frame_hdr, sizeof(frame_hdr),
                                             &payload, &payload_len, &stored_crc);
        if (rc == ESP_OK) {
            uint8_t tmp[WIFI_MAX_PAYLOAD];
            pcap_ring_read_bytes_at(cursor + PCAP_FRAME_HDR_OFFSET, tmp, payload_len);
            fwrite(tmp, 1, payload_len, stdout);
        } else {
            ESP_LOGW(TAG, "skipping corrupted frame in serial export");
        }

        cursor = (cursor + total_len) % g_pcap_ring_capacity;
        remaining -= total_len;
    }
    xSemaphoreGive(g_pcap_ring_mutex);
    printf("\nPCAP_END\n");
    fflush(stdout);
    return ESP_OK;
}

/*============================================================================*/
void pcap_ring_wipe(void)
{
    if (g_pcap_ring_mutex == NULL) {
        return;
    }

    xSemaphoreTake(g_pcap_ring_mutex, portMAX_DELAY);
    g_pcap_ring_used = 0;
    g_pcap_ring_head = 0;
    g_pcap_ring_tail = 0;
    g_pcap_ring_packets = 0;
    g_pcap_ring_dropped_packets = 0;
    g_pcap_ring_dropped_bytes = 0;
    xSemaphoreGive(g_pcap_ring_mutex);
}
