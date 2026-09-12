#ifndef PCAP_RING_H
#define PCAP_RING_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>

#include "esp_err.h"
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Binary frame layout in ring / on wire / in export stream:
 *
 *   [uint32_t total_len][uint32_t crc32][pcaprec_hdr_t][payload]
 *
 * total_len includes the entire frame, including the leading total_len field:
 *
 *   total_len = 4 + 4 + sizeof(pcaprec_hdr_t) + payload_len
 *
 * CRC32 is computed over:
 *
 *   pcaprec_hdr_t + payload
 *
 * CRC does NOT include total_len and does NOT include the stored CRC field.
 */

#define PCAP_RING_MAX_PAYLOAD   2346

#define PCAP_FRAME_CRC_OFFSET   4
#define PCAP_FRAME_HDR_OFFSET   8

#define PCAP_FRAME_MIN_LEN      (PCAP_FRAME_HDR_OFFSET + sizeof(pcaprec_hdr_t))

/*
 * Lifecycle
 */
esp_err_t pcap_ring_init(size_t size_bytes);
esp_err_t pcap_ring_start(uint32_t duration_sec);
void pcap_ring_stop(void);
bool pcap_ring_is_active(void);

/*
 * Status
 */
uint64_t pcap_ring_filled(void);
void pcap_ring_print_info(void);

/*
 * Store one packet into the ring.
 * Called from Wi-Fi packet worker.
 */
esp_err_t pcap_ring_store(const uint8_t *data, size_t len, const struct timeval *tv);

/*
 * Export
 */
esp_err_t pcap_ring_save(const char *path);
esp_err_t pcap_ring_export_serial(void);
void pcap_ring_wipe(void);

/*
 * Binary framing helpers
 */
uint32_t pcap_ring_frame_crc32(const uint8_t *buf, size_t len);

esp_err_t pcap_ring_build_frame(uint8_t *out, size_t out_sz,
                                const uint8_t *payload, size_t payload_len,
                                const struct timeval *tv);

esp_err_t pcap_ring_parse_frame(const uint8_t *buf, size_t buf_len,
                                const uint8_t **out_payload,
                                size_t *out_payload_len,
                                uint32_t *out_crc);

#ifdef __cplusplus
}
#endif

#endif /* PCAP_RING_H */
