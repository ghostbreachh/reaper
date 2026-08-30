#ifndef PCAP_RING_H
#define PCAP_RING_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Binary frame layout on wire / in ring / in file:
 *
 *   [uint32_t length][uint32_t crc32][pcaprec_hdr_t + payload]
 *
 *  length = sizeof(crc32) + sizeof(pcaprec_hdr_t) + payload_len
 */

#define PCAP_FRAME_CRC_OFFSET   4
#define PCAP_FRAME_HDR_OFFSET   8

esp_err_t pcap_ring_init(size_t size_bytes);
esp_err_t pcap_ring_start(uint32_t duration_sec);
void pcap_ring_stop(void);
bool pcap_ring_is_active(void);
uint64_t pcap_ring_filled(void);
void pcap_ring_print_info(void);
esp_err_t pcap_ring_save(const char *path);
esp_err_t pcap_ring_export_serial(void);
void pcap_ring_wipe(void);
esp_err_t pcap_ring_store(const uint8_t *data, size_t len, const struct timeval *tv);

/* Binary framing helpers */
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
