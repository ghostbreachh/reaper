#ifndef PCAP_RING_H
#define PCAP_RING_H

#include "common_types.h"

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

#endif // PCAP_RING_H
