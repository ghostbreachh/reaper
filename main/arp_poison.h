#ifndef ARP_POISON_H
#define ARP_POISON_H

#include "common_types.h"

esp_err_t arp_poison_init(void);
esp_err_t arp_poison_start(const char *victim_ip, const char *gateway_ip,
                           uint32_t interval_ms);
esp_err_t arp_poison_stop(void);
bool arp_poison_is_active(void);
void arp_relay_set_enabled(bool on);
void arp_poison_print_table(void);
void arp_poison_print_status(void);

void arp_feed_packet(const uint8_t *data, size_t len);
void arp_relay_frame(const uint8_t *data, size_t len);
extern atomic_bool g_arp_poison_active;

#endif // ARP_POISON_H
