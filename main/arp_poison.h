#ifndef ARP_POISON_H
#define ARP_POISON_H

#include "common_types.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t arp_poison_init(void);
esp_err_t arp_poison_start(const char *victim_ip, const char *gateway_ip, uint32_t interval_ms);
esp_err_t arp_poison_stop(void);
bool arp_poison_is_active(void);

void arp_relay_set_enabled(bool on);
void arp_poison_print_table(void);
void arp_poison_print_status(void);

/* Observer callbacks for wifi_sniffer */
void arp_feed_packet(const wifi_pkt_msg_t *msg);
void arp_relay_frame(const wifi_pkt_msg_t *msg);

extern atomic_bool g_arp_poison_active;

#ifdef __cplusplus
}
#endif

#endif // ARP_POISON_H
