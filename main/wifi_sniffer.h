#ifndef WIFI_SNIFFER_H
#define WIFI_SNIFFER_H

#include <stdatomic.h>
#include "common_types.h"

esp_err_t wifi_sniffer_init(void);
esp_err_t wifi_sniffer_start(uint32_t duration_sec);
esp_err_t wifi_sniffer_start_pcap(uint32_t duration_sec);
void wifi_sniffer_stop(void);
bool wifi_sniffer_is_active(void);

void wifi_sniffer_print_results(void);
void wifi_sniffer_fprint(FILE *out);
void wifi_sniffer_print_stats(void);
esp_err_t wifi_sniffer_save_report(const char *path);

uint16_t wifi_sniffer_get_ap_count(void);
uint16_t wifi_sniffer_get_client_count(void);

void wifi_sniffer_get_ssid_for_bssid(const uint8_t *bssid, char *out_ssid, size_t max_len);
void wifi_sniffer_get_ap_bssid_and_channel_for_client(const uint8_t *client_mac, uint8_t *out_bssid, uint8_t *out_channel);
bool wifi_sniffer_get_channel_for_bssid(const uint8_t *bssid, uint8_t *out_channel);
void wifi_sniffer_clear_fixed_channel(void);
void wifi_sniffer_print_clients_of_ap(const uint8_t *bssid);

extern atomic_bool g_wifi_sniffer_active;
extern _Atomic uint8_t g_wifi_fixed_channel;

#endif // WIFI_SNIFFER_H
