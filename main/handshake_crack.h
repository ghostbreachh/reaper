#ifndef HANDSHAKE_CRACK_H
#define HANDSHAKE_CRACK_H

#include "common_types.h"

esp_err_t handshake_init(void);
esp_err_t handshake_capture_start(const uint8_t *bssid, const uint8_t *client_mac,
                                  uint32_t duration_sec, bool force_deauth);
void handshake_capture_stop(void);
bool handshake_has_capture(void);
const handshake_t *handshake_get(void);
void handshake_set_ssid(const char *ssid);

esp_err_t handshake_crack_async(void);
bool handshake_crack_running(void);
bool handshake_crack_found(char *password, size_t sz);
void handshake_crack_stop(void);

esp_err_t handshake_load_wordlist(const char *path);
const char *const *handshake_wordlist(size_t *count);

esp_err_t handshake_save_password(const char *ssid, const char *password);
bool handshake_load_password(char *ssid, size_t ssid_sz, char *password, size_t pw_sz);
esp_err_t handshake_erase_password(void);

void handshake_feed_packet(const uint8_t *data, size_t len, uint8_t channel);
extern atomic_bool g_hs_capture_active;

#endif // HANDSHAKE_CRACK_H
