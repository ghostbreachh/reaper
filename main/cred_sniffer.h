#ifndef CRED_SNIFFER_H
#define CRED_SNIFFER_H

#include "common_types.h"

esp_err_t creds_init(void);
void creds_set_enabled(bool on);
bool creds_is_enabled(void);
void creds_print(void);
esp_err_t creds_save(const char *path);
void creds_clear(void);
uint16_t creds_count(void);
void creds_feed_packet(const uint8_t *data, size_t len);

bool extract_kv(const char *hay, const char *key, char *out, size_t out_sz);
void creds_push(const cred_hit_t *hit);

#endif // CRED_SNIFFER_H
