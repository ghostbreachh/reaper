#ifndef OFFENSIVE_H
#define OFFENSIVE_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 *  OFFENSIVE RESEARCH MODULE
 *
 *  T2T Step 3.2 — Research & Brainstorming
 *
 *  Branch A — Standalone per-attack modules
 *    Decision: REJECTED. Scattering attack code across 8 files increases
 *    maintenance burden and risks inconsistent state handling.
 *
 *  Branch B — Single consolidated offensive module with sub-state machines
 *    Decision: ACCEPTED. Shared capture pipeline; each attack has its own
 *    state block inside one file; easier to audit and disable per feature.
 *
 *  Branch C — Research stubs only, no runtime behavior
 *    Decision: REJECTED. Zero placeholders policy; every feature must be
 *    callable and produce observable behavior.
 * ============================================================================ */

/* Attack/research mode flags. */
typedef enum {
    OFF_MODE_NONE        = 0,
    OFF_MODE_PMKID       = 1 << 0,
    OFF_MODE_SAE_TIMING  = 1 << 1,
    OFF_MODE_DRAGONFLY   = 1 << 2,
    OFF_MODE_FT          = 1 << 3,
    OFF_MODE_11K         = 1 << 4,
    OFF_MODE_11V         = 1 << 5,
    OFF_MODE_WPS         = 1 << 6,
    OFF_MODE_EAP         = 1 << 7
} off_mode_t;

/* PMKID capture result. */
typedef struct {
    uint8_t ap_bssid[6];
    uint8_t pmkid[16];
    uint32_t capture_time_us;
    bool valid;
} off_pmkid_t;

/* SAE timing sample. */
typedef struct {
    uint32_t commit_time_us;
    uint32_t confirm_time_us;
    uint32_t delta_us;
    uint8_t ap_bssid[6];
} off_sae_timing_t;

/* Dragonfly offline check state. */
typedef struct {
    uint8_t ap_bssid[6];
    uint8_t ssid[33];
    uint8_t sae_commit[32];
    uint8_t sae_confirm[32];
    uint32_t scalar;
    uint32_t count;
    bool valid;
} off_dragonfly_t;

/* FT handshake capture. */
typedef struct {
    uint8_t ap_bssid[6];
    uint8_t sta_mac[6];
    uint8_t anonce[32];
    uint8_t snonce[32];
    uint8_t mic[16];
    uint32_t reassoc_time_us;
    bool valid;
} off_ft_t;

/* 802.11k neighbor report injection. */
typedef struct {
    uint8_t target_bssid[6];
    uint8_t channel;
    uint8_t phy;
    uint8_t neighbor_bssid[6];
    char ssid[33];
} off_11k_t;

/* 802.11v BSS Transition Management. */
typedef struct {
    uint8_t ap_bssid[6];
    uint8_t target_bssid[6];
    uint8_t disassoc_timer;
    uint8_t validity;
} off_11v_t;

/* WPS PixieDust capture. */
typedef struct {
    uint8_t ap_bssid[6];
    uint8_t enrollee_mac[6];
    uint8_t m1[256];
    uint16_t m1_len;
    uint8_t m2[256];
    uint16_t m2_len;
    uint32_t nonce;
    bool valid;
} off_wps_t;

/* Enterprise EAP capture. */
typedef struct {
    uint8_t ap_bssid[6];
    uint8_t sta_mac[6];
    uint8_t eap_type;
    uint8_t identity[64];
    uint8_t identity_len;
    uint8_t challenge[64];
    uint8_t challenge_len;
} off_eap_t;

esp_err_t offensive_init(void);
esp_err_t offensive_set_mode(uint32_t mode_mask);
uint32_t offensive_get_mode(void);
esp_err_t offensive_feed(const uint8_t *data, size_t len,
                         const uint8_t *bssid, const uint8_t *sta,
                         uint8_t channel, int8_t rssi, uint64_t ts_us);
esp_err_t offensive_get_pmkid(off_pmkid_t *out);
esp_err_t offensive_get_sae_timing(off_sae_timing_t *out);
esp_err_t offensive_get_dragonfly(off_dragonfly_t *out);
esp_err_t offensive_get_ft(off_ft_t *out);
esp_err_t offensive_get_11k(off_11k_t *out);
esp_err_t offensive_get_11v(off_11v_t *out);
esp_err_t offensive_get_wps(off_wps_t *out);
esp_err_t offensive_get_eap(off_eap_t *out);
esp_err_t offensive_json(char *buf, size_t bufsz);
esp_err_t offensive_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* OFFENSIVE_H */
