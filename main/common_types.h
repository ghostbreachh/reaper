#ifndef COMMON_TYPES_H
#define COMMON_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "esp_err.h"
#include "esp_log.h"

// ============================================================================
//  SECTION 1: LED MODULE TYPES
// ============================================================================

typedef enum {
    LED_STATE_OFF = 0,
    LED_STATE_IDLE,
    LED_STATE_SCANNING,
    LED_STATE_CONNECTED,
    LED_STATE_ERROR,
    LED_STATE_CUSTOM
} led_state_t;

typedef struct {
    uint8_t r;
    uint8_t g;
    uint8_t b;
} Color;

// ============================================================================
//  SECTION 2: WI-FI PROMISCUOUS SNIFFER TYPES
// ============================================================================

#define MAX_DISCOVERED_APS     50
#define MAX_DISCOVERED_CLIENTS 100

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    uint32_t pkt_count;
} ap_info_t;

typedef struct {
    uint8_t mac[6];
    uint8_t ap_bssid[6];
    int8_t rssi;
    uint8_t channel;
    uint32_t pkt_count;
} client_info_t;

typedef struct {
    uint32_t total_mgmt;
    uint32_t total_data;
    uint32_t beacon;
    uint32_t probe_req;
    uint32_t probe_resp;
    uint32_t deauth;
    uint32_t disassoc;
} wifi_stats_t;

typedef struct {
    uint8_t *payload;
    size_t len;
    int8_t rssi;
    uint8_t channel;
    struct timeval tv;
} wifi_pkt_msg_t;

typedef struct __attribute__((packed)) {
    uint16_t frame_ctrl;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} wifi_ieee80211_mac_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_file_header_t;

typedef struct __attribute__((packed)) {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

// ============================================================================
//  SECTION 3: BLE SCANNER TYPES
// ============================================================================

#define MAX_DISCOVERED_BLE 50

typedef struct {
    uint8_t mac[6];
    uint8_t addr_type;
    char name[33];
    int8_t rssi;
    uint16_t mfg_id;
    uint32_t pkt_count;
    uint8_t tracker_score;
} ble_info_t;

// ============================================================================
//  SECTION 6: DEAUTH TYPES
// ============================================================================

#define MAX_TARGET_APS    10
#define MAX_TARGET_CLIENTS 20

typedef enum {
    DEAUTH_TYPE_SINGLE,
    DEAUTH_TYPE_ALL,
    DEAUTH_TYPE_BROADCAST
} deauth_type_t;

typedef struct {
    uint8_t bssid[6];
    uint8_t client_mac[6];
    deauth_type_t type;
    uint32_t count;
    uint32_t delay_ms;
    bool active;
} deauth_target_t;

// ============================================================================
//  SECTION 7: WPA HANDSHAKE TYPES
// ============================================================================

#define EAPOL_BUF_SIZE 256

typedef struct {
    bool valid;
    bool has_pmkid;
    uint8_t ap_mac[6];
    uint8_t sta_mac[6];
    char ssid[33];
    uint8_t anonce[32];
    uint8_t snonce[32];
    uint8_t mic[16];
    uint8_t pmkid[16];
    uint8_t eapol[EAPOL_BUF_SIZE];
    uint16_t eapol_len;
    int64_t capture_time_us;
} handshake_t;

// ============================================================================
//  SECTION 8: ARP POISON TYPES
// ============================================================================

#define MAX_ARP_TABLE 32

typedef struct {
    uint8_t mac[6];
    uint8_t ip[4];
    uint8_t ap_bssid[6];
    bool    is_gateway;
    uint32_t pkt_count;
} arp_host_t;

// ============================================================================
//  SECTION 10: CREDENTIAL / PLAINTEXT SNIFFER
// ============================================================================

#define MAX_CREDS 32

typedef struct {
    char host[64];
    char user[48];
    char pass[64];
    char cookie[96];
    char path[64];
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    int64_t time_us;
} cred_hit_t;

#endif // COMMON_TYPES_H
