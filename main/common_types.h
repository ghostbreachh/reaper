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
    bool pmf_capable;
    bool pmf_required;
    uint16_t rsn_version;
    bool wpa3_sae;
    uint8_t akm_count;
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

typedef enum {
    CH_HOP_MODE_SEQUENTIAL = 0,
    CH_HOP_MODE_RANDOM     = 1
} ch_hop_mode_t;

typedef struct {
    uint32_t pkt_count;
    uint32_t beacon_count;
    uint32_t mgmt_count;
    uint32_t data_count;
    int32_t  rssi_sum;
    uint32_t rssi_samples;
    uint16_t ap_count;
    uint16_t client_count;
} ch_hop_stats_t;

typedef struct {
    ch_hop_mode_t mode;
    uint16_t dwell_ms;
    uint8_t  channel_mask;   /* bit0=ch1..bit12=ch13 */
    uint8_t  _pad;
} ch_hop_config_t;

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
//  SECTION 4: BOOT PORT DETECTION
// ============================================================================

// Transport modes chosen at boot based on detected USB port.
typedef enum {
    PORT_TRANSPORT_UART0 = 0,   // USB-Serial-JTAG / COM port console
    PORT_TRANSPORT_CDC,         // USB-OTG CDC-ACM active
    PORT_TRANSPORT_UNKNOWN,     // No recognised transport found
    PORT_TRANSPORT_BOTH         // Rare: both PHYs reported (UART0 preferred)
} port_transport_t;

// Detailed detection result for diagnostics and phone-app handshake.
typedef struct {
    port_transport_t active;
    bool usb_serial_jtag_present;  // USB-Serial-JTAG enum found
    bool cdc_acm_present;          // TinyUSB CDC ACM interface found
    bool both_active;              // both USB funcs simultaneously detected
    char jtag_serial[32];          // iSerial if available, else empty
    char cdc_iface[16];            // e.g. "ttyACM0" hint for debug
    uint8_t reason;                // why a transport was chosen
} port_detect_result_t;

#define PORT_REASON_JTAG_ONLY   0x01
#define PORT_REASON_CDC_ONLY    0x02
#define PORT_REASON_BOTH        0x03
#define PORT_REASON_FALLBACK    0x04

typedef enum {
    PORT_TRANSPORT_UART0 = 0,
    PORT_TRANSPORT_CDC,
    PORT_TRANSPORT_UNKNOWN,
    PORT_TRANSPORT_BOTH
} port_transport_t;

typedef struct {
    port_transport_t active;
    bool usb_serial_jtag_present;
    bool cdc_acm_present;
    bool both_active;
    char jtag_serial[32];
    char cdc_iface[16];
    uint8_t reason;
} port_detect_result_t;

#define PORT_REASON_JTAG_ONLY   0x01
#define PORT_REASON_CDC_ONLY    0x02
#define PORT_REASON_BOTH        0x03
#define PORT_REASON_FALLBACK    0x04

// ============================================================================
//  SECTION 5: DEAUTH TYPES
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
    bool wpa3_sae;
    bool pmf_required;
typedef enum {
    DEAUTH_FALLBACK_NONE = 0,
    DEAUTH_FALLBACK_DISASSOC = 1,
    DEAUTH_FALLBACK_AUTH_FLOOD = 2
} deauth_fallback_t;

typedef struct {
    uint8_t bssid[6];
    uint8_t client_mac[6];
    deauth_type_t type;
    uint32_t count;
    uint32_t delay_ms;
    bool active;
    bool wpa3_sae;
    bool pmf_required;
    deauth_fallback_t fallback_level;
    uint32_t disassoc_count;
    uint32_t auth_count;
} deauth_target_t;

// ============================================================================
//  SECTION 6: WPA HANDSHAKE TYPES
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
//  SECTION 7: ARP POISON TYPES
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
//  SECTION 8: CREDENTIAL / PLAINTEXT SNIFFER
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
