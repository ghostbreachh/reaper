#ifndef COMMON_TYPES_H
#define COMMON_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>

#include "esp_err.h"
#include "esp_log.h"

/* ==========================================================================
 *  GLOBAL CONSTANTS
 * ========================================================================== */

/* 
 * Maximum 802.11 frame size captured. 
 * 2346 bytes covers standard MSDU (2304) + MAC header (24) + FCS (4) + padding.
 * Centralized here to prevent mismatches between wifi_sniffer and pcap_ring.
 */
#define WIFI_MAX_FRAME_SIZE 2346

/* ==========================================================================
 *  SECTION 1: LED MODULE TYPES
 * ========================================================================== */

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

/* ==========================================================================
 *  SECTION 2: WI-FI PROMISCUOUS SNIFFER TYPES
 * ========================================================================== */

#define MAX_DISCOVERED_APS     50
#define MAX_DISCOVERED_CLIENTS 100

typedef struct __attribute__((packed)) {
    uint8_t bssid[6];
    uint8_t channel;
    uint8_t phy_mode; /* 0=unknown, 1=b, 2=a/g, 3=n, 4=ac, 5=ax */
} neighbor_entry_t;

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    uint32_t pkt_count;
    
    /* Security & Capabilities */
    uint16_t rsn_version;
    uint8_t akm_count;
    uint8_t neighbor_count;
    neighbor_entry_t neighbors[8];
    
    /* Multi-BSSID & HE */
    uint8_t max_bssid_indicator;
    uint8_t bssid_index;
    uint8_t he_mcs_nss; /* bit 0-3 = NSS, bit 4-7 = MCS */
    uint8_t he_ppdu_type; /* 0=unknown, 1=he-mu, 2=he-su */
    
    /* Regulatory domain */
    char country_code[3]; /* "US", "EU", "JP", etc. + null */
    uint8_t reg_class;
    uint8_t max_tx_power;
    
    /* AI device fingerprinting */
    uint8_t fp_oui[3];
    uint8_t fp_rates[8];
    uint8_t fp_rate_count;
    uint8_t fp_ext_cap[8];
    uint8_t fp_ext_cap_len;
    uint8_t fp_class; /* 0=unknown, 1=phone, 2=laptop, 3=iot, 4=ap, 5=router */
    char fp_label[32];

    /* 
     * Boolean flags grouped at the end to minimize compiler padding holes.
     * Using uint8_t or bool is fine, but keeping them together saves RAM.
     */
    bool pmf_capable;
    bool pmf_required;
    bool wpa3_sae;
    bool has_rrm;
    bool has_btm;
    bool is_multi_bssid;
    bool is_transmitted_bssid;
    bool he_capable;
    bool regdom_present;
    bool fp_done;
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

/* 
 * Binary protocol structs MUST be packed to prevent compiler padding 
 * from corrupting file formats and network frames.
 */
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

/* ==========================================================================
 *  SECTION 3: BLE SCANNER TYPES
 * ========================================================================== */

#define MAX_DISCOVERED_BLE 50

typedef struct {
    uint8_t mac[6];
    uint8_t addr_type;
    char name[33];
    int8_t rssi;
    uint16_t mfg_id;
    uint32_t pkt_count;
    uint8_t tracker_score;
    
    /* BT 5.0 extended advertising */
    uint8_t adv_mode; /* 0=legacy, 1=non-conn, 2=scan */
    uint8_t tx_power; /* dBm from AD ext header, if present */
    
    /* BT 5.0 periodic advertising / sync transfer */
    uint16_t periodic_adv_interval; /* units of 1.25 ms, 0 = unknown */
    uint8_t sync_handle; /* advertising SID from ADI or sync info */
    
    /* BLE privacy / RPA */
    uint8_t irk_hash[3];      /* lower 3 bytes of RPA hash */
    
    /* BT 5.2 ISO / isochronous channels */
    uint8_t iso_channels;     /* number of ISO channels advertised */
    uint8_t bis_handles[4];   /* BIS handle array, max 4 */
    uint32_t iso_interval_us; /* ISO interval in microseconds, 0=unknown */

    /* Boolean flags grouped to minimize padding */
    bool ext_adv_seen;
    bool has_aux_ptr;
    bool has_adi;
    bool has_scan_rsp;
    bool periodic_adv_seen;
    bool has_sync_info;
    bool sync_transfer_seen;
    bool phy_coded;       
    bool phy_coded_s8;    
    bool phy_1m;          
    bool phy_2m;          
    bool phy_coded_supported; 
    bool rpa_seen;            
    bool irk_hash_seen;       
    bool iso_seen;            
    bool has_big_info;        
} ble_info_t;

/* ==========================================================================
 *  SECTION 4: BOOT PORT DETECTION
 * ========================================================================== */

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

/* ==========================================================================
 *  SECTION 5: DEAUTH TYPES
 * ========================================================================== */

#define MAX_TARGET_APS    10
#define MAX_TARGET_CLIENTS 20

typedef enum {
    DEAUTH_TYPE_SINGLE,
    DEAUTH_TYPE_ALL,
    DEAUTH_TYPE_BROADCAST
} deauth_type_t;

typedef enum {
    DEAUTH_FALLBACK_NONE = 0,
    DEAUTH_FALLBACK_DISASSOC = 1,
    DEAUTH_FALLBACK_AUTH_FLOOD = 2
} deauth_fallback_t;

typedef enum {
    DEAUTH_MODE_FALLBACK_CHAIN = 0,
    DEAUTH_MODE_DEAUTH_ONLY    = 1,
    DEAUTH_MODE_DISASSOC_ONLY  = 2,
    DEAUTH_MODE_AUTH_FLOOD_ONLY = 3
} deauth_mode_t;

typedef struct {
    uint8_t bssid[6];
    uint8_t client_mac[6];
    deauth_type_t type;
    uint32_t count;
    uint32_t delay_ms;
    deauth_mode_t mode;
    deauth_fallback_t fallback_level;
    uint32_t disassoc_count;
    uint32_t auth_count;
    bool active;
    bool wpa3_sae;
    bool pmf_required;
} deauth_target_t;

/* ==========================================================================
 *  SECTION 6: WPA HANDSHAKE TYPES
 * ========================================================================== */

#define EAPOL_BUF_SIZE 256

typedef struct {
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
    bool valid;
    bool has_pmkid;
} handshake_t;

/* ==========================================================================
 *  SECTION 7: ARP POISON TYPES
 * ========================================================================== */

#define MAX_ARP_TABLE 32

typedef struct {
    uint8_t mac[6];
    uint8_t ip[4];
    uint8_t ap_bssid[6];
    uint32_t pkt_count;
    bool is_gateway;
} arp_host_t;

/* ==========================================================================
 *  SECTION 8: CREDENTIAL / PLAINTEXT SNIFFER
 * ========================================================================== */

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

/* ==========================================================================
 *  SECTION 9: GPS / TIMESTAMP CORRELATION
 * ========================================================================== */

typedef struct {
    double latitude;
    double longitude;
    double altitude;
    double speed_knots;
    time_t timestamp; /* Use time_t for standard POSIX compatibility */
    uint8_t sat_count;
    uint8_t fix_quality; /* 0=none, 1=GPS, 2=DGPS */
    bool valid;
} gps_fix_t;

#endif // COMMON_TYPES_H
