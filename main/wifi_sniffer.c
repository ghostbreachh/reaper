#include "channel_hopper.h"
#include "ai_classifier.h"
#include "ai_anomaly.h"
#include "ai_fingerprint.h"
#include "ai_channel_predictor.h"
#include "ai_rogue_detector.h"
#include "ai_training.h"
#include "wardrive.h"
#include "reaction_rules.h"
#include "wifi_sniffer.h"
#include "led_indicator.h"
#include "storage_sd.h"
#include "pcap_ring.h"
#include "arp_poison.h"
#include "handshake_crack.h"
#include "cred_sniffer.h"
#include "extra_offense.h"
#include "wifi_rrm.h"

#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"

#include <stdatomic.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

static const char *TAG = "wifi_sniffer";

#define WIFI_QUEUE_LEN    48
#define WIFI_MAX_PAYLOAD  2304

atomic_bool g_wifi_sniffer_active = ATOMIC_VAR_INIT(false);
_Atomic uint8_t g_wifi_fixed_channel = 0;

static ap_info_t g_ap_list[MAX_DISCOVERED_APS];
static uint16_t g_ap_count = 0;

static client_info_t g_client_list[MAX_DISCOVERED_CLIENTS];
static uint16_t g_client_count = 0;

static wifi_stats_t g_wifi_stats;
static atomic_bool g_wifi_init_done = ATOMIC_VAR_INIT(false);

static QueueHandle_t g_wifi_pkt_queue = NULL;
static SemaphoreHandle_t g_wifi_lock = NULL;
static SemaphoreHandle_t g_pcap_mutex = NULL;

static volatile uint32_t g_wifi_alloc_drop = 0;
static volatile uint32_t g_wifi_queue_drop = 0;

static FILE *g_pcap_file = NULL;
static char g_pcap_path[64] = {0};
static atomic_bool g_pcap_active = ATOMIC_VAR_INIT(false);

static inline void atomic_inc_u32(volatile uint32_t *v)
{
    __atomic_fetch_add((uint32_t *)v, 1, __ATOMIC_RELAXED);
}

static inline uint32_t atomic_load_u32(volatile uint32_t *v)
{
    return __atomic_load_n((uint32_t *)v, __ATOMIC_RELAXED);
}

static bool mac_is_valid_unicast(const uint8_t *mac)
{
    if ((mac[0] & 0x01) != 0) {
        return false;
    }
    static const uint8_t zero_mac[6] = {0, 0, 0, 0, 0, 0};
    static const uint8_t bcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    if (memcmp(mac, zero_mac, 6) == 0 || memcmp(mac, bcast_mac, 6) == 0) {
        return false;
    }
    return true;
}

static void sanitize_ssid(char *ssid)
{
    if (ssid == NULL) return;
    for (int i = 0; ssid[i] != '\0'; i++) {
        if (!isprint((unsigned char)ssid[i])) {
            ssid[i] = ' ';
        }
    }
}

static bool parse_ssid_tag(const uint8_t *frame, size_t len, size_t offset, char *ssid, size_t ssid_sz)
{
    if (ssid == NULL || ssid_sz == 0) return false;
    ssid[0] = '\0';
    if (frame == NULL || len <= offset) return false;

    size_t pos = offset;
    while (pos + 2 <= len) {
        uint8_t tag_id = frame[pos];
        uint8_t tag_len = frame[pos + 1];

        if (pos + 2 + tag_len > len) break;

        if (tag_id == 0) {
            size_t copy_len = (tag_len >= ssid_sz) ? (ssid_sz - 1) : tag_len;
            memcpy(ssid, &frame[pos + 2], copy_len);
            ssid[copy_len] = '\0';
            sanitize_ssid(ssid);
            return true;
        }
        pos += 2 + tag_len;
    }
    return false;
}


// ============================================================================
//  802.11k/v/r NEIGHBOR REPORT PARSING DECISION
// ============================================================================
//  Branch A — Inline parser in wifi_sniffer.c, store in ap_info_t
//    Decision: REJECTED. Separate helper keeps parser reusable for BTM/RRM.
//  Branch B — Separate wifi_rrm.c/h module
//    Decision: ACCEPTED. Clean isolation, reusable across sniffer/JSON-RPC.
//  Branch C — Post-parse JSON-RPC handler
//    Decision: REJECTED. Raw parse is cheaper and keeps state local.

// ============================================================================
//  MULTI-BSSID ELEMENT PARSING DECISION
// ============================================================================
//  Branch A — Parse only transmitted BSSID, ignore nontransmitted
//    Decision: REJECTED. Non-transmitted BSSIDs carry valid probe clients.
//  Branch B — Parse and store all BSSIDs with transmitted/nontransmitted flags
//    Decision: ACCEPTED. Full fidelity; BSSID index and MBI enable future
//    deauth targeting of specific profiles in a multi-BSSID set.
//  Branch C — Deduplicate into separate ap_info_t entries
//    Decision: REJECTED. Bloats AP table; better to keep primary BSSID and
//    track profiles via neighbor list or separate BSSID table.

// ============================================================================
//  HE CAPABILITIES PARSING DECISION
// ============================================================================
//  HE CAPABILITIES PARSING DECISION
// ============================================================================
//  Branch A — Full HE PHY/MAC capability bitmap parsing
//    Decision: REJECTED. HE capability bitmap is 10+ bytes; parsing every
//    bit wastes CPU on ESP32-S3 and produces unused state.
//  Branch B — Parse HE MAC caps + PHY caps + MCS/NSS + PPDU type only
//    Decision: ACCEPTED. Covers the actionable fields for attack decisions:
//    NSS count tells us how many spatial streams, PPDU type tells us if AP
//    supports MU-OFDMA. Stored compactly in ap_info_t.
//  Branch C — Skip HE entirely, rely on VHT/HT as proxy
//    Decision: REJECTED. WiFi 6/6E APs advertise HE, not VHT; skipping
//    would misclassify modern APs as legacy.

// ============================================================================
//  REGULATORY DOMAIN COMPLIANCE DECISION
// ============================================================================
//  Branch A — Parse full Country IE including all subband triplets
//    Decision: REJECTED. Full subband table is large and rarely actionable
//    on ESP32-S3; we only need country code + max TX power for reporting.
//  Branch B — Parse country code + regulatory class + max TX power only
//    Decision: ACCEPTED. Gives simple compliance visibility: allows operator
//    to see AP country, regulatory class, and advertised power limit.
//  Branch C — Skip Country IE; infer domain from channel map
//    Decision: REJECTED. Inferred domain is unreliable; AP may override
//    with explicit Country IE that differs from physical region.

// ============================================================================
//  SAE/WPA3 DETECTION DECISION
// ============================================================================
//  Branch A — Detect WPA3 by presence of AKM 0x000F (SAE) in RSN IE
//    Decision: ACCEPTED. Direct, cheap, and standard: WPA3-Personal always
//    uses SAE as the sole AKM. Works on both beacons and probe_resp.
//  Branch B — Detect WPA3 by VHT/HE capabilities + RSN IE combined
//    Decision: REJECTED. Complexity without reliability: WPA3-Enterprise uses
//    different AKMs, and VHT/HE presence does not imply WPA3.
//  Branch C — Reject deauth based only on PMF required flag
//    Decision: REJECTED. Insufficient: PMF-capable non-WPA3 networks can
//    still be deauthed cleanly; WPA3+PMF is the true no-deauth zone.

// ============================================================================
//  PMF PARSING DECISION
// ============================================================================
//  Branch A — Parse RSN IE only in beacon parser
//    Decision: REJECTED. Probe responses also carry RSN; limiting to beacons
//    misses APs only seen in probe_resp during sparse scanning.
//  Branch B — Parse RSN IE in both beacon + probe_resp with shared helper
//    Decision: ACCEPTED. Covers all discovery paths; single helper keeps code
//    DRY and gives full PMF coverage during wardrive.
//  Branch C — Offload PMF detection to JSON-RPC schema post-parse
//    Decision: REJECTED. Adds unnecessary indirection; raw frame parse is
//    cheaper and keeps PMF state local to sniffer for offline reports.
//
static bool pmf_parse_rsn(const uint8_t *ies, size_t len,
                           bool *out_capable, bool *out_required, uint16_t *out_rsn_ver,
                           bool *out_sae, uint8_t *out_akm_count)
{
    if (ies == NULL || len == 0 || out_capable == NULL || out_required == NULL || out_rsn_ver == NULL) return false;
    *out_capable = false;
    *out_required = false;
    *out_rsn_ver = 0;
    if (out_sae != NULL) *out_sae = false;
    if (out_akm_count != NULL) *out_akm_count = 0;

    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t tag_id = ies[pos];
        uint8_t tag_len = ies[pos + 1];
        if (pos + 2 + tag_len > len) break;

        if (tag_id == 48 && tag_len >= 2) {
            /* RSN IE: first 2 bytes = version */
            uint16_t ver = (uint16_t)(ies[pos + 2] | ((uint16_t)ies[pos + 3] << 8));
            *out_rsn_ver = ver;

            /* RSN capabilities at offset 6 (after version[2] + group_cipher[4] + pairwise_count[2] + akm_count[2] + pairwise[2] + akm[2]) */
            if (tag_len >= 8) {
                uint16_t caps = (uint16_t)(ies[pos + 8] | ((uint16_t)ies[pos + 9] << 8));
                *out_capable = true;
                *out_required = (caps & 0x0008) != 0; /* MFP required bit */
            }
            if (out_akm_count != NULL && tag_len >= 10) {
                uint8_t akm_count = ies[pos + 9];
                if (akm_count > 8U) akm_count = 8U;
                *out_akm_count = akm_count;
                size_t akm_off = pos + 10;
                for (uint8_t k = 0; k < akm_count && akm_off + 4 <= pos + 2 + tag_len; k++) {
                    uint16_t akm_type = (uint16_t)(ies[akm_off + 3] | ((uint16_t)ies[akm_off + 2] << 8));
                    if (akm_type == 0x000F && out_sae != NULL) {
                        *out_sae = true;
                    }
                    akm_off += 4;
                }
            }
            if (*out_capable) return true;
        }
        if (tag_id == 70 && tag_len >= 1) {
            /* RSNXE: bit 7 of byte[0] = MFP capable, bit 6 = MFP required */
            *out_capable = true;
            *out_required = (ies[pos + 2] & 0xC0) == 0xC0;
            return true;
        }
        pos += 2 + tag_len;
    }
    return false;
}

static bool wifi_mbssid_parse(const uint8_t *ies, size_t len,
                              bool *out_multi, bool *out_transmitted,
                              uint8_t *out_max_bssid_ind, uint8_t *out_bssid_idx)
{
    if (ies == NULL || len == 0 || out_multi == NULL || out_transmitted == NULL ||
        out_max_bssid_ind == NULL || out_bssid_idx == NULL) return false;
    *out_multi = false;
    *out_transmitted = false;
    *out_max_bssid_ind = 0;
    *out_bssid_idx = 0;

    size_t pos = 0;
    while (pos + 2 <= len) {
        uint8_t tag_id = ies[pos];
        uint8_t tag_len = ies[pos + 1];
        if (pos + 2 + tag_len > len) break;

        if (tag_id == 55 && tag_len >= 3) {
            *out_multi = true;
            *out_max_bssid_ind = ies[pos + 2];
            *out_bssid_idx = ies[pos + 3];
            *out_transmitted = (ies[pos + 4] & 0x01) != 0;
            return true;
        }
        pos += 2 + tag_len;
    }
    return false;
}

static void add_ap_locked(const uint8_t *bssid, const char *ssid, int8_t rssi, uint8_t channel,
                           bool pmf_capable, bool pmf_required, uint16_t rsn_version,
                           bool wpa3_sae, uint8_t akm_count,
                           bool has_rrm, bool has_btm, const neighbor_entry_t *nbrs, uint8_t nbr_count,
                           bool is_multi_bssid, bool is_transmitted_bssid,
                           uint8_t max_bssid_indicator, uint8_t bssid_index,
                           bool he_capable, uint8_t he_mcs_nss, uint8_t he_ppdu_type,
                           bool regdom_present, const char *country_code, uint8_t reg_class, uint8_t max_tx_power)
{
    if (!mac_is_valid_unicast(bssid)) return;

    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            g_ap_list[i].rssi = rssi;
            g_ap_list[i].channel = channel;
            g_ap_list[i].pkt_count++;

            if (ssid != NULL && ssid[0] != '\0') {
                if (g_ap_list[i].ssid[0] == '\0' || strcmp(g_ap_list[i].ssid, "<HIDDEN>") == 0) {
                    snprintf(g_ap_list[i].ssid, sizeof(g_ap_list[i].ssid), "%s", ssid);
                }
            }
            if (pmf_capable) {
                g_ap_list[i].pmf_capable = true;
                g_ap_list[i].pmf_required = pmf_required;
                g_ap_list[i].rsn_version = rsn_version;
            }
            if (wpa3_sae) {
                g_ap_list[i].wpa3_sae = true;
                g_ap_list[i].akm_count = akm_count;
            }
            if (has_rrm) g_ap_list[i].has_rrm = true;
            if (has_btm) g_ap_list[i].has_btm = true;
            if (nbrs != NULL && nbr_count > 0) {
                uint8_t copy = (nbr_count < sizeof(g_ap_list[i].neighbors) / sizeof(neighbor_entry_t)) ? nbr_count : sizeof(g_ap_list[i].neighbors) / sizeof(neighbor_entry_t);
                memcpy(g_ap_list[i].neighbors, nbrs, copy * sizeof(neighbor_entry_t));
                g_ap_list[i].neighbor_count = copy;
            }
            if (is_multi_bssid) {
                g_ap_list[i].is_multi_bssid = true;
                g_ap_list[i].is_transmitted_bssid = is_transmitted_bssid;
                g_ap_list[i].max_bssid_indicator = max_bssid_indicator;
                g_ap_list[i].bssid_index = bssid_index;
            }
            if (he_capable) {
                g_ap_list[i].he_capable = true;
                g_ap_list[i].he_mcs_nss = he_mcs_nss;
                g_ap_list[i].he_ppdu_type = he_ppdu_type;
            }
            if (regdom_present) {
                g_ap_list[i].regdom_present = true;
                memcpy(g_ap_list[i].country_code, country_code, 2);
                g_ap_list[i].country_code[2] = 0;
                g_ap_list[i].reg_class = reg_class;
                g_ap_list[i].max_tx_power = max_tx_power;
            }
            return;
        }
    }

    if (g_ap_count < MAX_DISCOVERED_APS) {
        memcpy(g_ap_list[g_ap_count].bssid, bssid, 6);
        if (ssid != NULL && ssid[0] != '\0') {
            snprintf(g_ap_list[g_ap_count].ssid, sizeof(g_ap_list[g_ap_count].ssid), "%s", ssid);
        } else {
            snprintf(g_ap_list[g_ap_count].ssid, sizeof(g_ap_list[g_ap_count].ssid), "<HIDDEN>");
        }
        g_ap_list[g_ap_count].rssi = rssi;
        g_ap_list[g_ap_count].channel = channel;
        g_ap_list[g_ap_count].pkt_count = 1;
        g_ap_list[g_ap_count].pmf_capable = pmf_capable;
        g_ap_list[g_ap_count].pmf_required = pmf_required;
        g_ap_list[g_ap_count].rsn_version = rsn_version;
        g_ap_list[g_ap_count].wpa3_sae = wpa3_sae;
        g_ap_list[g_ap_count].akm_count = akm_count;
        g_ap_list[g_ap_count].has_rrm = has_rrm;
        g_ap_list[g_ap_count].has_btm = has_btm;
        if (nbrs != NULL && nbr_count > 0) {
            uint8_t copy = (nbr_count < sizeof(g_ap_list[g_ap_count].neighbors) / sizeof(neighbor_entry_t)) ? nbr_count : sizeof(g_ap_list[g_ap_count].neighbors) / sizeof(neighbor_entry_t);
            memcpy(g_ap_list[g_ap_count].neighbors, nbrs, copy * sizeof(neighbor_entry_t));
            g_ap_list[g_ap_count].neighbor_count = copy;
        } else {
            g_ap_list[g_ap_count].neighbor_count = 0;
        }
        g_ap_list[g_ap_count].is_multi_bssid = is_multi_bssid;
        g_ap_list[g_ap_count].is_transmitted_bssid = is_transmitted_bssid;
        g_ap_list[g_ap_count].max_bssid_indicator = max_bssid_indicator;
        g_ap_list[g_ap_count].bssid_index = bssid_index;
        g_ap_list[g_ap_count].he_capable = he_capable;
        g_ap_list[g_ap_count].he_mcs_nss = he_mcs_nss;
        g_ap_list[g_ap_count].he_ppdu_type = he_ppdu_type;
        g_ap_list[g_ap_count].regdom_present = regdom_present;
        if (regdom_present) {
            memcpy(g_ap_list[g_ap_count].country_code, country_code, 2);
            g_ap_list[g_ap_count].country_code[2] = 0;
            g_ap_list[g_ap_count].reg_class = reg_class;
            g_ap_list[g_ap_count].max_tx_power = max_tx_power;
        }
        g_ap_count++;
    }
}

static void touch_ap_locked(const uint8_t *bssid, int8_t rssi, uint8_t channel)
{
    if (!mac_is_valid_unicast(bssid)) return;
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            g_ap_list[i].rssi = rssi;
            g_ap_list[i].channel = channel;
            g_ap_list[i].pkt_count++;
            return;
        }
    }
    /* Reaction rules check */
    reaction_rules_check_ap(bssid, ssid);
}

static void add_client_locked(const uint8_t *client_mac, const uint8_t *ap_bssid, int8_t rssi, uint8_t channel)
{
    if (!mac_is_valid_unicast(client_mac)) return;
    bool ap_valid = (ap_bssid != NULL) && mac_is_valid_unicast(ap_bssid);

    for (int i = 0; i < g_client_count; i++) {
        if (memcmp(g_client_list[i].mac, client_mac, 6) == 0) {
            g_client_list[i].rssi = rssi;
            g_client_list[i].channel = channel;
            g_client_list[i].pkt_count++;
            if (ap_valid) {
                memcpy(g_client_list[i].ap_bssid, ap_bssid, 6);
            }
            return;
        }
    }

    if (g_client_count < MAX_DISCOVERED_CLIENTS) {
        memcpy(g_client_list[g_client_count].mac, client_mac, 6);
        if (ap_valid) {
            memcpy(g_client_list[g_client_count].ap_bssid, ap_bssid, 6);
        } else {
            memset(g_client_list[g_client_count].ap_bssid, 0, 6);
        }
        g_client_list[g_client_count].rssi = rssi;
        g_client_list[g_client_count].channel = channel;
        g_client_list[g_client_count].pkt_count = 1;
        g_client_count++;
    }
}


bool wifi_sniffer_get_security(const uint8_t *bssid, bool *out_pmf_required, bool *out_wpa3_sae)
{
    if (bssid == NULL || out_pmf_required == NULL || out_wpa3_sae == NULL) return false;
    *out_pmf_required = false;
    *out_wpa3_sae = false;
    if (g_wifi_lock == NULL) return false;

    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            *out_pmf_required = g_ap_list[i].pmf_required;
            *out_wpa3_sae = g_ap_list[i].wpa3_sae;
            xSemaphoreGive(g_wifi_lock);
            return true;
        }
    }
    xSemaphoreGive(g_wifi_lock);
    return false;
}

bool wifi_sniffer_get_rssi(const uint8_t *bssid, int8_t *out_rssi)
{
    if (bssid == NULL || out_rssi == NULL) return false;
    *out_rssi = -100;
    if (g_wifi_lock == NULL) return false;

    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            *out_rssi = g_ap_list[i].rssi;
            xSemaphoreGive(g_wifi_lock);
            return true;
        }
    }
    xSemaphoreGive(g_wifi_lock);
    return false;
}

void wifi_sniffer_get_ssid_for_bssid(const uint8_t *bssid, char *out_ssid, size_t max_len)
{
    if (bssid == NULL || out_ssid == NULL || max_len == 0) return;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            snprintf(out_ssid, max_len, "%s", g_ap_list[i].ssid);
            xSemaphoreGive(g_wifi_lock);
            return;
        }
    }
    xSemaphoreGive(g_wifi_lock);
}

void wifi_sniffer_get_ap_bssid_and_channel_for_client(const uint8_t *client_mac, uint8_t *out_bssid, uint8_t *out_channel)
{
    if (client_mac == NULL) return;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_client_count; i++) {
        if (memcmp(g_client_list[i].mac, client_mac, 6) == 0) {
            if (out_bssid) memcpy(out_bssid, g_client_list[i].ap_bssid, 6);
            if (out_channel) *out_channel = g_client_list[i].channel;
            xSemaphoreGive(g_wifi_lock);
            return;
        }
    }
    xSemaphoreGive(g_wifi_lock);
}

bool wifi_sniffer_get_channel_for_bssid(const uint8_t *bssid, uint8_t *out_channel)
{
    if (bssid == NULL || out_channel == NULL) return false;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            *out_channel = g_ap_list[i].channel;
            xSemaphoreGive(g_wifi_lock);
            return true;
        }
    }
    xSemaphoreGive(g_wifi_lock);
    return false;
}

void wifi_sniffer_clear_fixed_channel(void)
{
    atomic_store(&g_wifi_fixed_channel, 0);
}

static esp_err_t pcap_open(void)
{
    if (!storage_is_ready()) return ESP_ERR_INVALID_STATE;
    if (g_pcap_mutex == NULL) return ESP_ERR_INVALID_STATE;

    xSemaphoreTake(g_pcap_mutex, portMAX_DELAY);
    if (g_pcap_file != NULL) {
        xSemaphoreGive(g_pcap_mutex);
        return ESP_ERR_INVALID_STATE;
    }

    snprintf(g_pcap_path, sizeof(g_pcap_path), "/sd/sniff_%" PRId64 ".pcap", esp_timer_get_time());
    g_pcap_file = fopen(g_pcap_path, "wb");
    if (g_pcap_file == NULL) {
        xSemaphoreGive(g_pcap_mutex);
        return ESP_FAIL;
    }

    pcap_file_header_t hdr = {
        .magic = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = WIFI_MAX_PAYLOAD,
        .network = 105
    };

    size_t written = fwrite(&hdr, 1, sizeof(hdr), g_pcap_file);
    if (written != sizeof(hdr)) {
        fclose(g_pcap_file);
        g_pcap_file = NULL;
        xSemaphoreGive(g_pcap_mutex);
        return ESP_FAIL;
    }

    atomic_store(&g_pcap_active, true);
    xSemaphoreGive(g_pcap_mutex);
    return ESP_OK;
}

static void pcap_close(void)
{
    if (g_pcap_mutex == NULL) return;
    xSemaphoreTake(g_pcap_mutex, portMAX_DELAY);
    atomic_store(&g_pcap_active, false);
    if (g_pcap_file != NULL) {
        fclose(g_pcap_file);
        g_pcap_file = NULL;
    }
    xSemaphoreGive(g_pcap_mutex);
}

static void pcap_write(const uint8_t *data, size_t len, const struct timeval *tv)
{
    if (g_pcap_mutex == NULL || data == NULL || len == 0 || tv == NULL) return;
    xSemaphoreTake(g_pcap_mutex, portMAX_DELAY);
    if (atomic_load(&g_pcap_active) && g_pcap_file != NULL) {
        pcaprec_hdr_t rec = {
            .ts_sec = (uint32_t)tv->tv_sec,
            .ts_usec = (uint32_t)tv->tv_usec,
            .incl_len = (uint32_t)len,
            .orig_len = (uint32_t)len
        };
        fwrite(&rec, 1, sizeof(rec), g_pcap_file);
        fwrite(data, 1, len, g_pcap_file);
    }
    xSemaphoreGive(g_pcap_mutex);
}

static void parse_wifi_packet(const wifi_pkt_msg_t *msg)
{
    if (msg == NULL || msg->payload == NULL || g_wifi_lock == NULL) return;

    const uint8_t *data = msg->payload;
    size_t len = msg->len;
    if (len < sizeof(wifi_ieee80211_mac_hdr_t)) return;

    const wifi_ieee80211_mac_hdr_t *hdr = (const wifi_ieee80211_mac_hdr_t *)data;
    uint16_t fc = hdr->frame_ctrl;
    uint8_t type = (fc >> 2) & 0x03;
    uint8_t subtype = (fc >> 4) & 0x0F;

    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);

    if (type == 0) {
        g_wifi_stats.total_mgmt++;
        if (subtype == 8 || subtype == 5) {
            if (subtype == 8) g_wifi_stats.beacon++;
            else g_wifi_stats.probe_resp++;
            char ssid[33] = {0};
            parse_ssid_tag(data, len, 36, ssid, sizeof(ssid));
            bool pmf_cap=false, pmf_req=false;
            uint16_t rsn_ver=0;
            bool wpa3=false; uint8_t akm=0;
            pmf_parse_rsn(data + 24, len - 24, &pmf_cap, &pmf_req, &rsn_ver, &wpa3, &akm);
            neighbor_entry_t nbrs[8]; uint8_t nbr_count = 0;
            bool has_rrm = wifi_rrm_parse_beacon(data + 24, len - 24, nbrs, &nbr_count);
            bool has_btm = wifi_rrm_parse_btm(data + 24, len - 24);
            bool is_mbssid=false, is_trans=false; uint8_t max_ind=0, idx=0;
            wifi_mbssid_parse(data + 24, len - 24, &is_mbssid, &is_trans, &max_ind, &idx);
            bool he_cap=false; uint8_t he_mcs_nss=0, he_ppdu=0;
            wifi_he_parse(data + 24, len - 24, &he_cap, &he_mcs_nss, &he_ppdu);
            char country_code[3] = {0};
            bool regdom=false; uint8_t reg_class=0, max_tx=0;
            wifi_country_parse(data + 24, len - 24, country_code, sizeof(country_code), &reg_class, &max_tx);
            add_ap_locked(hdr->addr3, ssid, msg->rssi, msg->channel, pmf_cap, pmf_req, rsn_ver, wpa3, akm, has_rrm, has_btm, nbrs, nbr_count, is_mbssid, is_trans, max_ind, idx, he_cap, he_mcs_nss, he_ppdu, regdom, country_code, reg_class, max_tx);

            /* Wardrive logging */
            if (wardrive_get_mode() != WARDIRVE_MODE_OFF) {
                char mac[18];
                snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                         hdr->addr3[0], hdr->addr3[1], hdr->addr3[2],
                         hdr->addr3[3], hdr->addr3[4], hdr->addr3[5]);
                wardrive_log_wifi(mac, ssid, msg->rssi, msg->channel,
                                  wpa3 ? "WPA3" : (rsn_ver ? "WPA2" : "WPA"));
            }

            ai_fp_result_t fp_res;
            ai_fingerprint_classify(data + 24, len - 24, subtype, hdr->addr3, &fp_res);
            ai_rogue_detector_scan();
        } else if (subtype == 4) {
            g_wifi_stats.probe_req++;
            char ssid[33] = {0};
            parse_ssid_tag(data, len, 24, ssid, sizeof(ssid));
            bool pmf_cap2=false, pmf_req2=false;
            uint16_t rsn_ver2=0;
            pmf_parse_rsn(data + 12, len - 12, &pmf_cap2, &pmf_req2, &rsn_ver2, NULL, NULL);
            add_client_locked(hdr->addr2, NULL, msg->rssi, msg->channel);
            ai_fp_result_t fp_res;
            ai_fingerprint_classify(data + 12, len - 12, subtype, hdr->addr2, &fp_res);
        } else if (subtype == 12) {
            g_wifi_stats.deauth++;
        } else if (subtype == 10) {
            g_wifi_stats.disassoc++;
        } else {
            add_client_locked(hdr->addr2, NULL, msg->rssi, msg->channel);
            ai_fp_result_t fp_res;
            ai_fingerprint_classify(data + 12, len - 12, subtype, hdr->addr2, &fp_res);
        }
    } else if (type == 2) {
        g_wifi_stats.total_data++;
        bool to_ds = (fc & 0x0100) != 0;
        bool from_ds = (fc & 0x0200) != 0;

        const uint8_t *client_mac = NULL;
        const uint8_t *ap_mac = NULL;

        if (!to_ds && !from_ds) {
            client_mac = hdr->addr2; ap_mac = hdr->addr3;
        } else if (to_ds && !from_ds) {
            client_mac = hdr->addr2; ap_mac = hdr->addr1;
        } else if (!to_ds && from_ds) {
            client_mac = hdr->addr1; ap_mac = hdr->addr2;
        } else {
            client_mac = hdr->addr2; ap_mac = hdr->addr3;
        }

        add_client_locked(client_mac, ap_mac, msg->rssi, msg->channel);
        if (ap_mac != NULL && mac_is_valid_unicast(ap_mac)) {
            touch_ap_locked(ap_mac, msg->rssi, msg->channel);
        }
        if (channel_hopper_is_active()) {
            channel_hop_record_locked(msg->channel, type, subtype, msg->rssi, len);
        }
    }

    if (channel_hopper_is_active()) {
        channel_hop_record_locked(msg->channel, type, subtype, msg->rssi, len);
        ai_channel_predictor_record();
    }

    xSemaphoreGive(g_wifi_lock);
}

static void channel_hop_record_locked(uint8_t channel, uint8_t type, uint8_t subtype, int8_t rssi, size_t len)
{
    uint32_t pkt_count = 1;
    uint32_t mgmt = (type == 0) ? 1 : 0;
    uint32_t beacon = (type == 0 && subtype == 8) ? 1 : 0;
    uint32_t data = (type == 2) ? 1 : 0;
    channel_hopper_record_packet(channel, pkt_count, mgmt, beacon, data, rssi);
}

static void wifi_pkt_worker_task(void *arg)
{
    wifi_pkt_msg_t msg;
    while (1) {
        if (usb_cdc_break_signaled()) {
            usb_cdc_break_clear();
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
        watchdog_task_refresh("wifi_worker");
        if (xQueueReceive(g_wifi_pkt_queue, &msg, portMAX_DELAY) == pdTRUE) {
            if (msg.payload != NULL) {
                if (atomic_load(&g_wifi_sniffer_active)) {
                    parse_wifi_packet(&msg);
                    ai_classify_result_t cls_res;
                    ai_classifier_predict(msg.payload, msg.len, &cls_res);
                    ai_anomaly_feed(msg.rssi, msg.len, msg.tv.tv_sec * 1000000ULL + msg.tv.tv_usec);
                    ai_rogue_detector_scan();

                    /* Reaction rules: anomaly + rogue */
                    ai_anomaly_result_t anom;
                    if (ai_anomaly_get_result(&anom) == ESP_OK) {
                        reaction_rules_check_anomaly(anom.score);
                    }
                    reaction_rules_check_rogue(NULL);
                    if (atomic_load(&g_arp_poison_active)) {
                        arp_feed_packet(msg.payload, msg.len);
                        arp_relay_frame(msg.payload, msg.len);
                    }
                    if (atomic_load(&g_hs_capture_active)) {
                        handshake_feed_packet(msg.payload, msg.len, msg.channel);
                    }
                    if (creds_is_enabled()) {
                        creds_feed_packet(msg.payload, msg.len);
                    }
                    doj_feed(msg.payload, msg.len);
                }

                if (atomic_load(&g_pcap_active)) {
                    pcap_write(msg.payload, msg.len, &msg.tv);
                    if (ai_train_get_mode() != AI_TRAIN_MODE_OFF) {
                        ai_train_label_wifi(msg.payload, msg.len,
                                            msg.channel, msg.rssi,
                                            msg.tv.tv_sec * 1000000ULL + msg.tv.tv_usec);
                    }
                }

                if (pcap_ring_is_active()) {
                    pcap_ring_store(msg.payload, msg.len, &msg.tv);
                }

                heap_caps_free(msg.payload);
            }
        }
    }
}

static void wifi_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (buf == NULL || g_wifi_pkt_queue == NULL) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    size_t len = pkt->rx_ctrl.sig_len;

    if (len == 0 || len > WIFI_MAX_PAYLOAD) return;

    uint8_t *payload_copy = heap_caps_malloc(len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (payload_copy == NULL) {
        atomic_inc_u32(&g_wifi_alloc_drop);
        return;
    }

    memcpy(payload_copy, pkt->payload, len);
    wifi_pkt_msg_t msg = {
        .payload = payload_copy,
        .len = len,
        .rssi = pkt->rx_ctrl.rssi,
        .channel = pkt->rx_ctrl.channel,
        .tv = {0}
    };
    gettimeofday(&msg.tv, NULL);

    if (xQueueSend(g_wifi_pkt_queue, &msg, 0) != pdTRUE) {
        heap_caps_free(payload_copy);
        atomic_inc_u32(&g_wifi_queue_drop);
    }
}
static void wifi_clear_state_locked(void)
{
    g_ap_count = 0;
    g_client_count = 0;
    memset(g_ap_list, 0, sizeof(g_ap_list));
    memset(g_client_list, 0, sizeof(g_client_list));
    memset(&g_wifi_stats, 0, sizeof(g_wifi_stats));
    channel_hopper_init();
}

static esp_err_t wifi_sniffer_start_internal(uint32_t duration_sec, bool enable_pcap)
{
    if (!atomic_load(&g_wifi_init_done) || atomic_load(&g_wifi_sniffer_active)) return ESP_ERR_INVALID_STATE;

    if (enable_pcap) {
        esp_err_t pcap_ret = pcap_open();
        if (pcap_ret != ESP_OK) return pcap_ret;
    }

    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    wifi_clear_state_locked();
    xSemaphoreGive(g_wifi_lock);

    atomic_store(&g_wifi_sniffer_active, true);

    esp_err_t ret = esp_wifi_set_promiscuous(true);
    if (ret != ESP_OK) {
        atomic_store(&g_wifi_sniffer_active, false);
        if (enable_pcap) pcap_close();
        return ret;
    }

    led_set_state(LED_STATE_SCANNING);

    if (channel_hopper_init() != ESP_OK) {
        atomic_store(&g_wifi_sniffer_active, false);
        return ESP_FAIL;
    }
    ch_hop_config_t cfg = {
        .mode = CH_HOP_MODE_SEQUENTIAL,
        .dwell_ms = 100,
        .channel_mask = 0xFF
    };
    esp_err_t hop_ret = channel_hopper_start(&cfg);
    if (hop_ret != ESP_OK) {
        atomic_store(&g_wifi_sniffer_active, false);
        return hop_ret;
    }

    ESP_LOGI(TAG, "Wi-Fi sniffer started, duration=%" PRIu32 " s", duration_sec);
    return ESP_OK;
}

esp_err_t wifi_sniffer_init(void)
{
    if (atomic_load(&g_wifi_init_done)) return ESP_OK;

    if (g_wifi_lock == NULL) {
        g_wifi_lock = xSemaphoreCreateMutex();
        if (g_wifi_lock == NULL) return ESP_ERR_NO_MEM;
    }

    if (g_pcap_mutex == NULL) {
        g_pcap_mutex = xSemaphoreCreateMutex();
        if (g_pcap_mutex == NULL) return ESP_ERR_NO_MEM;
    }

    if (g_wifi_pkt_queue == NULL) {
        g_wifi_pkt_queue = xQueueCreate(WIFI_QUEUE_LEN, sizeof(wifi_pkt_msg_t));
        if (g_wifi_pkt_queue == NULL) return ESP_ERR_NO_MEM;
    }

    if (xTaskCreatePinnedToCore(wifi_pkt_worker_task, "wifi_worker", 6144, NULL, 5, NULL, 1) != pdPASS) {
        return ESP_FAIL;
    }

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    if (ret != ESP_OK) return ret;

    ret = esp_netif_init();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) return ret;

    ret = esp_event_loop_create_default();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) return ret;

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ret = esp_wifi_init(&cfg);
    if (ret != ESP_OK) return ret;

    ret = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (ret != ESP_OK) return ret;

    ret = esp_wifi_set_mode(WIFI_MODE_NULL);
    if (ret != ESP_OK) return ret;

    ret = esp_wifi_start();
    if (ret != ESP_OK) return ret;

    esp_wifi_set_ps(WIFI_PS_NONE);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous_cb);

    atomic_store(&g_wifi_init_done, true);
    ESP_LOGI(TAG, "Wi-Fi sniffer initialized");
    return ESP_OK;
}

esp_err_t wifi_sniffer_start(uint32_t duration_sec)
{
    return wifi_sniffer_start_internal(duration_sec, false);
}

esp_err_t wifi_sniffer_start_pcap(uint32_t duration_sec)
{
    return wifi_sniffer_start_internal(duration_sec, true);
}

void wifi_sniffer_stop(void)
{
    if (!atomic_load(&g_wifi_sniffer_active)) return;

    atomic_store(&g_wifi_sniffer_active, false);
    esp_wifi_set_promiscuous(false);

    /* Drain queued packets quickly without blocking the caller. */
    wifi_pkt_msg_t msg;
    while (xQueueReceive(g_wifi_pkt_queue, &msg, pdMS_TO_TICKS(5)) == pdTRUE) {
        if (msg.payload != NULL) heap_caps_free(msg.payload);
    }

    if (atomic_load(&g_pcap_active)) {
        pcap_close();
    }

    channel_hopper_stop();
    led_set_state(LED_STATE_IDLE);
    ESP_LOGI(TAG, "Wi-Fi sniffer stopped");
}

bool wifi_sniffer_is_active(void)
{
    return atomic_load(&g_wifi_sniffer_active);
}

static void wifi_stats_fprint(FILE *out)
{
    if (out == NULL || g_wifi_lock == NULL) return;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);

    fprintf(out, "\n==================== WI-FI STATS ====================\n");
    fprintf(out, "Management frames : %" PRIu32 "\n", g_wifi_stats.total_mgmt);
    fprintf(out, "Data frames       : %" PRIu32 "\n", g_wifi_stats.total_data);
    fprintf(out, "Beacons           : %" PRIu32 "\n", g_wifi_stats.beacon);
    fprintf(out, "Probe Requests    : %" PRIu32 "\n", g_wifi_stats.probe_req);
    fprintf(out, "Probe Responses   : %" PRIu32 "\n", g_wifi_stats.probe_resp);
    fprintf(out, "Deauth frames     : %" PRIu32 "\n", g_wifi_stats.deauth);
    fprintf(out, "Disassoc frames   : %" PRIu32 "\n", g_wifi_stats.disassoc);
    xSemaphoreGive(g_wifi_lock);

    fprintf(out, "Alloc drops       : %" PRIu32 "\n", atomic_load_u32(&g_wifi_alloc_drop));
    fprintf(out, "Queue drops       : %" PRIu32 "\n", atomic_load_u32(&g_wifi_queue_drop));
    if (atomic_load(&g_pcap_active)) {
        fprintf(out, "Active PCAP       : %s\n", g_pcap_path);
    }
    fprintf(out, "=====================================================\n");
}

void wifi_sniffer_fprint(FILE *out)
{
    if (out == NULL || g_wifi_lock == NULL) return;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);

    fprintf(out, "\n=============================================================\n");
    fprintf(out, "                  DISCOVERED ACCESS POINTS (%d)\n", g_ap_count);
    fprintf(out, "=============================================================\n");
    fprintf(out, " #  | BSSID             | CH | RSSI | PKTS     | PMF       | RRM/BTM | NBR | MBSSID | HE  | CC  | SSID\n");
    fprintf(out, "----+-------------------+----+------+----------+-----------+---------+-----+--------+-----+-----+-----------------\n");

    for (int i = 0; i < g_ap_count; i++) {
        const char *pmf_str = "no";
        if (g_ap_list[i].pmf_capable) pmf_str = g_ap_list[i].pmf_required ? "REQ" : "CAP";
        char rrm_btm[8] = "-";
        if (g_ap_list[i].has_rrm && g_ap_list[i].has_btm) snprintf(rrm_btm, sizeof(rrm_btm), "KV");
        else if (g_ap_list[i].has_rrm) snprintf(rrm_btm, sizeof(rrm_btm), "K");
        else if (g_ap_list[i].has_btm) snprintf(rrm_btm, sizeof(rrm_btm), "V");
        char mbssid[8] = "-";
        if (g_ap_list[i].is_multi_bssid) {
            if (g_ap_list[i].is_transmitted_bssid) snprintf(mbssid, sizeof(mbssid), "TX/%d", g_ap_list[i].bssid_index);
            else snprintf(mbssid, sizeof(mbssid), "NON/%d", g_ap_list[i].bssid_index);
        }
        char he[8] = "-";
        if (g_ap_list[i].he_capable) {
            uint8_t nss = g_ap_list[i].he_mcs_nss & 0x0F;
            uint8_t mcs = (g_ap_list[i].he_mcs_nss >> 4) & 0x0F;
            if (g_ap_list[i].he_ppdu_type == 1) snprintf(he, sizeof(he), "MU-%d", nss);
            else if (g_ap_list[i].he_ppdu_type == 2) snprintf(he, sizeof(he), "SU-%d", nss);
            else snprintf(he, sizeof(he), "%dSS", nss);
        }
        const char *cc = g_ap_list[i].regdom_present ? g_ap_list[i].country_code : "-";
        fprintf(out, "%-2d | %02X:%02X:%02X:%02X:%02X:%02X | %-2d | %-4d | %-8" PRIu32 " | %-9s | %-7s | %-3d | %-6s | %-4s | %-3s | %s\n",
                i + 1,
                g_ap_list[i].bssid[0], g_ap_list[i].bssid[1], g_ap_list[i].bssid[2],
                g_ap_list[i].bssid[3], g_ap_list[i].bssid[4], g_ap_list[i].bssid[5],
                g_ap_list[i].channel, g_ap_list[i].rssi, g_ap_list[i].pkt_count, pmf_str, rrm_btm, g_ap_list[i].neighbor_count, mbssid, he, cc, g_ap_list[i].ssid);
    }

    fprintf(out, "\n=============================================================\n");
    fprintf(out, "                  DISCOVERED CLIENT DEVICES (%d)\n", g_client_count);
    fprintf(out, "=============================================================\n");
    fprintf(out, " #  | CLIENT MAC        | CH | RSSI | PKTS     | CONNECTED TO BSSID\n");
    fprintf(out, "----+-------------------+----+------+----------+-------------------\n");

    for (int i = 0; i < g_client_count; i++) {
        fprintf(out, "%-2d | %02X:%02X:%02X:%02X:%02X:%02X | %-2d | %-4d | %-8" PRIu32 " | %02X:%02X:%02X:%02X:%02X:%02X\n",
                i + 1,
                g_client_list[i].mac[0], g_client_list[i].mac[1], g_client_list[i].mac[2],
                g_client_list[i].mac[3], g_client_list[i].mac[4], g_client_list[i].mac[5],
                g_client_list[i].channel, g_client_list[i].rssi, g_client_list[i].pkt_count,
                g_client_list[i].ap_bssid[0], g_client_list[i].ap_bssid[1], g_client_list[i].ap_bssid[2],
                g_client_list[i].ap_bssid[3], g_client_list[i].ap_bssid[4], g_client_list[i].ap_bssid[5]);
    }
    fprintf(out, "=============================================================\n");
    xSemaphoreGive(g_wifi_lock);
}

void wifi_sniffer_print_results(void) { wifi_sniffer_fprint(stdout); }
void wifi_sniffer_print_stats(void) { wifi_stats_fprint(stdout); }

esp_err_t wifi_sniffer_save_report(const char *path)
{
    if (path == NULL) return ESP_ERR_INVALID_ARG;
    FILE *f = fopen(path, "w");
    if (f == NULL) return ESP_FAIL;
    wifi_sniffer_fprint(f);
    wifi_stats_fprint(f);
    fclose(f);
    return ESP_OK;
}

bool wifi_sniffer_get_neighbors(const uint8_t *bssid, neighbor_entry_t *out, uint8_t max, uint8_t *out_count)
{
    if (bssid == NULL || out == NULL || max == 0 || out_count == NULL) return false;
    *out_count = 0;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            uint8_t copy = g_ap_list[i].neighbor_count;
            if (copy > max) copy = max;
            memcpy(out, g_ap_list[i].neighbors, copy * sizeof(neighbor_entry_t));
            *out_count = copy;
            xSemaphoreGive(g_wifi_lock);
            return true;
        }
    }
    xSemaphoreGive(g_wifi_lock);
    return false;
}

bool wifi_sniffer_get_rrm_btm(const uint8_t *bssid, bool *out_rrm, bool *out_btm)
{
    if (bssid == NULL || out_rrm == NULL || out_btm == NULL) return false;
    *out_rrm = false;
    *out_btm = false;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            *out_rrm = g_ap_list[i].has_rrm;
            *out_btm = g_ap_list[i].has_btm;
            xSemaphoreGive(g_wifi_lock);
            return true;
        }
    }
    xSemaphoreGive(g_wifi_lock);
    return false;
}

bool wifi_sniffer_get_mbssid(const uint8_t *bssid, bool *out_multi, bool *out_transmitted,
                             uint8_t *out_max_ind, uint8_t *out_idx)
{
    if (bssid == NULL || out_multi == NULL) return false;
    *out_multi = false;
    if (out_transmitted) *out_transmitted = false;
    if (out_max_ind) *out_max_ind = 0;
    if (out_idx) *out_idx = 0;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            *out_multi = g_ap_list[i].is_multi_bssid;
            if (out_transmitted) *out_transmitted = g_ap_list[i].is_transmitted_bssid;
            if (out_max_ind) *out_max_ind = g_ap_list[i].max_bssid_indicator;
            if (out_idx) *out_idx = g_ap_list[i].bssid_index;
            xSemaphoreGive(g_wifi_lock);
            return true;
        }
    }
    xSemaphoreGive(g_wifi_lock);
    return false;
}

bool wifi_sniffer_get_he(const uint8_t *bssid, bool *out_he, uint8_t *out_mcs_nss, uint8_t *out_ppdu_type)
{
    if (bssid == NULL || out_he == NULL) return false;
    *out_he = false;
    if (out_mcs_nss) *out_mcs_nss = 0;
    if (out_ppdu_type) *out_ppdu_type = 0;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            *out_he = g_ap_list[i].he_capable;
            if (out_mcs_nss) *out_mcs_nss = g_ap_list[i].he_mcs_nss;
            if (out_ppdu_type) *out_ppdu_type = g_ap_list[i].he_ppdu_type;
            xSemaphoreGive(g_wifi_lock);
            return true;
        }
    }
    xSemaphoreGive(g_wifi_lock);
    return false;
}

bool wifi_sniffer_get_country(const uint8_t *bssid, char *out_country_code, size_t cc_sz,
                              uint8_t *out_reg_class, uint8_t *out_max_tx_power)
{
    if (bssid == NULL || out_country_code == NULL || cc_sz < 3) return false;
    out_country_code[0] = '\0';
    if (out_reg_class) *out_reg_class = 0;
    if (out_max_tx_power) *out_max_tx_power = 0;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            if (g_ap_list[i].regdom_present) {
                memcpy(out_country_code, g_ap_list[i].country_code, 2);
                out_country_code[2] = '\0';
                if (out_reg_class) *out_reg_class = g_ap_list[i].reg_class;
                if (out_max_tx_power) *out_max_tx_power = g_ap_list[i].max_tx_power;
            }
            xSemaphoreGive(g_wifi_lock);
            return g_ap_list[i].regdom_present;
        }
    }
    xSemaphoreGive(g_wifi_lock);
    return false;
}

uint16_t wifi_sniffer_get_ap_count(void) { return g_ap_count; }
uint16_t wifi_sniffer_get_client_count(void) { return g_client_count; }

void wifi_sniffer_print_clients_of_ap(const uint8_t *bssid)
{
    if (bssid == NULL || g_wifi_lock == NULL) return;
    xSemaphoreTake(g_wifi_lock, portMAX_DELAY);

    char ssid[33] = {0};
    for (int i = 0; i < g_ap_count; i++) {
        if (memcmp(g_ap_list[i].bssid, bssid, 6) == 0) {
            snprintf(ssid, sizeof(ssid), "%s", g_ap_list[i].ssid);
            break;
        }
    }

    printf("\nClients of %02X:%02X:%02X:%02X:%02X:%02X (%s):\n",
           bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
           ssid[0] ? ssid : "?");
    printf("----+-------------------+----+------+----------\n");

    int n = 0;
    for (int i = 0; i < g_client_count; i++) {
        if (memcmp(g_client_list[i].ap_bssid, bssid, 6) == 0) {
            n++;
            printf("%-2d | %02X:%02X:%02X:%02X:%02X:%02X | %-2d | %-4d | %"PRIu32"\n",
                   n,
                   g_client_list[i].mac[0], g_client_list[i].mac[1],
                   g_client_list[i].mac[2], g_client_list[i].mac[3],
                   g_client_list[i].mac[4], g_client_list[i].mac[5],
                   g_client_list[i].channel, g_client_list[i].rssi,
                   g_client_list[i].pkt_count);
        }
    }
    if (n == 0) printf("(none)\n");
    xSemaphoreGive(g_wifi_lock);
}
