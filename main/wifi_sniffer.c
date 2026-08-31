#include "channel_hopper.h"
#include "wifi_sniffer.h"
#include "led_indicator.h"
#include "storage_sd.h"
#include "pcap_ring.h"
#include "arp_poison.h"
#include "handshake_crack.h"
#include "cred_sniffer.h"
#include "extra_offense.h"

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

static void add_ap_locked(const uint8_t *bssid, const char *ssid, int8_t rssi, uint8_t channel)
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
            add_ap_locked(hdr->addr3, ssid, msg->rssi, msg->channel);
        } else if (subtype == 4) {
            g_wifi_stats.probe_req++;
            char ssid[33] = {0};
            parse_ssid_tag(data, len, 24, ssid, sizeof(ssid));
            add_client_locked(hdr->addr2, NULL, msg->rssi, msg->channel);
        } else if (subtype == 12) {
            g_wifi_stats.deauth++;
        } else if (subtype == 10) {
            g_wifi_stats.disassoc++;
        } else {
            add_client_locked(hdr->addr2, NULL, msg->rssi, msg->channel);
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
    fprintf(out, " #  | BSSID             | CH | RSSI | PKTS     | SSID\n");
    fprintf(out, "----+-------------------+----+------+----------+-----------------\n");

    for (int i = 0; i < g_ap_count; i++) {
        fprintf(out, "%-2d | %02X:%02X:%02X:%02X:%02X:%02X | %-2d | %-4d | %-8" PRIu32 " | %s\n",
                i + 1,
                g_ap_list[i].bssid[0], g_ap_list[i].bssid[1], g_ap_list[i].bssid[2],
                g_ap_list[i].bssid[3], g_ap_list[i].bssid[4], g_ap_list[i].bssid[5],
                g_ap_list[i].channel, g_ap_list[i].rssi, g_ap_list[i].pkt_count, g_ap_list[i].ssid);
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
