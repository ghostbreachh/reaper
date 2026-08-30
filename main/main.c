/*
 * ============================================================================
 *  ESP32-S3 · WIRELESS LAB TOOLKIT · main.c                           v1.0
 * ============================================================================
 *  Target   : ESP32-S3-N16R8  (16 MB Flash · 8 MB PSRAM)
 *  Interface: USB-OTG CDC  —  connect phone with OTG adapter, open any
 *             serial terminal at 115 200 baud, then type  help  to start
 *
 *  Capabilities at a glance
 *  ─────────────────────────
 *  · 802.11bgn promiscuous sniffer — AP/client discovery · PCAP export
 *  · BLE 5.0 active scanner — vendor OUI lookup · tracker heuristics
 *  · ARP poison + relay — full MITM for victim/gateway pair
 *  · WPA-2 EAPOL handshake capture + offline dictionary attack
 *  · HTTP credential sniffer — Basic-Auth / form field / session cookie
 *  · Deauth engine — targeted client kick or broadcast flood
 *  · Beacon spam · Rogue AP clone · Evil captive portal
 *  · Probe-request flood · Deauth-on-join sentry
 *  · 2 MiB PCAP ring-buffer in PSRAM + SD-card file export
 *  · Full interactive serial CLI — no recompile needed for any feature
 * ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "esp_timer.h"

#include "helper.h"   /* aggregate include — pulls in every module header */

/* ═══════════════════════════════════════════════════════════════════════════
 *  ANSI colour macros  (keep short for readable printf lines)
 * ═══════════════════════════════════════════════════════════════════════════ */
#define R0   "\033[0m"          /* reset             */
#define RB   "\033[1m"          /* bold              */
#define RED  "\033[91m"         /* bright red        */
#define GRN  "\033[92m"         /* bright green      */
#define YLW  "\033[93m"         /* bright yellow     */
#define BLU  "\033[94m"         /* bright blue       */
#define MAG  "\033[95m"         /* bright magenta    */
#define CYN  "\033[96m"         /* bright cyan       */
#define WHT  "\033[97m"         /* bright white      */
#define GRY  "\033[90m"         /* dark grey         */

/* ═══════════════════════════════════════════════════════════════════════════
 *  Build-time constants
 * ═══════════════════════════════════════════════════════════════════════════ */
#define RING_BYTES       (2UL * 1024UL * 1024UL)  /* PCAP ring in PSRAM  */
#define BOOT_SCAN_SECS   4                         /* quick startup scan  */
#define BOX_W            70                        /* terminal line width */

/* ═══════════════════════════════════════════════════════════════════════════
 *  Small formatting helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Print a horizontal divider of `ch` characters */
static void _hr(const char *ch)
{
    printf(GRY "  ");
    for (int i = 0; i < BOX_W - 2; i++) fputs(ch, stdout);
    printf(R0 "\n");
}

/* Open a named section block */
static void _section(const char *title)
{
    printf(CYN "\n  ┌─ " RB WHT "%s" R0 "\n", title);
}

/* Single init status row — optional=true means failure is just a warning */
static void _init_row(const char *label, esp_err_t e, bool optional)
{
    if (e == ESP_OK || e == ESP_ERR_INVALID_STATE) {
        printf("  " CYN "│" R0 "  " GRN "✔" R0 "  %-45s " GRN "OK" R0 "\n", label);
    } else if (optional) {
        printf("  " CYN "│" R0 "  " YLW "⚠" R0 "  %-45s " YLW "skip" GRY "  (%s)" R0 "\n",
               label, esp_err_to_name(e));
    } else {
        printf("  " CYN "│" R0 "  " RED "✖" R0 "  %-45s " RED "FAIL" GRY "  [%s]" R0 "\n",
               label, esp_err_to_name(e));
    }
}

/* Key / value info row inside a section */
static void _kv(const char *key, const char *val)
{
    printf("  " CYN "│" R0 "  " GRY "%-24s" R0 WHT "%s" R0 "\n", key, val);
}

/* Capability bullet — icon, label, description */
static void _cap(const char *icon, const char *label, const char *desc)
{
    printf("  " CYN "│" R0 "  %s  " RB WHT "%-22s" R0 GRY "%s" R0 "\n",
           icon, label, desc);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  BANNER
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_banner(void)
{
    /* Clear the screen for a clean boot look */
    printf("\033[2J\033[H");

    puts("");

    /* Top border */
    printf(CYN
        "  ╔══════════════════════════════════════════════════════════════════╗\n"
        "  ║                                                                  ║\n"
    R0);

    /* Project logo: simple wide-spaced typographic style */
    printf(CYN "  ║  " R0 YLW RB
        "   W . L . A . B   ·   W I R E L E S S   L A B   T K   "
    R0 CYN "  ║\n" R0);

    printf(CYN "  ║  " R0 GRY
        "                  E S P 3 2 - S 3  ·  N 1 6 R 8              "
    R0 CYN "  ║\n" R0);

    /* Horizontal separator line inside box */
    printf(CYN
        "  ║                                                                  ║\n"
        "  ╠══════════════════════════════════════════════════════════════════╣\n"
    R0);

    /* Tagline rows */
    printf(CYN "  ║  " R0 GRY
        "  802.11bgn Sniffer  ·  BLE 5.0  ·  ARP MITM  ·  WPA2 Crack    "
    R0 CYN "║\n" R0);
    printf(CYN "  ║  " R0 GRY
        "  PCAP Ring  ·  Deauth  ·  Evil Portal  ·  Cred Sniffer         "
    R0 CYN "║\n" R0);

    printf(CYN
        "  ╚══════════════════════════════════════════════════════════════════╝\n"
    R0);

    puts("");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SYSTEM INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_sysinfo(void)
{
    _section("Hardware · Firmware");

    esp_chip_info_t ci;
    esp_chip_info(&ci);

    uint32_t flash_kb = 0;
    {
        uint32_t fsz = 0;
        if (esp_flash_get_size(NULL, &fsz) == ESP_OK)
            flash_kb = fsz / 1024;
    }

    size_t int_total = heap_caps_get_total_size(MALLOC_CAP_INTERNAL);
    size_t int_free  = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t ps_total  = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    size_t ps_free   = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

    uint8_t mac_sta[6], mac_ap[6], mac_bt[6];
    esp_read_mac(mac_sta, ESP_MAC_WIFI_STA);
    esp_read_mac(mac_ap,  ESP_MAC_WIFI_SOFTAP);
    esp_read_mac(mac_bt,  ESP_MAC_BT);

    char buf[80];

    snprintf(buf, sizeof(buf), "ESP32-S3  rev %d  ·  %d cores", ci.revision, ci.cores);
    _kv("Chip :", buf);

    snprintf(buf, sizeof(buf), "%" PRIu32 " kB", flash_kb);
    _kv("Flash :", buf);

    snprintf(buf, sizeof(buf), "%zu kB free  /  %zu kB total",
             int_free / 1024, int_total / 1024);
    _kv("Internal RAM :", buf);

    snprintf(buf, sizeof(buf), "%zu kB free  /  %zu kB total",
             ps_free / 1024, ps_total / 1024);
    _kv("PSRAM :", buf);

    _kv("IDF Version :", IDF_VER);

    snprintf(buf, sizeof(buf),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             mac_sta[0], mac_sta[1], mac_sta[2],
             mac_sta[3], mac_sta[4], mac_sta[5]);
    _kv("MAC · STA :", buf);

    snprintf(buf, sizeof(buf),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             mac_ap[0], mac_ap[1], mac_ap[2],
             mac_ap[3], mac_ap[4], mac_ap[5]);
    _kv("MAC · SoftAP :", buf);

    snprintf(buf, sizeof(buf),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             mac_bt[0], mac_bt[1], mac_bt[2],
             mac_bt[3], mac_bt[4], mac_bt[5]);
    _kv("MAC · BT :", buf);

    printf("  " CYN "│" R0 "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  MODULE INITIALISATION SEQUENCE
 * ═══════════════════════════════════════════════════════════════════════════ */

static void run_init_sequence(void)
{
    _section("Module Initialisation");

    /* ── 3. USB transport detection ───────────────────────────────────── */
    port_detect_result_t port = {0};
    boot_port_detect(&port);
    port_print_banner(&port);

    /* Choose console path:
     * - If CDC-ACM is active, this device is being controlled by a phone;
     *   keep UART0 quiet and let the JSON-RPC dispatcher handle I/O.
     * - Otherwise use the traditional UART0 CLI.
     */
    if (port.active == PORT_TRANSPORT_CDC) {
        printf("  │  Active path is USB-OTG CDC-ACM. ");
        printf("Use the companion app for control.\n");
    }

    /* ── 4. LED indicator ─────────────────────────────────────────────── */
    _init_row("LED Indicator (WS2812, GPIO 48)",
              helper_init(), false);

    /* Boot LED: rapid cyan pulse to signal start */
    led_set_rgb(0, 200, 255);
    vTaskDelay(pdMS_TO_TICKS(120));
    led_set_state(LED_STATE_SCANNING);

    /* ── 5. SD card (optional — device works fine without it) ─────────── */
    _init_row("SD Card Storage  (SPI2, /sd)",
              storage_init(), true);

    /* ── 6. Wi-Fi stack ───────────────────────────────────────────────── */
    _init_row("Wi-Fi Subsystem  (802.11bgn promiscuous)",
              wifi_sniffer_init(), false);

    /* ── 7. BLE stack ─────────────────────────────────────────────────── */
    _init_row("BLE 5.0 Scanner  (NimBLE host)",
              ble_scanner_init(), false);

    /* ── 8. ARP poison engine ─────────────────────────────────────────── */
    _init_row("ARP Poison Engine  (MITM + relay)",
              arp_poison_init(), false);

    /* ── 9. Credential sniffer ────────────────────────────────────────── */
    _init_row("HTTP Credential Sniffer  (form/cookie/Basic)",
              creds_init(), false);

    /* ── 10. WPA handshake capture ─────────────────────────────────────── */
    _init_row("WPA-2 Handshake Capture + Crack  (EAPOL)",
              handshake_init(), false);

    /* ── 11. PCAP ring buffer in PSRAM ─────────────────────────────────── */
    _init_row("PCAP Ring Buffer  (2 MiB PSRAM)",
              pcap_ring_init(RING_BYTES), false);

    /* ── 12. Interactive serial CLI ────────────────────────────────────── */
    _init_row("Interactive Serial CLI  (auto-selected transport)",
              cli_start(), false);

    printf("  " CYN "│" R0 "\n");

    /* Settle LEDs to idle */
    led_set_state(LED_STATE_IDLE);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  QUICK BOOT SCAN  –  brief Wi-Fi survey so first output is real data
 * ═══════════════════════════════════════════════════════════════════════════ */

static void run_boot_scan(void)
{
    char title[64];
    snprintf(title, sizeof(title),
             "Boot Scan  —  " YLW RB "Wi-Fi" R0 "  (" GRY "passive, %d s" R0 ")",
             BOOT_SCAN_SECS);
    _section(title);
    printf("  " CYN "│" R0 "\n");
    printf("  " CYN "│" R0 "  " GRY "Hopping channels 1-13, gathering nearby APs & clients …" R0 "\n");
    printf("  " CYN "│" R0 "\n");

    led_set_state(LED_STATE_SCANNING);

    /* channel_hopper_task will call wifi_sniffer_stop() when duration expires */
    esp_err_t r = wifi_sniffer_start(BOOT_SCAN_SECS);
    if (r != ESP_OK) {
        printf("  " CYN "│" R0 "  " RED "scan skipped: %s" R0 "\n", esp_err_to_name(r));
    } else {
        /* Wait for the scan to finish (duration + 1s safety margin) */
        vTaskDelay(pdMS_TO_TICKS((BOOT_SCAN_SECS + 1) * 1000));

        uint16_t ap_cnt  = wifi_sniffer_get_ap_count();
        uint16_t cli_cnt = wifi_sniffer_get_client_count();

        char buf[80];
        snprintf(buf, sizeof(buf),
                 GRN "%u" R0 " access points  ·  " GRN "%u" R0 " clients",
                 ap_cnt, cli_cnt);
        _kv("Discovered :", buf);
    }

    led_set_state(LED_STATE_IDLE);
    printf("  " CYN "│" R0 "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CAPABILITY REFERENCE TABLE
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_capabilities(void)
{
    _section("Feature Reference  —  type " YLW "help" R0 " for full syntax");

    printf("  " CYN "│" R0 "\n");

    _cap(CYN  "◈" R0, "wifi start / pcap",   "promiscuous 802.11 sniffer, optional PCAP to SD");
    _cap(GRN  "◈" R0, "ble start / results",  "BLE 5.0 scanner with tracker heuristics");
    _cap(YLW  "◈" R0, "deauth ap / client",   "802.11 deauthentication flood (broadcast or unicast)");
    _cap(MAG  "◈" R0, "arp poison",           "ARP MITM with transparent relay to gateway");
    _cap(RED  "◈" R0, "creds on / show",      "HTTP clear-text credential harvester");
    _cap(CYN  "◈" R0, "pcap start / export",  "ring-buffer capture; export to SD or serial");
    _cap(GRN  "◈" R0, "beacon spam",          "30-SSID fake-AP flood across target channel");
    _cap(YLW  "◈" R0, "portal start",         "evil captive portal + DNS hijack on open SoftAP");
    _cap(MAG  "◈" R0, "rogue start",          "clone any SSID as open or WPA2 SoftAP");
    _cap(RED  "◈" R0, "probe start",          "randomised probe-request flood");
    _cap(CYN  "◈" R0, "doj start",            "deauth-on-join sentry — auto-kick new clients");
    _cap(GRN  "◈" R0, "analyzer",             "per-channel activity dwell analysis (1-13)");
    _cap(YLW  "◈" R0, "oui <mac>",            "OUI vendor lookup from on-device table");
    _cap(MAG  "◈" R0, "save wifi / ble",      "write discovered device report to SD card");

    printf("  " CYN "│" R0 "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  READY FOOTER
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_ready_footer(void)
{
    _hr("─");

    printf("\n");
    printf(GRY "  Uptime      : " R0 WHT "%" PRId64 " ms" R0 "\n",
           esp_timer_get_time() / 1000LL);

    printf(GRY "  PCAP ring   : " R0 WHT "2 MiB ready  " GRY "(pcap start → pcap export)" R0 "\n");

    if (storage_is_ready())
        printf(GRY "  SD card     : " R0 GRN "mounted at /sd" R0 "\n");
    else
        printf(GRY "  SD card     : " R0 YLW "not present  " GRY "(insert for file export)" R0 "\n");

    printf("\n");
    printf("  " RB CYN "──────────────────────────────────────────────────────────────" R0 "\n");
    printf("  " RB WHT "  Console ready.  Type " R0 YLW RB "help" R0 WHT RB " for the full command reference." R0 "\n");
    printf("  " RB CYN "──────────────────────────────────────────────────────────────" R0 "\n");
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════ */

void app_main(void)
{
    /*
     * Boot order:
     *   1. banner
     *   2. hardware info
     *   3. init all modules (spawns CLI task internally)
     *   4. quick passive Wi-Fi scan for an immediate result
     *   5. capability cheat-sheet
     *   6. ready prompt — CLI task handles everything from here
     *
     * app_main is free to return; FreeRTOS keeps all spawned tasks alive.
     */

    /* ── 1. Banner ────────────────────────────────────────────────────── */
    print_banner();

    /* ── 2. System info ───────────────────────────────────────────────── */
    print_sysinfo();

    /* ── 3. Module init ───────────────────────────────────────────────── */
    run_init_sequence();

    /* ── 4. Quick boot scan ───────────────────────────────────────────── */
    run_boot_scan();

    /* ── 5. Capabilities ─────────────────────────────────────────────── */
    print_capabilities();

    /* ── 6. Ready prompt ─────────────────────────────────────────────── */
    print_ready_footer();

    /*
     * app_main returns here — the following tasks are alive and running:
     *   · cli_task        (pin core 1)  — reads stdin, dispatches commands
     *   · wifi_worker     (pin core 1)  — processes packet queue
     *   · led_task        (pin core 1)  — LED animation loop
     *   · ble_host_task   (NimBLE)      — BLE host stack
     */
}