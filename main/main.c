/*
 * ============================================================================
 *  ESP32-S3 · WIRELESS LAB TOOLKIT · main.c
 * ============================================================================
 *  Target   : ESP32-S3-N16R8  (16 MB Flash · 8 MB PSRAM)
 *  Interface: USB-OTG CDC / UART CLI
 *
 *  Notes:
 *    - When USB CDC is detected, the firmware assumes machine/control mode.
 *    - ANSI console output is suppressed in machine mode.
 *    - JSON-RPC initialization must be wired here before production use.
 * ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "nvs_flash.h"

#include "helper.h"   /* aggregate include — pulls in every module header */

#define TAG "main"

/* ═══════════════════════════════════════════════════════════════════════════
 *  ANSI colour macros
 * ═══════════════════════════════════════════════════════════════════════════ */

#define UI_RESET   "\033[0m"
#define UI_BOLD    "\033[1m"
#define UI_RED     "\033[91m"
#define UI_GREEN   "\033[92m"
#define UI_YELLOW  "\033[93m"
#define UI_BLUE    "\033[94m"
#define UI_MAGENTA "\033[95m"
#define UI_CYAN    "\033[96m"
#define UI_WHITE   "\033[97m"
#define UI_GRAY    "\033[90m"

/* ═══════════════════════════════════════════════════════════════════════════
 *  Build-time constants
 * ═══════════════════════════════════════════════════════════════════════════ */

#define RING_BYTES       (2UL * 1024UL * 1024UL)  /* PCAP ring in PSRAM */
#define BOOT_SCAN_SECS   4                         /* quick startup scan */
#define BOX_W            70                        /* terminal line width */

/* ═══════════════════════════════════════════════════════════════════════════
 *  Boot state
 * ═══════════════════════════════════════════════════════════════════════════ */

static bool s_machine_mode = false;      /* true when phone/CDC control expected */
static bool s_boot_failed = false;       /* critical init failure */
static bool s_boot_degraded = false;     /* optional module failure */
static bool s_led_ready = false;         /* LED module successfully initialized */

static port_detect_result_t s_port = {0};

/* ═══════════════════════════════════════════════════════════════════════════
 *  Small UI helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static void ui_hr(const char *ch)
{
    if (s_machine_mode) {
        return;
    }

    printf(UI_GRAY "  ");
    for (int i = 0; i < BOX_W - 2; i++) {
        fputs(ch, stdout);
    }
    printf(UI_RESET "\n");
}

static void ui_section(const char *title)
{
    if (s_machine_mode) {
        return;
    }

    printf(UI_CYAN "\n  ┌─ " UI_BOLD UI_WHITE "%s" UI_RESET "\n", title);
}

static void ui_kv(const char *key, const char *val)
{
    if (s_machine_mode) {
        return;
    }

    printf("  " UI_CYAN "│" UI_RESET "  " UI_GRAY "%-24s" UI_RESET UI_WHITE "%s" UI_RESET "\n",
           key, val);
}

static void ui_cap(const char *icon, const char *label, const char *desc)
{
    if (s_machine_mode) {
        return;
    }

    printf("  " UI_CYAN "│" UI_RESET "  %s  " UI_BOLD UI_WHITE "%-22s" UI_RESET UI_GRAY "%s" UI_RESET "\n",
           icon, label, desc);
}

static void init_report(const char *label, esp_err_t err, bool optional)
{
    if (err == ESP_OK) {
        if (!s_machine_mode) {
            printf("  " UI_CYAN "│" UI_RESET "  " UI_GREEN "✔" UI_RESET
                   "  %-45s " UI_GREEN "OK" UI_RESET "\n",
                   label);
        }
        return;
    }

    if (err == ESP_ERR_INVALID_STATE) {
        if (!s_machine_mode) {
            printf("  " UI_CYAN "│" UI_RESET "  " UI_BLUE "✔" UI_RESET
                   "  %-45s " UI_BLUE "already" UI_RESET "\n",
                   label);
        } else {
            ESP_LOGI(TAG, "%s already initialized", label);
        }
        return;
    }

    if (optional) {
        s_boot_degraded = true;

        if (!s_machine_mode) {
            printf("  " UI_CYAN "│" UI_RESET "  " UI_YELLOW "⚠" UI_RESET
                   "  %-45s " UI_YELLOW "skip" UI_GRAY "  (%s)" UI_RESET "\n",
                   label, esp_err_to_name(err));
        }

        ESP_LOGW(TAG, "Optional init skipped: %s (%s)", label, esp_err_to_name(err));
        return;
    }

    s_boot_failed = true;

    if (!s_machine_mode) {
        printf("  " UI_CYAN "│" UI_RESET "  " UI_RED "✖" UI_RESET
               "  %-45s " UI_RED "FAIL" UI_GRAY "  [%s]" UI_RESET "\n",
               label, esp_err_to_name(err));
    }

    ESP_LOGE(TAG, "Critical init failed: %s (%s)", label, esp_err_to_name(err));
}

#define BOOT_INIT(label, expr, optional)                    \
    do {                                                    \
        esp_err_t boot_init_err = (expr);                   \
        init_report((label), boot_init_err, (optional));    \
    } while (0)

/* ═══════════════════════════════════════════════════════════════════════════
 *  NVS bootstrap
 * ═══════════════════════════════════════════════════════════════════════════ */

static esp_err_t bootstrap_nvs(void)
{
    esp_err_t err = nvs_flash_init();

    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition invalid (%s); erasing and retrying", esp_err_to_name(err));

        esp_err_t erase_err = nvs_flash_erase();
        if (erase_err != ESP_OK) {
            return erase_err;
        }

        err = nvs_flash_init();
    }

    return err;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Formatting helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static void format_mac(char *out, size_t out_len, const uint8_t mac[6])
{
    if (out == NULL || out_len < 18) {
        if (out != NULL && out_len > 0) {
            out[0] = '\0';
        }
        return;
    }

    snprintf(out, out_len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  BANNER
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_banner(void)
{
    if (s_machine_mode) {
        return;
    }

    /* Clear screen for clean boot look. */
    printf("\033[2J\033[H");

    puts("");

    printf(UI_CYAN
        "  ╔══════════════════════════════════════════════════════════════════╗\n"
        "  ║                                                                  ║\n"
    UI_RESET);

    printf(UI_CYAN "  ║  " UI_RESET UI_YELLOW UI_BOLD
        "   W . L . A . B   ·   W I R E L E S S   L A B   T K   "
    UI_RESET UI_CYAN "  ║\n" UI_RESET);

    printf(UI_CYAN "  ║  " UI_RESET UI_GRAY
        "                  E S P 3 2 - S 3  ·  N 1 6 R 8              "
    UI_RESET UI_CYAN "  ║\n" UI_RESET);

    printf(UI_CYAN
        "  ║                                                                  ║\n"
        "  ╠══════════════════════════════════════════════════════════════════╣\n"
    UI_RESET);

    printf(UI_CYAN "  ║  " UI_RESET UI_GRAY
        "  802.11bgn Sniffer  ·  BLE 5.0  ·  ARP MITM  ·  WPA2 Crack    "
    UI_RESET UI_CYAN "║\n" UI_RESET);

    printf(UI_CYAN "  ║  " UI_RESET UI_GRAY
        "  PCAP Ring  ·  Deauth  ·  Evil Portal  ·  Cred Sniffer         "
    UI_RESET UI_CYAN "║\n" UI_RESET);

    printf(UI_CYAN
        "  ╚══════════════════════════════════════════════════════════════════╝\n"
    UI_RESET);

    puts("");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  SYSTEM INFORMATION
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_sysinfo(void)
{
    if (s_machine_mode) {
        return;
    }

    ui_section("Hardware · Firmware");

    esp_chip_info_t ci = {0};
    esp_chip_info(&ci);

    uint32_t flash_size = 0;
    if (esp_flash_get_size(NULL, &flash_size) != ESP_OK) {
        flash_size = 0;
    }

    uint32_t flash_kb = flash_size / 1024;

    size_t int_total = heap_caps_get_total_size(MALLOC_CAP_INTERNAL);
    size_t int_free  = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t ps_total  = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    size_t ps_free   = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

    uint8_t mac_sta[6] = {0};
    uint8_t mac_ap[6]  = {0};
    uint8_t mac_bt[6]  = {0};

    if (esp_read_mac(mac_sta, ESP_MAC_WIFI_STA) != ESP_OK) {
        memset(mac_sta, 0, sizeof(mac_sta));
    }

    if (esp_read_mac(mac_ap, ESP_MAC_WIFI_SOFTAP) != ESP_OK) {
        memset(mac_ap, 0, sizeof(mac_ap));
    }

    if (esp_read_mac(mac_bt, ESP_MAC_BT) != ESP_OK) {
        memset(mac_bt, 0, sizeof(mac_bt));
    }

    char buf[80];
    char mac_str[24];

    snprintf(buf, sizeof(buf), "ESP32-S3 rev %d · %d cores", ci.revision, ci.cores);
    ui_kv("Chip :", buf);

    snprintf(buf, sizeof(buf), "%" PRIu32 " kB", flash_kb);
    ui_kv("Flash :", buf);

    snprintf(buf, sizeof(buf), "%zu kB free / %zu kB total",
             int_free / 1024, int_total / 1024);
    ui_kv("Internal RAM :", buf);

    snprintf(buf, sizeof(buf), "%zu kB free / %zu kB total",
             ps_free / 1024, ps_total / 1024);
    ui_kv("PSRAM :", buf);

    ui_kv("IDF Version :", IDF_VER);

    format_mac(mac_str, sizeof(mac_str), mac_sta);
    ui_kv("MAC · STA :", mac_str);

    format_mac(mac_str, sizeof(mac_str), mac_ap);
    ui_kv("MAC · SoftAP :", mac_str);

    format_mac(mac_str, sizeof(mac_str), mac_bt);
    ui_kv("MAC · BT :", mac_str);

    printf("  " UI_CYAN "│" UI_RESET "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  MODULE INITIALISATION SEQUENCE
 * ═══════════════════════════════════════════════════════════════════════════ */

static void run_init_sequence(void)
{
    ui_section("Module Initialisation");

    if (!s_machine_mode) {
        port_print_banner(&s_port);
    } else {
        ESP_LOGI(TAG, "Port detection complete; active transport=%d", (int)s_port.active);
    }

    BOOT_INIT("NVS Persistence (settings/targets)", nvs_persist_init(), true);

    if (s_port.active == PORT_TRANSPORT_CDC) {
        ESP_LOGI(TAG, "USB CDC active: companion app/JSON-RPC transport expected");
    }

    /* LED indicator */
    esp_err_t led_err = helper_init();
    init_report("LED Indicator (WS2812, GPIO 48)", led_err, false);

    if (led_err == ESP_OK || led_err == ESP_ERR_INVALID_STATE) {
        s_led_ready = true;
        led_set_rgb(0, 200, 255);
        vTaskDelay(pdMS_TO_TICKS(120));
        led_set_state(LED_STATE_SCANNING);
    }

    /* Core system services */
    BOOT_INIT("Structured Logging (ring + JSON)", structured_log_init(), false);
    BOOT_INIT("Watchdog + Panic Handler", watchdog_init(), false);
    BOOT_INIT("Health Telemetry (heap/PSRAM/temp/uptime)", health_telemetry_init(), false);

    /*
     * USB CDC is critical in machine mode, optional in UART CLI mode.
     */
    BOOT_INIT("USB CDC-ACM Custom VID/PID", usb_cdc_init(), !s_machine_mode);

    /*
     * TODO: initialize JSON-RPC server here.
     *
     * This is currently missing from the boot flow.
     * Without JSON-RPC initialization, phone control over USB CDC will not work.
     *
     * Likely future calls:
     *
     *   BOOT_INIT("JSON-RPC Server", jsonrpc_init(), false);
     *   BOOT_INIT("JSON-RPC Schema", jsonrpc_schema_init(), false);
     *
     * The exact function names depend on jsonrpc.h / jsonrpc_schema.h.
     */
    if (s_port.active == PORT_TRANSPORT_CDC) {
        ESP_LOGW(TAG, "JSON-RPC server is not initialized in main.c yet. "
                      "Phone control will not work until this is wired.");
    }

    /* Storage and update services */
    BOOT_INIT("SD Card Storage (SPI2, /sd)", storage_init(), true);
    BOOT_INIT("SPIFFS Wordlist Store (5 MiB)", storage_spiffs_init(), true);
    BOOT_INIT("OTA Updater (HTTP + RSA-2048)", ota_http_init(), true);

    /* AI / analysis modules */
    BOOT_INIT("AI Model Zoo", ai_model_zoo_init(), false);
    BOOT_INIT("AI Classifier", ai_classifier_init(), false);
    BOOT_INIT("AI Anomaly", ai_anomaly_init(), false);
    BOOT_INIT("AI Fingerprint", ai_fingerprint_init(), false);
    BOOT_INIT("AI Channel Predictor", ai_channel_predictor_init(), false);
    BOOT_INIT("AI Handshake Quality", ai_hs_quality_init(), false);
    BOOT_INIT("AI Rogue Detector", ai_rogue_detector_init(), false);
    BOOT_INIT("AI Deauth Predictor", ai_deauth_predictor_init(), false);
    BOOT_INIT("AI BLE Profiler", ai_ble_profiler_init(), false);
    BOOT_INIT("AI Training", ai_train_init(), false);

    /* Automation / planning / reaction */
    BOOT_INIT("Wardrive", wardrive_init(), false);
    BOOT_INIT("Attack Planner", attack_planner_init(), false);
    BOOT_INIT("Stealth", stealth_init(), false);
    BOOT_INIT("Scheduler", scheduler_init(), false);
    BOOT_INIT("Reaction Rules", reaction_rules_init(), false);

    /* Export / offensive core / CLI bridge */
    BOOT_INIT("Export", export_init(), false);
    BOOT_INIT("Offensive Core", offensive_init(), false);
    BOOT_INIT("CLI Flipper", cli_flipper_init(), false);

    /* Wi-Fi security extensions */
    BOOT_INIT("PMKID Capture", pmkid_init(), false);
    BOOT_INIT("SAE Side-Channel", sae_sidechannel_init(), false);
    BOOT_INIT("Dragonfly Simulator", dragonfly_sim_init(), false);
    BOOT_INIT("FT Roaming", ft_roam_init(), false);
    BOOT_INIT("Neighbor Report", neighbor_report_init(), false);
    BOOT_INIT("BTM", btm_init(), false);
    BOOT_INIT("WPS Pixie Dust", wps_pixiedust_init(), false);
    BOOT_INIT("EAP Capture", eap_capture_init(), false);

    /*
     * TODO: audit channel_hopper lifecycle.
     *
     * channel_hopper.c is compiled, but no explicit channel_hopper_init()
     * appears here. It may be managed internally by wifi_sniffer.c, but that
     * should be made explicit.
     */

    /* Wi-Fi core */
    BOOT_INIT("Wi-Fi Coexistence", coex_init(), false);
    BOOT_INIT("Wi-Fi Sniffer", wifi_sniffer_init(), false);

    /* BLE core */
    BOOT_INIT("BLE 5.0 Scanner (NimBLE host)", ble_scanner_init(), false);
    BOOT_INIT("GPS Timestamp Correlator", gps_init(), false);

    /*
     * TODO: audit BLE submodules.
     *
     * These are compiled but not explicitly initialized here:
     *
     *   ble_ext_adv.c
     *   ble_periodic.c
     *   ble_phy.c
     *   ble_iso.c
     *   ble_gatt_client.c
     *   ble_gatt_enumerator.c
     *   ble_mitm.c
     *   ble_rpa_bypass.c
     *   ble_findmy.c
     *   ble_smarttag.c
     *   ble_privacy.c
     *
     * If they are started internally by ble_scanner.c, that should be documented.
     * Otherwise they need explicit lifecycle calls.
     */

    /* Network attack/capture engines */
    BOOT_INIT("ARP Poison Engine (MITM + relay)", arp_poison_init(), false);
    BOOT_INIT("HTTP Credential Sniffer (form/cookie/Basic)", creds_init(), false);
    BOOT_INIT("WPA-2 Handshake Capture + Crack (EAPOL)", handshake_init(), false);

    /* Packet capture buffer */
    BOOT_INIT("PCAP Ring Buffer (2 MiB PSRAM)", pcap_ring_init(RING_BYTES), false);

    /*
     * In CDC machine mode, JSON-RPC should own the control transport.
     * CLI is kept for compatibility until JSON-RPC is fully wired.
     */
    if (s_port.active == PORT_TRANSPORT_CDC) {
        ESP_LOGW(TAG, "CDC active: JSON-RPC should own transport. "
                      "cli_start() is still called for compatibility.");
    }

    BOOT_INIT("Interactive Serial CLI (auto-selected transport)", cli_start(), false);

    if (!s_machine_mode) {
        printf("  " UI_CYAN "│" UI_RESET "\n");
    }

    if (s_led_ready && !s_boot_failed) {
        led_set_state(LED_STATE_IDLE);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  QUICK BOOT SCAN
 * ═══════════════════════════════════════════════════════════════════════════ */

static void run_boot_scan(void)
{
    if (s_machine_mode || s_boot_failed) {
        return;
    }

    char title[128];
    snprintf(title, sizeof(title),
             "Boot Scan — " UI_YELLOW UI_BOLD "Wi-Fi" UI_RESET
             " (" UI_GRAY "passive, %d s" UI_RESET ")",
             BOOT_SCAN_SECS);

    ui_section(title);

    printf("  " UI_CYAN "│" UI_RESET "\n");
    printf("  " UI_CYAN "│" UI_RESET "  " UI_GRAY
           "Hopping channels 1-13, gathering nearby APs & clients …"
           UI_RESET "\n");
    printf("  " UI_CYAN "│" UI_RESET "\n");

    if (s_led_ready) {
        led_set_state(LED_STATE_SCANNING);
    }

    esp_err_t r = wifi_sniffer_start(BOOT_SCAN_SECS);
    if (r != ESP_OK) {
        printf("  " UI_CYAN "│" UI_RESET "  " UI_RED "scan skipped: %s" UI_RESET "\n",
               esp_err_to_name(r));
    } else {
        /*
         * Wait for the scan to finish.
         *
         * TODO: replace this delay with a proper completion event/callback
         * from wifi_sniffer/channel_hopper.
         */
        vTaskDelay(pdMS_TO_TICKS((BOOT_SCAN_SECS + 1) * 1000));

        uint16_t ap_cnt  = wifi_sniffer_get_ap_count();
        uint16_t cli_cnt = wifi_sniffer_get_client_count();

        char buf[80];
        snprintf(buf, sizeof(buf),
                 UI_GREEN "%u" UI_RESET " access points · " UI_GREEN "%u" UI_RESET " clients",
                 ap_cnt, cli_cnt);

        ui_kv("Discovered :", buf);
    }

    if (s_led_ready) {
        led_set_state(LED_STATE_IDLE);
    }

    printf("  " UI_CYAN "│" UI_RESET "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  CAPABILITY REFERENCE TABLE
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_capabilities(void)
{
    if (s_machine_mode) {
        return;
    }

    ui_section("Feature Reference — authorized lab use only; type " UI_YELLOW "help" UI_RESET " for syntax");

    printf("  " UI_CYAN "│" UI_RESET "\n");

    ui_cap(UI_CYAN "◈" UI_RESET, "wifi start / pcap", "promiscuous 802.11 sniffer, optional PCAP to SD");
    ui_cap(UI_GREEN "◈" UI_RESET, "ble start / results", "BLE 5.0 scanner with tracker heuristics");
    ui_cap(UI_YELLOW "◈" UI_RESET, "deauth ap / client", "802.11 deauthentication (authorized lab only)");
    ui_cap(UI_MAGENTA "◈" UI_RESET, "arp poison", "ARP MITM with transparent relay to gateway");
    ui_cap(UI_RED "◈" UI_RESET, "creds on / show", "HTTP clear-text credential capture");
    ui_cap(UI_CYAN "◈" UI_RESET, "pcap start / export", "ring-buffer capture; export to SD or serial");
    ui_cap(UI_GREEN "◈" UI_RESET, "beacon spam", "fake-AP beacon generation for lab testing");
    ui_cap(UI_YELLOW "◈" UI_RESET, "portal start", "captive portal testing on owned/open lab AP");
    ui_cap(UI_MAGENTA "◈" UI_RESET, "rogue start", "SSID clone for authorized rogue-AP testing");
    ui_cap(UI_RED "◈" UI_RESET, "probe start", "probe-request generation for lab testing");
    ui_cap(UI_CYAN "◈" UI_RESET, "doj start", "deauth-on-join sentry for controlled lab use");
    ui_cap(UI_GREEN "◈" UI_RESET, "analyzer", "per-channel activity dwell analysis (1-13)");
    ui_cap(UI_YELLOW "◈" UI_RESET, "oui <mac>", "OUI vendor lookup from on-device table");
    ui_cap(UI_MAGENTA "◈" UI_RESET, "save wifi / ble", "write discovered device report to SD card");

    printf("  " UI_CYAN "│" UI_RESET "\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  READY FOOTER
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_ready_footer(void)
{
    if (s_machine_mode) {
        return;
    }

    ui_hr("─");

    printf("\n");
    printf(UI_GRAY "  Uptime      : " UI_RESET UI_WHITE "%" PRId64 " ms" UI_RESET "\n",
           esp_timer_get_time() / 1000LL);

    printf(UI_GRAY "  PCAP ring   : " UI_RESET UI_WHITE "2 MiB ready  "
           UI_GRAY "(pcap start → pcap export)" UI_RESET "\n");

    if (storage_is_ready()) {
        printf(UI_GRAY "  SD card     : " UI_RESET UI_GREEN "mounted at /sd" UI_RESET "\n");
    } else {
        printf(UI_GRAY "  SD card     : " UI_RESET UI_YELLOW "not present  "
               UI_GRAY "(insert for file export)" UI_RESET "\n");
    }

    if (s_boot_degraded) {
        printf(UI_YELLOW "  Boot state  : degraded — one or more optional modules failed" UI_RESET "\n");
    } else {
        printf(UI_GREEN "  Boot state  : healthy" UI_RESET "\n");
    }

    printf("\n");
    printf("  " UI_BOLD UI_CYAN
           "──────────────────────────────────────────────────────────────"
           UI_RESET "\n");
    printf("  " UI_BOLD UI_WHITE "  Console ready.  Type " UI_RESET
           UI_YELLOW UI_BOLD "help" UI_RESET UI_BOLD UI_WHITE
           " for the full command reference." UI_RESET "\n");
    printf("  " UI_BOLD UI_CYAN
           "──────────────────────────────────────────────────────────────"
           UI_RESET "\n");
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════ */

void app_main(void)
{
    /*
     * Boot order:
     *   1. NVS bootstrap
     *   2. transport detection
     *   3. banner/sysinfo if human console mode
     *   4. module init
     *   5. optional quick scan
     *   6. capability/help footer
     */

    esp_err_t nvs_err = bootstrap_nvs();
    if (nvs_err != ESP_OK) {
        ESP_LOGE(TAG, "NVS bootstrap failed: %s", esp_err_to_name(nvs_err));
        s_boot_failed = true;
    }

    boot_port_detect(&s_port);
    s_machine_mode = (s_port.active == PORT_TRANSPORT_CDC);

    if (s_machine_mode) {
        ESP_LOGI(TAG, "Machine mode: USB CDC detected; suppressing ANSI console");
    }

    print_banner();
    print_sysinfo();
    run_init_sequence();

    if (!s_boot_failed) {
        run_boot_scan();
        print_capabilities();
        print_ready_footer();
    } else {
        ESP_LOGE(TAG, "Critical initialization failure detected");

        if (!s_machine_mode) {
            printf("\n  " UI_RED UI_BOLD "Critical initialization failure." UI_RESET "\n");
            printf("  Check ESP_LOG output and fix failing modules before continuing.\n\n");
        }
    }

    if (s_led_ready) {
        if (s_boot_failed) {
            led_set_rgb(255, 0, 0);
        } else if (s_boot_degraded) {
            led_set_rgb(255, 160, 0);
        } else {
            led_set_state(LED_STATE_IDLE);
        }
    }

    if (s_boot_failed) {
        ESP_LOGE(TAG, "Boot finished with critical errors");
    } else if (s_boot_degraded) {
        ESP_LOGW(TAG, "Boot finished in degraded state");
    } else {
        ESP_LOGI(TAG, "Boot complete");
    }

    /*
     * app_main returns here.
     *
     * Expected long-running tasks:
     *   - CLI task
     *   - USB CDC / JSON-RPC task(s)
     *   - Wi-Fi sniffer/worker task(s)
     *   - BLE host stack task(s)
     *   - LED task
     *   - watchdog/health task(s)
     */
}
