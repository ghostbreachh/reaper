/*
 * ============================================================================
 *  cli_module.c  —  Interactive UART0 console for the ESP32-S3 Wireless Lab
 *  Toolkit.  Drop-in replacement — full command set preserved.
 *
 *  WHY THIS VERSION WORKS WHERE THE OLD ONE LOCKED UP
 *  -------------------------------------------------
 *  The old CLI read from `stdin`.  `stdin` is routed through the console VFS,
 *  which the generated project pointed at a USB-CDC path (the phone/OTG plan).
 *  With the board on a PC's COM port (UART0 = GPIO43 TX / GPIO44 RX), that
 *  read side never delivers data, so fgets() returned NULL instantly and the
 *  task re-printed "toolkit> " forever.
 *
 *  This version bypasses stdin completely:
 *    · installs the UART0 driver (safe if the console VFS already did)
 *    · reads input with uart_read_bytes() straight off UART0
 *    · echoes typed characters, supports backspace, \r or \n ends a line
 *    · the prompt is printed once per command — zero spam
 *
 *  Interface: USB-UART bridge -> COM port @ 115200 8N1
 * ============================================================================
 */

#include "cli_module.h"
#include "led_indicator.h"
#include "wifi_sniffer.h"
#include "ble_scanner.h"
#include "storage_sd.h"
#include "deauth_engine.h"
#include "arp_poison.h"
#include "pcap_ring.h"
#include "cred_sniffer.h"
#include "beacon_spam.h"
#include "extra_offense.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#include "esp_system.h"
#include "esp_timer.h"
#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "cli";

/* ---------------------------------------------------------------------------
 *  UART0 console configuration
 * ------------------------------------------------------------------------- */
#define CLI_UART        UART_NUM_0
#define CLI_UART_BAUD   115200
#define CLI_UART_RX_BUF 1024            /* RX ring buffer, plenty for typing */
#define CLI_UART_TXD    43              /* ESP32-S3 U0TXD -> bridge RX      */
#define CLI_UART_RXD    44              /* ESP32-S3 U0RXD <- bridge TX      */

/* Small ANSI colour for the prompt (matches main.c banner style) */
#define CLR_CYN "\033[96m"
#define CLR_RST "\033[0m"

/* ---------------------------------------------------------------------------
 *  UART0 driver bring-up.
 *
 *  If the console VFS already installed the driver (ESP_ERR_INVALID_STATE),
 *  that is fine — we just use it.  If not, we install it ourselves so that
 *  uart_read_bytes() below can never return "uart driver error".
 * ------------------------------------------------------------------------- */
static esp_err_t cli_uart_init(void)
{
    esp_err_t ret = uart_driver_install(CLI_UART, CLI_UART_RX_BUF, 0, 0, NULL, 0);
    if (ret == ESP_ERR_INVALID_STATE) {
        ESP_LOGI(TAG, "UART0 driver already installed (console VFS)");
        ret = ESP_OK;
    }
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "UART0 driver install failed: %s", esp_err_to_name(ret));
        return ret;
    }

    uart_config_t cfg = {
        .baud_rate  = CLI_UART_BAUD,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,    /* 80 MHz APB on ESP32-S3 */
    };

    ret = uart_param_config(CLI_UART, &cfg);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "uart_param_config: %s", esp_err_to_name(ret));
    }

    ret = uart_set_pin(CLI_UART, CLI_UART_TXD, CLI_UART_RXD,
                       UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "uart_set_pin: %s", esp_err_to_name(ret));
    }

    ESP_LOGI(TAG, "UART0 console @ %d baud (TXD=GPIO%d RXD=GPIO%d)",
             CLI_UART_BAUD, CLI_UART_TXD, CLI_UART_RXD);
    return ESP_OK;
}

/* ---------------------------------------------------------------------------
 *  Read one command line from UART0.
 *  · echoes printable characters so typing is visible
 *  · backspace (BS / DEL) edits the line
 *  · both \r and \n terminate the line (handles CRLF from Windows terminals)
 *  · returns 0 on a complete line, -1 after 60 s of silence (no spam)
 * ------------------------------------------------------------------------- */
static int cli_read_line(char *line, size_t size)
{
    size_t i = 0;
    bool got_any = false;

    for (;;) {
        uint8_t c = 0;
        int n = uart_read_bytes(CLI_UART, &c, 1, pdMS_TO_TICKS(60000));
        if (n != 1) {
            return -1;                      /* 60 s of silence: give up */
        }

        if (c == '\r' || c == '\n') {
            if (!got_any) {
                continue;                   /* stray EOL (CR of a CRLF pair) */
            }
            line[i] = '\0';
            uart_write_bytes(CLI_UART, (const uint8_t *)"\r\n", 2);
            return 0;
        }

        got_any = true;

        if (c == 0x08 || c == 0x7F) {       /* backspace / DEL */
            if (i > 0) {
                i--;
                uart_write_bytes(CLI_UART, (const uint8_t *)"\b \b", 3);
            }
            continue;
        }

        if (c < 0x20) {
            continue;                       /* drop other control bytes */
        }

        if (i < size - 1) {
            line[i++] = (char)c;
            uart_write_bytes(CLI_UART, &c, 1);      /* echo */
        }
    }
}

/* ---------------------------------------------------------------------------
 *  Argument helper
 * ------------------------------------------------------------------------- */
static uint32_t arg_to_u32(const char *s, uint32_t def)
{
    if (s == NULL || s[0] == '\0') {
        return def;
    }
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (end == s) {
        return def;
    }
    return (uint32_t)v;
}

/* ---------------------------------------------------------------------------
 *  Help
 * ------------------------------------------------------------------------- */
static void cli_print_help(void)
{
    printf("\n");
    printf("ESP32-S3 Wireless Lab Toolkit\n");
    printf("Commands:\n");
    printf("  help\n");
    printf("  reboot\n");
    printf("\n");
    printf("  led off | idle | scan | conn | error\n");
    printf("  led rgb <r> <g> <b>\n");
    printf("\n");
    printf("  storage status\n");
    printf("\n");
    printf("  wifi start [seconds]\n");
    printf("  wifi pcap [seconds]\n");
    printf("  wifi stop\n");
    printf("  wifi results\n");
    printf("  wifi stats\n");
    printf("\n");
    printf("  ble start [seconds]\n");
    printf("  ble stop\n");
    printf("  ble results\n");
    printf("  ble trackers\n");
    printf("\n");
    printf("  adv start [seconds] [name]\n");
    printf("  adv stop\n");
    printf("\n");
    printf("  deauth ap <bssid> [count]\n");
    printf("  deauth client <bssid> <client> [count]\n");
    printf("  deauth stop\n");
    printf("\n");
    printf("  arp poison <victim_ip> [gateway_ip] [interval_ms]\n");
    printf("  arp stop | status | table\n");
    printf("  arp relay on|off\n");
    printf("\n");
    printf("  pcap start [secs] | stop | info | wipe\n");
    printf("  pcap save [path] | export\n");
    printf("\n");
    printf("  save wifi\n");
    printf("  save ble\n");
    printf("\n");
    printf("  creds on|off|show|clear|save\n");
    printf("\n");
    printf("  beacon spam [ch] | stop\n");
    printf("  rogue start <ssid> [ch] [open|wpa2] | stop\n");
    printf("  portal start <ssid> [ch] | stop | creds\n");
    printf("\n");
    printf("  probe start <ssid> <count> [ch] | stop\n");
    printf("  doj start <bssid> | stop\n");
    printf("  oui <mac>\n");
    printf("  analyzer [seconds_per_channel]\n");
    printf("\n");
}

/* ---------------------------------------------------------------------------
 *  CLI task — read a line from UART0, tokenise, dispatch
 * ------------------------------------------------------------------------- */
static void cli_task(void *arg)
{
    char line[192];

    printf("\n");
    printf("Console ready on UART0 (COM port) @ 115200. Type 'help'.\n");

    printf(CLR_CYN "toolkit> " CLR_RST);
    fflush(stdout);

    while (1) {
        if (cli_read_line(line, sizeof(line)) != 0) {
            continue;                       /* silence timeout: no spam */
        }

        if (line[0] == '\0') {
            printf(CLR_CYN "toolkit> " CLR_RST);
            fflush(stdout);
            continue;
        }

        char *argv[8] = {0};
        int argc = 0;
        char *saveptr = NULL;

        char *token = strtok_r(line, " ", &saveptr);
        while (token != NULL && argc < 8) {
            argv[argc++] = token;
            token = strtok_r(NULL, " ", &saveptr);
        }

        if (argc == 0) {
            printf(CLR_CYN "toolkit> " CLR_RST);
            fflush(stdout);
            continue;
        }

        if (strcmp(argv[0], "help") == 0) {
            cli_print_help();
        } else if (strcmp(argv[0], "reboot") == 0) {
            esp_restart();
        } else if (strcmp(argv[0], "storage") == 0) {
            if (argc >= 2 && strcmp(argv[1], "status") == 0) {
                if (storage_is_ready()) {
                    printf("SD card ready.\n");
                    sdmmc_card_print_info(stdout, g_sd_card);
                } else {
                    printf("SD card not ready.\n");
                }
            } else {
                printf("Usage: storage status\n");
            }
        } else if (strcmp(argv[0], "led") == 0) {
            if (argc < 2) {
                printf("Usage: led off|idle|scan|conn|error|rgb\n");
            } else if (strcmp(argv[1], "off") == 0) {
                led_set_state(LED_STATE_OFF);
            } else if (strcmp(argv[1], "idle") == 0) {
                led_set_state(LED_STATE_IDLE);
            } else if (strcmp(argv[1], "scan") == 0) {
                led_set_state(LED_STATE_SCANNING);
            } else if (strcmp(argv[1], "conn") == 0) {
                led_set_state(LED_STATE_CONNECTED);
            } else if (strcmp(argv[1], "error") == 0) {
                led_set_state(LED_STATE_ERROR);
            } else if (strcmp(argv[1], "rgb") == 0) {
                if (argc >= 5) {
                    uint8_t r = (uint8_t)(arg_to_u32(argv[2], 0) & 0xFF);
                    uint8_t g = (uint8_t)(arg_to_u32(argv[3], 0) & 0xFF);
                    uint8_t b = (uint8_t)(arg_to_u32(argv[4], 0) & 0xFF);
                    led_set_rgb(r, g, b);
                } else {
                    printf("Usage: led rgb <r> <g> <b>\n");
                }
            } else {
                printf("Unknown led mode\n");
            }
        } else if (strcmp(argv[0], "wifi") == 0) {
            if (argc < 2) {
                printf("Usage: wifi start|pcap|stop|results|stats\n");
            } else if (strcmp(argv[1], "start") == 0) {
                uint32_t duration = arg_to_u32(argv[2], 10);

                esp_err_t ret = wifi_sniffer_start(duration);
                if (ret != ESP_OK) {
                    printf("wifi start failed: %s\n", esp_err_to_name(ret));
                } else if (duration > 0) {
                    printf("Wi-Fi sniffer running for %u s. Use 'wifi stop'.\n", (unsigned)duration);
                } else {
                    printf("Wi-Fi sniffer running indefinitely. Use 'wifi stop'.\n");
                }
            } else if (strcmp(argv[1], "pcap") == 0) {
                uint32_t duration = arg_to_u32(argv[2], 10);

                esp_err_t ret = wifi_sniffer_start_pcap(duration);
                if (ret != ESP_OK) {
                    printf("wifi pcap failed: %s\n", esp_err_to_name(ret));
                } else if (duration > 0) {
                    printf("Wi-Fi PCAP running for %u s. Use 'wifi stop'.\n", (unsigned)duration);
                } else {
                    printf("Wi-Fi PCAP running indefinitely. Use 'wifi stop'.\n");
                }
            } else if (strcmp(argv[1], "stop") == 0) {
                wifi_sniffer_stop();
            } else if (strcmp(argv[1], "results") == 0) {
                wifi_sniffer_print_results();
            } else if (strcmp(argv[1], "stats") == 0) {
                wifi_sniffer_print_stats();
            } else {
                printf("Unknown wifi command\n");
            }
        } else if (strcmp(argv[0], "ble") == 0) {
            if (argc < 2) {
                printf("Usage: ble start|stop|results|trackers\n");
            } else if (strcmp(argv[1], "start") == 0) {
                uint32_t duration = arg_to_u32(argv[2], 10);

                esp_err_t ret = ble_scanner_start(duration);
                if (ret != ESP_OK) {
                    printf("ble start failed: %s\n", esp_err_to_name(ret));
                } else if (duration > 0) {
                    printf("BLE scan running for %u s. Use 'ble stop'.\n", (unsigned)duration);
                } else {
                    printf("BLE scan running indefinitely. Use 'ble stop'.\n");
                }
            } else if (strcmp(argv[1], "stop") == 0) {
                ble_scanner_stop();
            } else if (strcmp(argv[1], "results") == 0) {
                ble_scanner_print_results();
            } else if (strcmp(argv[1], "trackers") == 0) {
                ble_tracker_print();
            } else {
                printf("Unknown ble command\n");
            }
        } else if (strcmp(argv[0], "adv") == 0) {
            if (argc < 2) {
                printf("Usage: adv start|stop\n");
            } else if (strcmp(argv[1], "start") == 0) {
                uint32_t duration = arg_to_u32(argv[2], 10);
                const char *name = (argc >= 4) ? argv[3] : "ESP32-S3-LAB";

                esp_err_t ret = ble_advertise_start(name, duration);
                if (ret != ESP_OK) {
                    printf("adv start failed: %s\n", esp_err_to_name(ret));
                } else {
                    printf("BLE identification advertisement started.\n");
                }
            } else if (strcmp(argv[1], "stop") == 0) {
                ble_advertise_stop();
            } else {
                printf("Unknown adv command\n");
            }
        } else if (strcmp(argv[0], "deauth") == 0) {
            if (argc < 2) {
                printf("Usage:\n");
                printf("  deauth ap <bssid> [count=100]         - Deauth all clients on AP\n");
                printf("  deauth client <bssid> <client> [count] - Deauth specific client\n");
                printf("  deauth stop\n");
                printf("  deauth list\n");
            } else if (strcmp(argv[1], "ap") == 0 && argc >= 3) {
                uint8_t bssid[6];
                if (sscanf(argv[2], "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                           &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) != 6) {
                    printf("Invalid BSSID format\n");
                } else {
                    uint32_t count = arg_to_u32(argv[3], 100);
                    deauth_remove_all();
                    deauth_attack_ap_all_clients(bssid, count, 0);
                    deauth_start();
                }
            } else if (strcmp(argv[1], "client") == 0 && argc >= 4) {
                uint8_t bssid[6], client[6];
                if (sscanf(argv[2], "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                           &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) != 6 ||
                    sscanf(argv[3], "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                           &client[0], &client[1], &client[2], &client[3], &client[4], &client[5]) != 6) {
                    printf("Invalid MAC format\n");
                } else {
                    uint32_t count = arg_to_u32(argv[4], 50);
                    deauth_remove_all();
                    deauth_add_target(bssid, client, count, 0);
                    deauth_start();
                }
            } else if (strcmp(argv[1], "stop") == 0) {
                deauth_stop();
                deauth_remove_all();
            } else if (strcmp(argv[1], "list") == 0) {
                printf("Deauth targets: %d\n", g_deauth_target_count);
                for (int i = 0; i < g_deauth_target_count; i++) {
                    printf("  [%d] BSSID: %02X:%02X:%02X:%02X:%02X:%02X -> CLIENT: %02X:%02X:%02X:%02X:%02X:%02X [count=%" PRIu32 " active=%d]\n",
                           i,
                           g_deauth_targets[i].bssid[0], g_deauth_targets[i].bssid[1],
                           g_deauth_targets[i].bssid[2], g_deauth_targets[i].bssid[3],
                           g_deauth_targets[i].bssid[4], g_deauth_targets[i].bssid[5],
                           g_deauth_targets[i].client_mac[0], g_deauth_targets[i].client_mac[1],
                           g_deauth_targets[i].client_mac[2], g_deauth_targets[i].client_mac[3],
                           g_deauth_targets[i].client_mac[4], g_deauth_targets[i].client_mac[5],
                           g_deauth_targets[i].count, g_deauth_targets[i].active);
                }
            } else {
                printf("Unknown deauth command\n");
            }
        } else if (strcmp(argv[0], "arp") == 0) {
            if (argc < 2) {
                printf("Usage:\n"
                       "  arp poison <victim_ip> [gateway_ip] [interval_ms]\n"
                       "  arp stop | status | table\n"
                       "  arp relay on|off\n");
            } else if (strcmp(argv[1], "poison") == 0 && argc >= 3) {
                const char *gw = (argc >= 4) ? argv[3] : NULL;
                const char *interval_arg = (argc >= 5) ? argv[4] : NULL;
                uint32_t iv = arg_to_u32(interval_arg, 2000);
                esp_err_t r = arp_poison_start(argv[2], gw, iv);
                printf("arp poison: %s\n", esp_err_to_name(r));
            } else if (strcmp(argv[1], "stop") == 0) {
                arp_poison_stop();
            } else if (strcmp(argv[1], "status") == 0) {
                arp_poison_print_status();
            } else if (strcmp(argv[1], "table") == 0) {
                arp_poison_print_table();
            } else if (strcmp(argv[1], "relay") == 0 && argc >= 3) {
                if (strcmp(argv[2], "on") == 0) {
                    arp_relay_set_enabled(true);
                    printf("relay on\n");
                } else if (strcmp(argv[2], "off") == 0) {
                    arp_relay_set_enabled(false);
                    printf("relay off\n");
                } else {
                    printf("Usage: arp relay on|off\n");
                }
            } else {
                printf("Unknown arp command\n");
            }
        } else if (strcmp(argv[0], "pcap") == 0) {
            if (argc < 2) {
                printf("Usage:\n  pcap start [secs] | stop | info | wipe\n"
                       "  pcap save [path] | export\n");
            } else if (strcmp(argv[1], "start") == 0) {
                uint32_t d = arg_to_u32(argv[2], 0);
                esp_err_t r = pcap_ring_start(d);
                printf("pcap start: %s\n", esp_err_to_name(r));
            } else if (strcmp(argv[1], "stop") == 0) {
                pcap_ring_stop();
            } else if (strcmp(argv[1], "info") == 0) {
                pcap_ring_print_info();
            } else if (strcmp(argv[1], "wipe") == 0) {
                pcap_ring_wipe();
                printf("ring wiped\n");
            } else if (strcmp(argv[1], "save") == 0) {
                char path[64];
                snprintf(path, sizeof(path), "/sd/ring_%" PRId64 ".pcap", esp_timer_get_time());
                if (argc >= 3) snprintf(path, sizeof(path), "%s", argv[2]);
                esp_err_t r = pcap_ring_save(path);
                printf("pcap save: %s (%s)\n", esp_err_to_name(r), path);
            } else if (strcmp(argv[1], "export") == 0) {
                pcap_ring_export_serial();
            } else {
                printf("Unknown pcap command\n");
            }
        } else if (strcmp(argv[0], "save") == 0) {
            if (!storage_is_ready()) {
                printf("SD card not ready.\n");
            } else if (argc < 2) {
                printf("Usage: save wifi | save ble\n");
            } else {
                char path[64];

                if (strcmp(argv[1], "wifi") == 0) {
                    snprintf(path, sizeof(path), "/sd/wifi_%" PRId64 ".txt",
                             esp_timer_get_time());
                    esp_err_t ret = wifi_sniffer_save_report(path);
                    if (ret == ESP_OK) {
                        printf("Saved: %s\n", path);
                    } else {
                        printf("Failed to save Wi-Fi report\n");
                    }
                } else if (strcmp(argv[1], "ble") == 0) {
                    snprintf(path, sizeof(path), "/sd/ble_%" PRId64 ".txt",
                             esp_timer_get_time());
                    esp_err_t ret = ble_scanner_save_report(path);
                    if (ret == ESP_OK) {
                        printf("Saved: %s\n", path);
                    } else {
                        printf("Failed to save BLE report\n");
                    }
                } else {
                    printf("Usage: save wifi | save ble\n");
                }
            }
        } else if (strcmp(argv[0], "creds") == 0) {
            if (argc < 2) {
                printf("Usage: creds on|off|show|clear|save\n");
            } else if (strcmp(argv[1], "on") == 0) {
                /* Needs sniffer running so we see data frames */
                if (!atomic_load(&g_wifi_sniffer_active)) wifi_sniffer_start(0);
                creds_set_enabled(true);
                printf("Credential sniffer ON\n");
            } else if (strcmp(argv[1], "off") == 0) {
                creds_set_enabled(false);
            } else if (strcmp(argv[1], "show") == 0) {
                creds_print();
            } else if (strcmp(argv[1], "clear") == 0) {
                creds_clear();
            } else if (strcmp(argv[1], "save") == 0) {
                char path[64];
                snprintf(path, sizeof(path), "/sd/creds_%" PRId64 ".txt", esp_timer_get_time());
                if (storage_is_ready() && creds_save(path) == ESP_OK)
                    printf("Saved %s\n", path);
                else
                    printf("Save failed (SD?)\n");
            }
        } else if (strcmp(argv[0], "beacon") == 0) {
            if (argc < 2) {
                printf("Usage: beacon spam [ch] | stop\n");
            } else if (strcmp(argv[1], "spam") == 0) {
                uint8_t ch = (uint8_t)arg_to_u32(argv[2], 6);
                printf("beacon spam: %s\n", esp_err_to_name(beacon_spam_start_builtin(ch)));
            } else if (strcmp(argv[1], "stop") == 0) {
                beacon_spam_stop();
            } else {
                printf("Unknown beacon command\n");
            }
        } else if (strcmp(argv[0], "rogue") == 0) {
            if (argc < 2) {
                printf("Usage: rogue start <ssid> [ch] [open|wpa2] | stop\n");
            } else if (strcmp(argv[1], "start") == 0 && argc >= 3) {
                uint8_t ch = (uint8_t)arg_to_u32(argv[3], 6);
                bool open = !(argc >= 5 && strcmp(argv[4], "wpa2") == 0);
                printf("rogue: %s\n", esp_err_to_name(rogue_ap_start(argv[2], ch, open)));
            } else if (strcmp(argv[1], "stop") == 0) {
                rogue_ap_stop();
            } else {
                printf("Unknown rogue command\n");
            }
        } else if (strcmp(argv[0], "portal") == 0) {
            if (argc < 2) {
                printf("Usage: portal start <ssid> [ch] | stop | creds\n");
            } else if (strcmp(argv[1], "start") == 0 && argc >= 3) {
                uint8_t ch = (uint8_t)arg_to_u32(argv[3], 6);
                printf("portal: %s\n", esp_err_to_name(evil_portal_start(argv[2], ch)));
            } else if (strcmp(argv[1], "stop") == 0) {
                evil_portal_stop();
            } else if (strcmp(argv[1], "creds") == 0) {
                evil_portal_print_creds();
            } else {
                printf("Unknown portal command\n");
            }
        } else if (strcmp(argv[0], "probe") == 0) {
            if (argc < 2) {
                printf("Usage: probe start <ssid> <count> [ch] | stop\n");
            } else if (strcmp(argv[1], "start") == 0 && argc >= 4) {
                uint32_t count = arg_to_u32(argv[3], 0);
                uint8_t ch = (argc >= 5) ? (uint8_t)arg_to_u32(argv[4], 1) : 1;
                printf("probe: %s\n", esp_err_to_name(probe_flood_start(argv[2], count, ch)));
            } else if (strcmp(argv[1], "stop") == 0) {
                probe_flood_stop();
            } else {
                printf("Unknown probe command\n");
            }
        } else if (strcmp(argv[0], "doj") == 0) {
            if (argc < 2) {
                printf("Usage: doj start <bssid> | stop\n");
            } else if (strcmp(argv[1], "start") == 0 && argc >= 3) {
                uint8_t bssid[6];
                if (sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                           &bssid[0], &bssid[1], &bssid[2],
                           &bssid[3], &bssid[4], &bssid[5]) == 6) {
                    printf("doj: %s\n", esp_err_to_name(deauth_on_join_start(bssid)));
                } else {
                    printf("Invalid BSSID format.\n");
                }
            } else if (strcmp(argv[1], "stop") == 0) {
                deauth_on_join_stop();
            } else {
                printf("Unknown doj command\n");
            }
        } else if (strcmp(argv[0], "oui") == 0) {
            if (argc < 2) {
                printf("Usage: oui <mac>\n");
            } else {
                uint8_t mac[6];
                if (sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                           &mac[0], &mac[1], &mac[2],
                           &mac[3], &mac[4], &mac[5]) == 6) {
                    printf("OUI for %02X:%02X:%02X:... is %s\n", mac[0], mac[1], mac[2], oui_lookup(mac));
                } else {
                    printf("Invalid MAC format.\n");
                }
            }
        } else if (strcmp(argv[0], "analyzer") == 0) {
            uint32_t secs = (argc >= 2) ? arg_to_u32(argv[1], 2) : 2;
            channel_analyzer_run(secs);
        } else {
            printf("Unknown command. Type 'help'.\n");
        }

        printf(CLR_CYN "toolkit> " CLR_RST);
        fflush(stdout);
    }
}

/* ---------------------------------------------------------------------------
 *  Public entry — called from main.c's init sequence
 * ------------------------------------------------------------------------- */
esp_err_t cli_start(void)
{
    esp_err_t ret = cli_uart_init();
    if (ret != ESP_OK) {
        /* Non-fatal: log and keep going — reads will just time out. */
        ESP_LOGE(TAG, "CLI cannot read UART0, continuing without input (%s)",
                 esp_err_to_name(ret));
    }

    if (xTaskCreatePinnedToCore(cli_task, "cli_task", 8192, NULL, 3, NULL, 1) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create CLI task");
        return ESP_FAIL;
    }
    return ESP_OK;
}