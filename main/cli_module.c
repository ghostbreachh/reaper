/*
 * ============================================================================
 *  cli_module.c  —  Unified command dispatcher for the REAPER CLI
 *
 *  This file contains ONLY command parsing and dispatch logic.
 *  Transport I/O is handled by cli_transport.c/h, which abstracts UART0
 *  and CDC-ACM behind a common vtable.
 * ============================================================================
 */

#include "cli_module.h"
#include "cli_transport.h"
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "cli";

static uint32_t arg_to_u32(const char *s, uint32_t def)
{
    if (s == NULL || s[0] == '\0') return def;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (end == s) return def;
    return (uint32_t)v;
}

static void cli_print_help(void)
{
    const cli_transport_t *t = cli_transport_get();
    if (!t || !t->printf) return;

    t->printf("\nESP32-S3 Wireless Lab Toolkit\n");
    t->printf("Commands:\n");
    t->printf("  help\n");
    t->printf("  reboot\n");
    t->printf("\n");
    t->printf("  led off | idle | scan | conn | error\n");
    t->printf("  led rgb <r> <g> <b>\n");
    t->printf("\n");
    t->printf("  storage status\n");
    t->printf("\n");
    t->printf("  wifi start [seconds]\n");
    t->printf("  wifi pcap [seconds]\n");
    t->printf("  wifi stop\n");
    t->printf("  wifi results\n");
    t->printf("  wifi stats\n");
    t->printf("\n");
    t->printf("  ble start [seconds]\n");
    t->printf("  ble stop\n");
    t->printf("  ble results\n");
    t->printf("  ble trackers\n");
    t->printf("\n");
    t->printf("  adv start [seconds] [name]\n");
    t->printf("  adv stop\n");
    t->printf("\n");
    t->printf("  deauth ap <bssid> [count]\n");
    t->printf("  deauth client <bssid> <client> [count]\n");
    t->printf("  deauth stop\n");
    t->printf("  deauth list\n");
    t->printf("\n");
    t->printf("  arp poison <victim_ip> [gateway_ip] [interval_ms]\n");
    t->printf("  arp stop | status | table\n");
    t->printf("  arp relay on|off\n");
    t->printf("\n");
    t->printf("  pcap start [secs] | stop | info | wipe\n");
    t->printf("  pcap save [path] | export\n");
    t->printf("\n");
    t->printf("  save wifi\n");
    t->printf("  save ble\n");
    t->printf("\n");
    t->printf("  creds on|off|show|clear|save\n");
    t->printf("\n");
    t->printf("  beacon spam [ch] | stop\n");
    t->printf("  rogue start <ssid> [ch] [open|wpa2] | stop\n");
    t->printf("  portal start <ssid> [ch] | stop | creds\n");
    t->printf("\n");
    t->printf("  probe start <ssid> <count> [ch] | stop\n");
    t->printf("  doj start <bssid> | stop\n");
    t->printf("  oui <mac>\n");
    t->printf("  analyzer [seconds_per_channel]\n");
}

void cli_dispatch_command(int argc, char *argv[])
{
    const cli_transport_t *t = cli_transport_get();

    if (argc == 0 || argv[0] == NULL) return;

    if (strcmp(argv[0], "help") == 0) {
        cli_print_help();
    } else if (strcmp(argv[0], "reboot") == 0) {
        esp_restart();
    } else if (strcmp(argv[0], "storage") == 0) {
        if (argc >= 2 && strcmp(argv[1], "status") == 0) {
            if (storage_is_ready()) {
                if (t && t->printf) t->printf("SD card ready.\n");
                sdmmc_card_print_info(stdout, g_sd_card);
            } else {
                if (t && t->printf) t->printf("SD card not ready.\n");
            }
        } else {
            if (t && t->printf) t->printf("Usage: storage status\n");
        }
    } else if (strcmp(argv[0], "led") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: led off|idle|scan|conn|error|rgb\n");
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
                if (t && t->printf) t->printf("Usage: led rgb <r> <g> <b>\n");
            }
        } else {
            if (t && t->printf) t->printf("Unknown led mode\n");
        }
    } else if (strcmp(argv[0], "wifi") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: wifi start|pcap|stop|results|stats\n");
        } else if (strcmp(argv[1], "start") == 0) {
            uint32_t duration = arg_to_u32(argv[2], 10);
            esp_err_t ret = wifi_sniffer_start(duration);
            if (ret != ESP_OK) {
                if (t && t->printf) t->printf("wifi start failed: %s\n", esp_err_to_name(ret));
            } else if (duration > 0) {
                if (t && t->printf) t->printf("Wi-Fi sniffer running for %u s. Use 'wifi stop'.\n", (unsigned)duration);
            } else {
                if (t && t->printf) t->printf("Wi-Fi sniffer running indefinitely. Use 'wifi stop'.\n");
            }
        } else if (strcmp(argv[1], "pcap") == 0) {
            uint32_t duration = arg_to_u32(argv[2], 10);
            esp_err_t ret = wifi_sniffer_start_pcap(duration);
            if (ret != ESP_OK) {
                if (t && t->printf) t->printf("wifi pcap failed: %s\n", esp_err_to_name(ret));
            } else if (duration > 0) {
                if (t && t->printf) t->printf("Wi-Fi PCAP running for %u s. Use 'wifi stop'.\n", (unsigned)duration);
            } else {
                if (t && t->printf) t->printf("Wi-Fi PCAP running indefinitely. Use 'wifi stop'.\n");
            }
        } else if (strcmp(argv[1], "stop") == 0) {
            wifi_sniffer_stop();
        } else if (strcmp(argv[1], "results") == 0) {
            wifi_sniffer_print_results();
        } else if (strcmp(argv[1], "stats") == 0) {
            wifi_sniffer_print_stats();
        } else {
            if (t && t->printf) t->printf("Unknown wifi command\n");
        }
    } else if (strcmp(argv[0], "ble") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: ble start|stop|results|trackers\n");
        } else if (strcmp(argv[1], "start") == 0) {
            uint32_t duration = arg_to_u32(argv[2], 10);
            esp_err_t ret = ble_scanner_start(duration);
            if (ret != ESP_OK) {
                if (t && t->printf) t->printf("ble start failed: %s\n", esp_err_to_name(ret));
            } else if (duration > 0) {
                if (t && t->printf) t->printf("BLE scan running for %u s. Use 'ble stop'.\n", (unsigned)duration);
            } else {
                if (t && t->printf) t->printf("BLE scan running indefinitely. Use 'ble stop'.\n");
            }
        } else if (strcmp(argv[1], "stop") == 0) {
            ble_scanner_stop();
        } else if (strcmp(argv[1], "results") == 0) {
            ble_scanner_print_results();
        } else if (strcmp(argv[1], "trackers") == 0) {
            ble_tracker_print();
        } else {
            if (t && t->printf) t->printf("Unknown ble command\n");
        }
    } else if (strcmp(argv[0], "adv") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: adv start|stop\n");
        } else if (strcmp(argv[1], "start") == 0) {
            uint32_t duration = arg_to_u32(argv[2], 10);
            const char *name = (argc >= 4) ? argv[3] : "ESP32-S3-LAB";
            esp_err_t ret = ble_advertise_start(name, duration);
            if (ret != ESP_OK) {
                if (t && t->printf) t->printf("adv start failed: %s\n", esp_err_to_name(ret));
            } else {
                if (t && t->printf) t->printf("BLE identification advertisement started.\n");
            }
        } else if (strcmp(argv[1], "stop") == 0) {
            ble_advertise_stop();
        } else {
            if (t && t->printf) t->printf("Unknown adv command\n");
        }
    } else if (strcmp(argv[0], "deauth") == 0) {
        if (argc < 2) {
            if (t && t->printf) {
                t->printf("Usage:\n");
                t->printf("  deauth ap <bssid> [count=100]         - Deauth all clients on AP\n");
                t->printf("  deauth client <bssid> <client> [count] - Deauth specific client\n");
                t->printf("  deauth stop\n");
                t->printf("  deauth list\n");
            }
        } else if (strcmp(argv[1], "ap") == 0 && argc >= 3) {
            uint8_t bssid[6];
            if (sscanf(argv[2], "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                       &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) != 6) {
                if (t && t->printf) t->printf("Invalid BSSID format\n");
            } else {
                uint32_t count = arg_to_u32(argv[3], 100);
                deauth_remove_all();
                deauth_attack_ap_all_clients(bssid, count, 0);
            }
        } else if (strcmp(argv[1], "client") == 0 && argc >= 4) {
            uint8_t bssid[6], client[6];
            if (sscanf(argv[2], "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                       &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]) != 6 ||
                sscanf(argv[3], "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                       &client[0], &client[1], &client[2], &client[3], &client[4], &client[5]) != 6) {
                if (t && t->printf) t->printf("Invalid MAC format\n");
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
            if (t && t->printf) t->printf("Deauth targets: %d\n", g_deauth_target_count);
            for (int i = 0; i < g_deauth_target_count; i++) {
                t->printf("  [%d] BSSID: %02X:%02X:%02X:%02X:%02X:%02X -> CLIENT: %02X:%02X:%02X:%02X:%02X:%02X [count=%" PRIu32 " active=%d]\n",
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
            if (t && t->printf) t->printf("Unknown deauth command\n");
        }
    } else if (strcmp(argv[0], "arp") == 0) {
        if (argc < 2) {
            if (t && t->printf) {
                t->printf("Usage:\n");
                t->printf("  arp poison <victim_ip> [gateway_ip] [interval_ms]\n");
                t->printf("  arp stop | status | table\n");
                t->printf("  arp relay on|off\n");
            }
        } else if (strcmp(argv[1], "poison") == 0 && argc >= 3) {
            const char *gw = (argc >= 4) ? argv[3] : NULL;
            const char *interval_arg = (argc >= 5) ? argv[4] : NULL;
            uint32_t iv = arg_to_u32(interval_arg, 2000);
            esp_err_t r = arp_poison_start(argv[2], gw, iv);
            if (t && t->printf) t->printf("arp poison: %s\n", esp_err_to_name(r));
        } else if (strcmp(argv[1], "stop") == 0) {
            arp_poison_stop();
        } else if (strcmp(argv[1], "status") == 0) {
            arp_poison_print_status();
        } else if (strcmp(argv[1], "table") == 0) {
            arp_poison_print_table();
        } else if (strcmp(argv[1], "relay") == 0 && argc >= 3) {
            if (strcmp(argv[2], "on") == 0) {
                arp_relay_set_enabled(true);
                if (t && t->printf) t->printf("relay on\n");
            } else if (strcmp(argv[2], "off") == 0) {
                arp_relay_set_enabled(false);
                if (t && t->printf) t->printf("relay off\n");
            } else {
                if (t && t->printf) t->printf("Usage: arp relay on|off\n");
            }
        } else {
            if (t && t->printf) t->printf("Unknown arp command\n");
        }
    } else if (strcmp(argv[0], "pcap") == 0) {
        if (argc < 2) {
            if (t && t->printf) {
                t->printf("Usage:\n  pcap start [secs] | stop | info | wipe\n");
                t->printf("  pcap save [path] | export\n");
            }
        } else if (strcmp(argv[1], "start") == 0) {
            uint32_t d = arg_to_u32(argv[2], 0);
            esp_err_t r = pcap_ring_start(d);
            if (t && t->printf) t->printf("pcap start: %s\n", esp_err_to_name(r));
        } else if (strcmp(argv[1], "stop") == 0) {
            pcap_ring_stop();
        } else if (strcmp(argv[1], "info") == 0) {
            pcap_ring_print_info();
        } else if (strcmp(argv[1], "wipe") == 0) {
            pcap_ring_wipe();
            if (t && t->printf) t->printf("ring wiped\n");
        } else if (strcmp(argv[1], "save") == 0) {
            char path[64];
            snprintf(path, sizeof(path), "/sd/ring_%" PRId64 ".pcap", esp_timer_get_time());
            if (argc >= 3) snprintf(path, sizeof(path), "%s", argv[2]);
            esp_err_t r = pcap_ring_save(path);
            if (t && t->printf) t->printf("pcap save: %s (%s)\n", esp_err_to_name(r), path);
        } else if (strcmp(argv[1], "export") == 0) {
            pcap_ring_export_serial();
        } else {
            if (t && t->printf) t->printf("Unknown pcap command\n");
        }
    } else if (strcmp(argv[0], "save") == 0) {
        if (!storage_is_ready()) {
            if (t && t->printf) t->printf("SD card not ready.\n");
        } else if (argc < 2) {
            if (t && t->printf) t->printf("Usage: save wifi | save ble\n");
        } else {
            char path[64];
            if (strcmp(argv[1], "wifi") == 0) {
                snprintf(path, sizeof(path), "/sd/wifi_%" PRId64 ".txt", esp_timer_get_time());
                esp_err_t ret = wifi_sniffer_save_report(path);
                if (t && t->printf) t->printf("Saved: %s\n", path);
            } else if (strcmp(argv[1], "ble") == 0) {
                snprintf(path, sizeof(path), "/sd/ble_%" PRId64 ".txt", esp_timer_get_time());
                esp_err_t ret = ble_scanner_save_report(path);
                if (t && t->printf) t->printf("Saved: %s\n", path);
            } else {
                if (t && t->printf) t->printf("Usage: save wifi | save ble\n");
            }
        }
    } else if (strcmp(argv[0], "creds") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: creds on|off|show|clear|save\n");
        } else if (strcmp(argv[1], "on") == 0) {
            if (!atomic_load(&g_wifi_sniffer_active)) wifi_sniffer_start(0);
            creds_set_enabled(true);
            if (t && t->printf) t->printf("Credential sniffer ON\n");
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
                if (t && t->printf) t->printf("Saved %s\n", path);
            else
                if (t && t->printf) t->printf("Save failed (SD?)\n");
        }
    } else if (strcmp(argv[0], "beacon") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: beacon spam [ch] | stop\n");
        } else if (strcmp(argv[1], "spam") == 0) {
            uint8_t ch = (uint8_t)arg_to_u32(argv[2], 6);
            if (t && t->printf) t->printf("beacon spam: %s\n", esp_err_to_name(beacon_spam_start_builtin(ch)));
        } else if (strcmp(argv[1], "stop") == 0) {
            beacon_spam_stop();
        } else {
            if (t && t->printf) t->printf("Unknown beacon command\n");
        }
    } else if (strcmp(argv[0], "rogue") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: rogue start <ssid> [ch] [open|wpa2] | stop\n");
        } else if (strcmp(argv[1], "start") == 0 && argc >= 3) {
            uint8_t ch = (uint8_t)arg_to_u32(argv[3], 6);
            bool open = !(argc >= 5 && strcmp(argv[4], "wpa2") == 0);
            if (t && t->printf) t->printf("rogue: %s\n", esp_err_to_name(rogue_ap_start(argv[2], ch, open)));
        } else if (strcmp(argv[1], "stop") == 0) {
            rogue_ap_stop();
        } else {
            if (t && t->printf) t->printf("Unknown rogue command\n");
        }
    } else if (strcmp(argv[0], "portal") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: portal start <ssid> [ch] | stop | creds\n");
        } else if (strcmp(argv[1], "start") == 0 && argc >= 3) {
            uint8_t ch = (uint8_t)arg_to_u32(argv[3], 6);
            if (t && t->printf) t->printf("portal: %s\n", esp_err_to_name(evil_portal_start(argv[2], ch)));
        } else if (strcmp(argv[1], "stop") == 0) {
            evil_portal_stop();
        } else if (strcmp(argv[1], "creds") == 0) {
            evil_portal_print_creds();
        } else {
            if (t && t->printf) t->printf("Unknown portal command\n");
        }
    } else if (strcmp(argv[0], "probe") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: probe start <ssid> <count> [ch] | stop\n");
        } else if (strcmp(argv[1], "start") == 0 && argc >= 4) {
            uint32_t count = arg_to_u32(argv[3], 0);
            uint8_t ch = (argc >= 5) ? (uint8_t)arg_to_u32(argv[4], 1) : 1;
            if (t && t->printf) t->printf("probe: %s\n", esp_err_to_name(probe_flood_start(argv[2], count, ch)));
        } else if (strcmp(argv[1], "stop") == 0) {
            probe_flood_stop();
        } else {
            if (t && t->printf) t->printf("Unknown probe command\n");
        }
    } else if (strcmp(argv[0], "doj") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: doj start <bssid> | stop\n");
        } else if (strcmp(argv[1], "start") == 0 && argc >= 3) {
            uint8_t bssid[6];
            if (sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &bssid[0], &bssid[1], &bssid[2],
                       &bssid[3], &bssid[4], &bssid[5]) == 6) {
                if (t && t->printf) t->printf("doj: %s\n", esp_err_to_name(deauth_on_join_start(bssid)));
            } else {
                if (t && t->printf) t->printf("Invalid BSSID format.\n");
            }
        } else if (strcmp(argv[1], "stop") == 0) {
            deauth_on_join_stop();
        } else {
            if (t && t->printf) t->printf("Unknown doj command\n");
        }
    } else if (strcmp(argv[0], "oui") == 0) {
        if (argc < 2) {
            if (t && t->printf) t->printf("Usage: oui <mac>\n");
        } else {
            uint8_t mac[6];
            if (sscanf(argv[1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &mac[0], &mac[1], &mac[2],
                       &mac[3], &mac[4], &mac[5]) == 6) {
                if (t && t->printf) t->printf("OUI for %02X:%02X:%02X:... is %s\n",
                                               mac[0], mac[1], mac[2], oui_lookup(mac));
            } else {
                if (t && t->printf) t->printf("Invalid MAC format.\n");
            }
        }
    } else if (strcmp(argv[0], "analyzer") == 0) {
        uint32_t secs = (argc >= 2) ? arg_to_u32(argv[1], 2) : 2;
        channel_analyzer_run(secs);
    } else {
        if (t && t->printf) t->printf("Unknown command. Type 'help'.\n");
    }
}
