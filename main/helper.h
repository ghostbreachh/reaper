#ifndef HELPER_H
#define HELPER_H

/* 
 * ============================================================================
 *  AGGREGATE INCLUDE HEADER
 * ============================================================================
 *  WARNING: This file includes almost every module header.
 *  It is intended ONLY for use in main.c or the CLI dispatcher.
 *  
 *  Do NOT include this file in individual module source files (e.g. wifi_sniffer.c).
 *  Doing so creates massive dependency coupling and slows down incremental builds.
 * ============================================================================
 */

/* ─── Core / Low-Level ──────────────────────────────────────────────────── */
#include "common_types.h"
#include "wifi_tx_fix.h"     /* Raw frame overrides / TX bypass */

/* ─── Platform / System ─────────────────────────────────────────────────── */
#include "platform_config.h"
#include "platform_secure_boot.h"
#include "platform_antitamper.h"
#include "platform_factory_test.h"
#include "platform_fleet.h"
#include "platform_plugins.h"
#include "watchdog.h"
#include "structured_log.h"
#include "health_telemetry.h"
#include "health_ai_monitor.h"

/* ─── Storage / Persistence ─────────────────────────────────────────────── */
#include "nvs_persist.h"
#include "storage_sd.h"
#include "storage_spiffs.h"
#include "wordlist_manager.h"
#include "export.h"

/* ─── Transport / Interface ─────────────────────────────────────────────── */
#include "port_detect.h"
#include "usb_cdc.h"
#include "cli_transport.h"
#include "cli_module.h"
#include "cli_flipper.h"
#include "jsonrpc.h"
#include "jsonrpc_schema.h"
#include "led_indicator.h"

/* ─── Wi-Fi Core ────────────────────────────────────────────────────────── */
#include "wifi_sniffer.h"
#include "channel_hopper.h"
#include "coex.h"
#include "wifi_rrm.h"
#include "pcap_ring.h"

/* ─── Wi-Fi Offensive / Analysis ────────────────────────────────────────── */
#include "deauth_engine.h"
#include "beacon_spam.h"
#include "arp_poison.h"
#include "handshake_crack.h"
#include "cred_sniffer.h"
#include "extra_offense.h"
#include "offensive.h"
#include "attack_planner.h"
#include "reaction_rules.h"
#include "stealth.h"
#include "wardrive.h"

/* ─── Wi-Fi Advanced / Specific ─────────────────────────────────────────── */
#include "pmkid.h"
#include "sae_sidechannel.h"
#include "dragonfly_sim.h"
#include "ft_roam.h"
#include "neighbor_report.h"
#include "btm.h"
#include "wps_pixiedust.h"
#include "eap_capture.h"
#include "tx_bypass.h"

/* ─── BLE Core ──────────────────────────────────────────────────────────── */
#include "ble_scanner.h"
#include "ble_ext_adv.h"
#include "ble_periodic.h"
#include "ble_phy.h"
#include "ble_iso.h"
#include "ble_privacy.h"
#include "ble_gatt_client.h"
#include "ble_gatt_enumerator.h"
#include "ble_mitm.h"
#include "ble_rpa_bypass.h"
#include "ble_findmy.h"
#include "ble_smarttag.h"

/* ─── AI / ML ───────────────────────────────────────────────────────────── */
#include "ai_model.h"
#include "ai_classifier.h"
#include "ai_anomaly.h"
#include "ai_fingerprint.h"
#include "ai_channel_predictor.h"
#include "ai_handshake_quality.h"
#include "ai_rogue_detector.h"
#include "ai_deauth_predictor.h"
#include "ai_ble_profiler.h"
#include "ai_training.h"

/* ─── Misc / Other Radios ───────────────────────────────────────────────── */
#include "gps.h"
#include "scheduler.h"
#include "thread_border_router.h"
#include "matter_commissioner.h"
#include "zigbee_sniffer.h"
#include "ota_http.h"

#endif // HELPER_H
