# REAPER — ESP32-S3 Wireless Lab Toolkit

> **ESP32-S3-N16R8 · USB-OTG CDC-ACM · JSON-RPC 2.0 · Dual-core AI · Massive wordlists**
>
> A state-of-the-art, self-healing wireless security platform that fits in your pocket. Controlled from your phone via OTG cable. Wardrives, cracks handshakes on-device, and runs protocol-DoS with surgical precision.

---

## Table of Contents

- [Architecture](#architecture)
- [Hardware](#hardware)
- [Dependencies](#dependencies)
- [Build & Flash](#build--flash)
- [Phone Companion App](#phone-companion-app)
- [Feature Roadmap](#feature-roadmap)
- [Error Taxonomy](#error-taxonomy)
- [Contributing](#contributing)
- [License](#license)

---

## Architecture

REAPER is split into two halves:

| Half | Role |
|------|------|
| **Firmware (`main/`)** | Runs on ESP32-S3-N16R8. Handles all radio I/O, PCAP capture, on-device cracking, AI inference, and exposes a JSON-RPC 2.0 API over USB-OTG CDC-ACM. |
| **Companion App** | Android app (Flutter/Compose). Connects via USB-OTG, renders terminal + dashboard, manages wardriving maps, streams wordlists, displays real-time events. |

### Firmware Module Map

```
main/
├── main.c                  — Boot, port detection, task spawn
├── helper.h                — Aggregated include for all module headers
├── cli_module.c/h          — Dual-transport CLI (UART0 + CDC-ACM), JSON-RPC dispatcher
├── wifi_sniffer.c/h        — 802.11 promiscuous capture, channel hopping, PMF/SAE detection
├── ble_scanner.c/h         — BLE 5.0 active/passive scan, extended adv, coded PHY
├── deauth_engine.c/h       — Protocol-DoS: deauth, disassoc, auth flood, CTS, PMF-aware
├── beacon_spam.c/h         — Beacon frame injection, SSID randomization, phantom APs
├── cred_sniffer.c/h        — EAPOL handshake capture, HTTP credential extraction
├── handshake_crack.c/h     — On-device dual-core PBKDF2-SHA1 crack with streaming wordlists
├── arp_poison.c/h          — ARP poisoning + relay MITM
├── extra_offense.c/h       — Probe flood, deauth-on-join, auth flood, BLE adv flood
├── tx_bypass.c/h           — Low-level raw 802.11 TX helpers, frame sanity bypass
├── pcap_ring.c/h           — 2 MiB PSRAM ring buffer, PCAP-NG framing, binary export
├── storage_sd.c/h          — SPIFFS wordlist management, zstd compression, Bloom filter
├── led_indicator.c/h       — RGB status indicator (attack/idle/error states)
├── common_types.h          — Typed error codes, shared structs, JSON-RPC schema enums
├── wifi_tx_fix.h           — TX calibration and power fixups for ESP32-S3 radio
└── tools/
    └── pcap_reassemble.py   — Host-side PCAP reassembly utility
```

### Boot Sequence

```
1. NVS init → restore last session config
2. Detect active USB port:
   - USB-Serial-JTAG present → UART0 CLI mode
   - USB-OTG CDC-ACM present → JSON-RPC mode
3. Init subsystems:
   - WiFi promiscuous sniffer
   - BLE scanner
   - PCAP ring buffer (2 MiB PSRAM)
   - Wordlist Bloom filter (SPIFFS → PSRAM)
   - Self-healing health monitor
4. Spawn tasks:
   - Channel hopper (esp_timer-driven, microsecond precision)
   - CLI reader task (UART0 or CDC)
   - JSON-RPC dispatcher
   - PCAP ring writer
   - Health watchdog
5. Enter idle loop, wait for commands/events
```

---

## Hardware

| Component | Spec |
|-----------|------|
| **MCU** | ESP32-S3-N16R8 (LX7 dual-core @ 240 MHz) |
| **Flash** | 16 MB (factory + 2 OTA slots + 4 MB SPIFFS wordlists + 1 MB NVS) |
| **PSRAM** | 8 MB (2 MiB PCAP ring + 2 MiB Bloom filter + 1 MiB AI model weights + 3 MiB heap) |
| **USB** | USB-Serial-JTAG (debug) + USB-OTG CDC-ACM (phone control) |
| **WiFi** | 802.11b/g/n (WiFi 4), promiscuous mode, raw frame TX |
| **BLE** | BLE 5.0, extended advertising, coded PHY S=8 |
| **Storage** | SPIFFS (wordlists, config, crash logs). No SD card required. |
| **LED** | WS2812B status ring (optional) |

### Pinout Reference

| Signal | GPIO | Notes |
|--------|------|-------|
| WS2812B data | GPIO8 | LED indicator ring |
| SD card CS | GPIO10 | SPIFFS alternative (optional) |
| USB-OTG D+ | GPIO20 | CDC-ACM device |
| USB-OTG D- | GPIO19 | CDC-ACM device |
| UART0 TX | GPIO43 | Debug console |
| UART0 RX | GPIO44 | Debug console |

---

## Dependencies

### Toolchain

| Tool | Version | Install |
|------|---------|---------|
| **ESP-IDF** | v5.3 | `git clone -b v5.3 --recursive https://github.com/espressif/esp-idf.git ~/esp/esp-idf` |
| **Python** | 3.10+ | `sudo pacman -S python` (Omarchy) |
| **CMake** | 3.24+ | `sudo pacman -S cmake` |
| **Ninja** | 1.10+ | `sudo pacman -S ninja` |
| **Git** | 2.40+ | `sudo pacman -S git` |

### ESP-IDF Setup

```bash
# One-time setup
cd ~/esp/esp-idf
./install.sh esp32s3
source export.sh

# Verify
idf.py --version
```

### Phone App Dependencies

- **Flutter SDK** 3.x with Kotlin Android embedding
- `usb-serial-for-android` (CDC-ACM driver)
- `maplibre_gl` + `pmtiles` (offline maps)
- `flutter_blue_plus` (optional BLE bridge mode)
- `provider` / `riverpod` (state management)

---

## Build & Flash

### First Build

```bash
cd ~/reaper
source ~/esp/esp-idf/export.sh
idf.py set-target esp32s3
idf.py build
```

### Flash (USB-Serial-JTAG)

```bash
idf.py -p /dev/ttyACM0 flash monitor
```

### Flash (USB-OTG CDC)

```bash
idf.py -p /dev/ttyACM1 flash monitor
```

### OTA Update

```bash
# Build OTA binary
idf.py build
# Upload via JSON-RPC
curl -X POST http://<ota-server>/firmware.bin -o /tmp/
# Or via phone app: Settings → Firmware Update
```

### Serial Terminal (CLI mode)

```bash
screen /dev/ttyACM0 115200
# or
picocom /dev/ttyACM0 -b 115200
```

---

## Phone Companion App

### Architecture

```
lib/
├── core/
│   ├── reaper_connection.dart      — USB-CDC open/close, permission flow
│   ├── json_rpc_client.dart        — JSON-RPC 2.0 request/response/notification
│   └── protocol_schema.dart        — Constants for all RPC methods/events
├── features/
│   ├── terminal/
│   │   └── terminal_screen.dart    — ANSI escape parser + scrollback
│   ├── dashboard/
│   │   └── dashboard_screen.dart   — Real-time metrics (heap, temp, RSSI)
│   ├── attacks/
│   │   └── attack_builder.dart     — Attack configurator UI
│   ├── wardrive/
│   │   └── wardrive_screen.dart    — GPS + MapLibre + PMTiles offline maps
│   ├── wordlists/
│   │   └── wordlist_manager.dart   — Download, upload, manage on-device lists
│   └── settings/
│       └── firmware_update.dart    — OTA binary upload + verify
└── shared/
    ├── models/                     — Generated from JSON-RPC schema
    └── widgets/                    — Reusable UI components
```

### Communication Protocol

REAPER speaks **JSON-RPC 2.0 over CDC-ACM serial** at 115200 baud, 8N1, no flow control.

**Example request:**
```json
{"jsonrpc":"2.0","id":1,"method":"wifi.start_sniff","params":{"channel":6,"duration":30}}
```

**Example response:**
```json
{"jsonrpc":"2.0","id":1,"result":{"status":"started","channel":6,"duration":30}}
```

**Example event (async):**
```json
{"jsonrpc":"2.0","method":"event","params":{"type":"ap_found","data":{"bssid":"AA:BB:CC:DD:EE:FF","ssid":"TargetNet","rssi":-42,"channel":6}}}
```

**Example error:**
```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"Internal error","data":{"module":"deauth_engine","code":"ERR_DEAUTH_TX_FAILED","line":50,"esp_err":"ESP_ERR_WIFI_IF","context":"phantom_ap_restarted"}}}
```

---

## Feature Roadmap

**100 features across 5 phases.**

### Phase 1: Foundation (22 features)
Boot detection, USB-CDC, JSON-RPC, NVS, OTA, watchdog, structured logging, health telemetry, binary PCAP framing, typed error taxonomy.

### Phase 2: Radio Excellence (18 features)
Smart channel hopper, PMF/SAE detection, deauth fallback chain, 802.11k/v/r parsing, BLE 5.0 extended adv, coded PHY, adaptive dwell, WiFi/BLE coexistence.

### Phase 3: Intelligence Layer (15 features)
ESP-DL model loader, packet classifier, anomaly detector, device fingerprinting, channel predictor, handshake quality scorer, rogue AP detector, BLE profiler.

### Phase 4: Ecosystem & Tooling (23 features)
Android app (terminal, dashboard, attack builder, wardrive maps, wordlist manager, firmware updater), PCAP-NG export, Kismet/NetXML, Wireshark Lua dissector, Flipper bridge.

### Phase 5: Advanced Research (22 features)
PMKID, SAE side-channel, 802.11r/11k/11v injection, WPS PixieDust, BLE MITM, Find My detection, Thread/Matter (future HW), secure boot, plugin architecture.

See `skills/esp32-marauder-knowledge/references/100-feature-master-plan.md` for the full enumerated list.

---

## Error Taxonomy

Every module returns **typed error codes** with full context (file, line, function, stack watermark). No generic `ESP_FAIL`.

```c
typedef enum {
    ERR_OK = 0,
    ERR_WIFI_BASE = 0x1000,
    ERR_WIFI_NOT_INIT = 0x1001,
    ERR_WIFI_CHANNEL_SET = 0x1002,
    ERR_DEAUTH_BASE = 0x2000,
    ERR_DEAUTH_NO_TARGETS = 0x2001,
    ERR_DEAUTH_TX_FAILED = 0x2002,
    ERR_PCAP_BASE = 0x3000,
    ERR_PCAP_RING_FULL = 0x3001,
    ERR_NVS_BASE = 0x4000,
    ERR_NVS_WRITE_FAILED = 0x4001,
    ERR_WORDLIST_BASE = 0x5000,
    ERR_WORDLIST_CORRUPT = 0x5001,
    ERR_OTA_BASE = 0x6000,
    ERR_OTA_VERIFY_FAILED = 0x6001,
    // ... 200+ codes
} marauder_err_t;
```

Errors propagate to the phone app with human-readable messages and suggested fixes.

---

## Contributing

1. `git clone https://github.com/ghostbreachh/reaper.git`
2. Follow the phase roadmap. Each feature gets its own commit.
3. Every 10 features: micro-optimization sweep + `DEV_LOG.md` update.
4. No placeholders, no TODOs, no partial code.

---

## License

MIT — see `LICENSE` for details.

---

**Built on ESP-IDF v5.3 · ESP32-S3-N16R8 · Omarchy Linux**
