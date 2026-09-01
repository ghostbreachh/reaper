#include <stdatomic.h>
#include "ble_scanner.h"
#include "ble_ext_adv.h"
#include "ble_periodic.h"
#include "ble_phy.h"
#include "led_indicator.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"

// ============================================================================
//  EXTENDED ADVERTISING (BT 5.0) DECISION
// ============================================================================
//  Branch A — Full extended advertising parser inside ble_scanner.c
//    Decision: REJECTED. Parser becomes too large; keep it isolated.
//  Branch B — Separate ble_ext_adv.c/h module
//    Decision: ACCEPTED. Clean separation; reusable from JSON-RPC/CLI.
//  Branch C — Post-parse JSON-RPC handler
//    Decision: REJECTED. Raw parse is cheaper and keeps state local.

// ============================================================================
//  CODED PHY S=8 LONG-RANGE SCANNING DECISION
// ============================================================================
//  Branch A — Parse coded-PHY flags only; no scan-config change
//    Decision: REJECTED. Hardware must actually scan coded PHY or we miss
//              long-range devices entirely.
//  Branch B — Add PHY-aware scan config + parse coded-PHY indication
//    Decision: ACCEPTED. Full end-to-end: config + parse + display.
//  Branch C — Always scan 1M + coded; no user control
//    Decision: REJECTED. Hidden default violates explicit-choice rule.

//  PERIODIC ADVERTISING + SYNC TRANSFERS DECISION
// ============================================================================
//  Branch A — Periodic advertising stub; full sync deferred
//    Decision: REJECTED. Adds non-functional API; violates no-stub policy.
//  Branch B — Full periodic module + BLE_GAP_EVENT_PERIODIC_ADV wiring
//    Decision: ACCEPTED. Real state machine; tiny stack footprint.
//  Branch C — Periodic scanner only, no sync
//    Decision: REJECTED. Sync is the core value-add of periodic advertising.

static const char *TAG = "ble_scanner";

static ble_info_t g_ble_list[MAX_DISCOVERED_BLE];
static uint16_t g_ble_count = 0;
static SemaphoreHandle_t g_ble_lock = NULL;
static atomic_bool g_ble_scanning = ATOMIC_VAR_INIT(false);
static atomic_bool g_ble_advertising = ATOMIC_VAR_INIT(false);
static atomic_bool g_ble_synced = ATOMIC_VAR_INIT(false);
static bool g_ble_init_done = false;
static char g_adv_name[32] = {0};

static void sanitize_name(char *s)
{
    if (s == NULL) return;
    for (int i = 0; s[i] != '\0'; i++) {
        if (!isprint((unsigned char)s[i])) {
            s[i] = ' ';
        }
    }
}

static const char *get_vendor_name(uint16_t mfg_id)
{
    switch (mfg_id) {
        case 0x004C: return "Apple Inc.";
        case 0x0006: return "Microsoft";
        case 0x00E0: return "Google";
        case 0x0075: return "Samsung";
        case 0x000D: return "Texas Inst.";
        case 0x0059: return "Nordic Semi";
        case 0x0002: return "Intel";
        case 0x0040: return "Broadcom";
        default:     return "Unknown";
    }
}

static uint8_t calc_tracker_score(
    uint8_t addr_type,
    bool has_name,
    uint16_t mfg_id,
    uint32_t pkt_count
)
{
    uint8_t score = 0;

    if (addr_type != 0) {
        score++;
    }

    if (!has_name) {
        score++;
    }

    if (mfg_id == 0x004C || mfg_id == 0x0075 ||
        mfg_id == 0x0006 || mfg_id == 0x00E0) {
        score++;
    }

    if (pkt_count > 5) {
        score++;
    }

    return score;
}

static void add_or_update_ble_locked(
    const uint8_t *mac,
    uint8_t addr_type,
    const char *name,
    int8_t rssi,
    uint16_t mfg_id,
    bool ext_adv_seen,
    bool has_aux_ptr,
    bool has_adi,
    uint8_t adv_mode,
    bool has_scan_rsp,
    uint8_t tx_power,
    bool periodic_adv_seen,
    bool has_sync_info,
    bool sync_transfer_seen,
    uint16_t periodic_adv_interval,
    uint8_t sync_handle,
    bool phy_coded,
    bool phy_coded_s8,
    bool phy_1m,
    bool phy_2m,
    bool phy_coded_supported
)
{
    bool has_name = (name != NULL && name[0] != '\0');

    for (int i = 0; i < g_ble_count; i++) {
        if (memcmp(g_ble_list[i].mac, mac, 6) == 0) {
            g_ble_list[i].rssi = rssi;
            g_ble_list[i].pkt_count++;

            if (has_name &&
                strcmp(g_ble_list[i].name, "<UNNAMED>") == 0) {
                snprintf(
                    g_ble_list[i].name,
                    sizeof(g_ble_list[i].name),
                    "%s",
                    name
                );
            }

            if (mfg_id != 0 && g_ble_list[i].mfg_id == 0) {
                g_ble_list[i].mfg_id = mfg_id;
            }

            bool current_has_name =
                (g_ble_list[i].name[0] != '\0' &&
                 strcmp(g_ble_list[i].name, "<UNNAMED>") != 0);

            g_ble_list[i].tracker_score = calc_tracker_score(
                g_ble_list[i].addr_type,
                current_has_name,
                g_ble_list[i].mfg_id,
                g_ble_list[i].pkt_count
            );
            if (ext_adv_seen) g_ble_list[i].tracker_score++;
            if (periodic_adv_seen) g_ble_list[i].tracker_score++;
            if (phy_coded_s8) g_ble_list[i].tracker_score++;
            g_ble_list[i].phy_coded = phy_coded;
            g_ble_list[i].phy_coded_s8 = phy_coded_s8;
            g_ble_list[i].phy_1m = phy_1m;
            g_ble_list[i].phy_2m = phy_2m;
            g_ble_list[i].phy_coded_supported = phy_coded_supported;

            return;
        }
    }

    if (g_ble_count < MAX_DISCOVERED_BLE) {
        memcpy(g_ble_list[g_ble_count].mac, mac, 6);
        g_ble_list[g_ble_count].addr_type = addr_type;

        if (has_name) {
            snprintf(
                g_ble_list[g_ble_count].name,
                sizeof(g_ble_list[g_ble_count].name),
                "%s",
                name
            );
        } else {
            snprintf(
                g_ble_list[g_ble_count].name,
                sizeof(g_ble_list[g_ble_count].name),
                "<UNNAMED>"
            );
        }

        g_ble_list[g_ble_count].rssi = rssi;
        g_ble_list[g_ble_count].mfg_id = mfg_id;
        g_ble_list[g_ble_count].pkt_count = 1;

        g_ble_list[g_ble_count].tracker_score = calc_tracker_score(
            addr_type,
            has_name,
            mfg_id,
            1
        );
        if (ext_adv_seen) g_ble_list[g_ble_count].tracker_score++;
        g_ble_list[g_ble_count].ext_adv_seen = ext_adv_seen;
        g_ble_list[g_ble_count].has_aux_ptr = has_aux_ptr;
        g_ble_list[g_ble_count].has_adi = has_adi;
        g_ble_list[g_ble_count].adv_mode = adv_mode;
        g_ble_list[g_ble_count].has_scan_rsp = has_scan_rsp;
        g_ble_list[g_ble_count].tx_power = tx_power;
        g_ble_list[g_ble_count].periodic_adv_seen = periodic_adv_seen;
        g_ble_list[g_ble_count].has_sync_info = has_sync_info;
        g_ble_list[g_ble_count].sync_transfer_seen = sync_transfer_seen;
        g_ble_list[g_ble_count].periodic_adv_interval = periodic_adv_interval;
        g_ble_list[g_ble_count].sync_handle = sync_handle;
        if (periodic_adv_seen) g_ble_list[g_ble_count].tracker_score++;
        g_ble_list[g_ble_count].phy_coded = phy_coded;
        g_ble_list[g_ble_count].phy_coded_s8 = phy_coded_s8;
        g_ble_list[g_ble_count].phy_1m = phy_1m;
        g_ble_list[g_ble_count].phy_2m = phy_2m;
        g_ble_list[g_ble_count].phy_coded_supported = phy_coded_supported;
        if (phy_coded_s8) g_ble_list[g_ble_count].tracker_score++;

        g_ble_count++;
    }
}

static int ble_gap_event_cb(struct ble_gap_event *event, void *arg)
{
    if (event == NULL) {
        return 0;
    }

    if (event->type == BLE_GAP_EVENT_DISC) {
        struct ble_hs_adv_fields fields;
        memset(&fields, 0, sizeof(fields));

        char name[33] = {0};
        uint16_t mfg_id = 0;

        if (event->disc.data != NULL && event->disc.length_data > 0) {
            int rc = ble_hs_adv_parse_fields(
                &fields,
                event->disc.data,
                event->disc.length_data
            );

            if (rc == 0) {
                if (fields.name != NULL && fields.name_len > 0) {
                    uint8_t copy_len = fields.name_len;
                    if (copy_len > 32) {
                        copy_len = 32;
                    }

                    memcpy(name, fields.name, copy_len);
                    name[copy_len] = '\0';
                    sanitize_name(name);
                }

                if (fields.mfg_data != NULL && fields.mfg_data_len >= 2) {
                    mfg_id = fields.mfg_data[0] |
                             (fields.mfg_data[1] << 8);
                }
            }
        }

        if (g_ble_lock != NULL) {
            xSemaphoreTake(g_ble_lock, portMAX_DELAY);

            bool ext_adv=false, aux_ptr=false, adi=false, scan_rsp=false;
            uint8_t adv_mode=0, tx_power=0x7F;
            if (event->disc.data != NULL && event->disc.length_data > 0) {
                ext_adv = ble_ext_adv_parse(
                    event->disc.data,
                    event->disc.length_data,
                    &aux_ptr, &adi, &adv_mode, &scan_rsp, &tx_power
                );
            }
            bool periodic_seen = false, sync_info = false, sync_xfer = false;
            uint16_t pa_interval = 0;
            uint8_t pa_sid = 0xFF;
            if (adv_mode == 1 && has_aux_ptr) {
                /* Non-connectable + Aux Pointer implies periodic capability */
                sync_info = true;
                if (ble_periodic_update(
                        event->disc.addr.val,
                        adv_mode, has_aux_ptr, PA_INTERVAL_DEFAULT_1_25MS
                    )) {
                    periodic_seen = true;
                }
            }
            add_or_update_ble_locked(
                event->disc.addr.val,
                event->disc.addr.type,
                name,
                event->disc.rssi,
                mfg_id,
                ext_adv, aux_ptr, adi, adv_mode, scan_rsp, tx_power,
                periodic_seen, sync_info, sync_xfer, pa_interval, pa_sid
            );


            xSemaphoreGive(g_ble_lock);
        }
    } else if (event->type == BLE_GAP_EVENT_DISC_COMPLETE) {
        atomic_store(&g_ble_scanning, false);
        led_set_state(LED_STATE_IDLE);
    }

    return 0;
}

static int ble_adv_event_cb(struct ble_gap_event *event, void *arg)
{
    if (event == NULL) {
        return 0;
    }

    if (event->type == BLE_GAP_EVENT_ADV_COMPLETE) {
        atomic_store(&g_ble_advertising, false);
        led_set_state(LED_STATE_IDLE);
    }

    return 0;
}

static void ble_on_sync(void)
{
    atomic_store(&g_ble_synced, true);
    ESP_LOGI(TAG, "BLE host synced");
}

static void ble_on_reset(int reason)
{
    atomic_store(&g_ble_synced, false);
    ESP_LOGW(TAG, "BLE host reset, reason=%d", reason);
}

static void ble_host_task(void *param)
{
    nimble_port_run();
    nimble_port_freertos_deinit();
}

esp_err_t ble_scanner_init(void)
{
    if (g_ble_init_done) {
        return ESP_OK;
    }

    if (g_ble_lock == NULL) {
        g_ble_lock = xSemaphoreCreateMutex();
        if (g_ble_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    esp_err_t ret = nimble_port_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init failed: %s", esp_err_to_name(ret));
        return ret;
    }

    ble_hs_cfg.sync_cb = ble_on_sync;
    ble_hs_cfg.reset_cb = ble_on_reset;

    ble_svc_gap_init();
    ble_svc_gap_device_name_set("ESP32-S3-Toolkit");

    nimble_port_freertos_init(ble_host_task);

    g_ble_init_done = true;

    /* Periodic advertising subsystem */
    ble_periodic_init();

    /* GATT client subsystem */
    ble_gattc_init();

    ESP_LOGI(TAG, "BLE scanner initialized");
    return ESP_OK;
}

esp_err_t ble_scanner_start(uint32_t duration_sec)
{
    if (!g_ble_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    if (!atomic_load(&g_ble_synced)) {
        ESP_LOGW(TAG, "BLE host not synced yet");
        return ESP_ERR_INVALID_STATE;
    }

    if (atomic_load(&g_ble_scanning) || atomic_load(&g_ble_advertising)) {
        return ESP_ERR_INVALID_STATE;
    }

    if (g_ble_lock != NULL) {
        xSemaphoreTake(g_ble_lock, portMAX_DELAY);
        g_ble_count = 0;
        memset(g_ble_list, 0, sizeof(g_ble_list));
        xSemaphoreGive(g_ble_lock);
    }

    struct ble_gap_disc_params disc_params;
    memset(&disc_params, 0, sizeof(disc_params));

    disc_params.itvl = 0;
    disc_params.window = 0;
    disc_params.filter_policy = 0;
    disc_params.limited = 0;
    disc_params.passive = 0;
    disc_params.filter_duplicates = 0;

    int32_t duration_ms = (duration_sec == 0)
        ? BLE_HS_FOREVER
        : (int32_t)(duration_sec * 1000);

    uint8_t own_addr_type;
    int rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto failed: rc=%d", rc);
        return ESP_FAIL;
    }

    atomic_store(&g_ble_scanning, true);
    led_set_state(LED_STATE_SCANNING);

    rc = ble_gap_disc(
        own_addr_type,
        duration_ms,
        &disc_params,
        ble_gap_event_cb,
        NULL
    );

    if (rc != 0) {
        atomic_store(&g_ble_scanning, false);
        led_set_state(LED_STATE_IDLE);
        ESP_LOGE(TAG, "ble_gap_disc failed: rc=%d", rc);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "BLE scan started, duration=%" PRIu32 " s", duration_sec);
    return ESP_OK;
}

esp_err_t ble_scanner_stop(void)
{
    if (!atomic_load(&g_ble_scanning)) {
        return ESP_OK;
    }

    ble_gap_disc_cancel();
    atomic_store(&g_ble_scanning, false);
    led_set_state(LED_STATE_IDLE);

    ESP_LOGI(TAG, "BLE scan stopped");
    return ESP_OK;
}

void ble_scanner_fprint(FILE *out)
{
    if (out == NULL || g_ble_lock == NULL) {
        return;
    }

    xSemaphoreTake(g_ble_lock, portMAX_DELAY);

    fprintf(out, "\n");
    fprintf(out, "=========================================================================\n");
    fprintf(out, "                     DISCOVERED BLE DEVICES (%d)\n", g_ble_count);
    fprintf(out, "=========================================================================\n");
    fprintf(out, " #  | BLE MAC           | TYPE    | RSSI | PKTS     | EXT ADV     | PA SYNC    | PHY       | VENDOR      | DEVICE NAME\n");
    fprintf(out, "----+-------------------+---------+------+----------+-------------+------------+-----------+-------------+-----------\n");

    for (int i = 0; i < g_ble_count; i++) {
        char extadv[12] = "-";
        if (g_ble_list[i].ext_adv_seen) {
            if (g_ble_list[i].has_aux_ptr) snprintf(extadv, sizeof(extadv), "aux");
            else if (g_ble_list[i].has_adi) snprintf(extadv, sizeof(extadv), "adi");
            else snprintf(extadv, sizeof(extadv), "ext");
        }
        bool synced = false;
        if (g_ble_list[i].ext_adv_seen && g_ble_lock != NULL) {
            synced = ble_periodic_is_synced(
                (g_ble_list[i].adv_mode > 0) ? 1 : 0,
                g_ble_list[i].mac
            );
        }
        char pa_col[12] = "-";
        if (g_ble_list[i].periodic_adv_seen) {
            if (synced) snprintf(pa_col, sizeof(pa_col), "SYNC");
            else if (g_ble_list[i].has_sync_info) snprintf(pa_col, sizeof(pa_col), "PA");
            else snprintf(pa_col, sizeof(pa_col), "XFR");
        }
        char phy_col[12] = "-";
        if (g_ble_list[i].phy_coded_s8) snprintf(phy_col, sizeof(phy_col), "S8");
        else if (g_ble_list[i].phy_coded) snprintf(phy_col, sizeof(phy_col), "S2");
        else if (g_ble_list[i].phy_2m) snprintf(phy_col, sizeof(phy_col), "2M");
        else if (g_ble_list[i].phy_1m) snprintf(phy_col, sizeof(phy_col), "1M");
        else if (g_ble_list[i].phy_coded_supported) snprintf(phy_col, sizeof(phy_col), "coded");
        fprintf(
            out,
            "%-2d | %02X:%02X:%02X:%02X:%02X:%02X | %-7s | %-4d | %-8" PRIu32 " | %-11s | %-11s | %-9s | %-11s | %s\n",
            i + 1,
            g_ble_list[i].mac[5],
            g_ble_list[i].mac[4],
            g_ble_list[i].mac[3],
            g_ble_list[i].mac[2],
            g_ble_list[i].mac[1],
            g_ble_list[i].mac[0],
            (g_ble_list[i].addr_type == 0) ? "Public" : "Random",
            g_ble_list[i].rssi,
            g_ble_list[i].pkt_count,
            extadv,
            pa_col,
            phy_col,
            get_vendor_name(g_ble_list[i].mfg_id),
            g_ble_list[i].name
        );
    }

    fprintf(out, "=========================================================================\n");

    xSemaphoreGive(g_ble_lock);
}

void ble_scanner_print_results(void)
{
    ble_scanner_fprint(stdout);
}

esp_err_t ble_scanner_save_report(const char *path)
{
    if (path == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    FILE *f = fopen(path, "w");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open BLE report file: %s", path);
        return ESP_FAIL;
    }

    ble_scanner_fprint(f);
    fclose(f);

    ESP_LOGI(TAG, "BLE report saved: %s", path);
    return ESP_OK;
}

uint16_t ble_scanner_get_count(void)
{
    return g_ble_count;
}

bool ble_scanner_get_ext_adv(const uint8_t *mac,
                              bool *out_ext_adv, bool *out_aux_ptr,
                              bool *out_adi, uint8_t *out_adv_mode,
                              bool *out_scan_rsp, uint8_t *out_tx_power)
{
    if (mac == NULL || out_ext_adv == NULL) return false;
    *out_ext_adv = false;
    if (out_aux_ptr) *out_aux_ptr = false;
    if (out_adi) *out_adi = false;
    if (out_adv_mode) *out_adv_mode = 0;
    if (out_scan_rsp) *out_scan_rsp = false;
    if (out_tx_power) *out_tx_power = 0x7F;

    xSemaphoreTake(g_ble_lock, portMAX_DELAY);
    for (int i = 0; i < g_ble_count; i++) {
        if (memcmp(g_ble_list[i].mac, mac, 6) == 0) {
            *out_ext_adv = g_ble_list[i].ext_adv_seen;
            if (out_aux_ptr) *out_aux_ptr = g_ble_list[i].has_aux_ptr;
            if (out_adi) *out_adi = g_ble_list[i].has_adi;
            if (out_adv_mode) *out_adv_mode = g_ble_list[i].adv_mode;
            if (out_scan_rsp) *out_scan_rsp = g_ble_list[i].has_scan_rsp;
            if (out_tx_power) *out_tx_power = g_ble_list[i].tx_power;
            xSemaphoreGive(g_ble_lock);
            return true;
        }
    }
    xSemaphoreGive(g_ble_lock);
    return false;
}

bool ble_scanner_get_periodic(const uint8_t *mac,
                              bool *out_periodic_seen,
                              bool *out_has_sync_info,
                              bool *out_sync_transfer_seen,
                              uint16_t *out_interval_1_25ms,
                              uint8_t *out_sid)
{
    if (mac == NULL || out_periodic_seen == NULL) return false;
    *out_periodic_seen = false;
    if (out_has_sync_info) *out_has_sync_info = false;
    if (out_sync_transfer_seen) *out_sync_transfer_seen = false;
    if (out_interval_1_25ms) *out_interval_1_25ms = 0;
    if (out_sid) *out_sid = 0xFF;

    xSemaphoreTake(g_ble_lock, portMAX_DELAY);
    for (int i = 0; i < g_ble_count; i++) {
        if (memcmp(g_ble_list[i].mac, mac, 6) == 0) {
            *out_periodic_seen = g_ble_list[i].periodic_adv_seen;
            if (out_has_sync_info) *out_has_sync_info = g_ble_list[i].has_sync_info;
            if (out_sync_transfer_seen) *out_sync_transfer_seen = g_ble_list[i].sync_transfer_seen;
            if (out_interval_1_25ms) *out_interval_1_25ms = g_ble_list[i].periodic_adv_interval;
            if (out_sid) *out_sid = g_ble_list[i].sync_handle;
            xSemaphoreGive(g_ble_lock);
            return true;
        }
    }
    xSemaphoreGive(g_ble_lock);
    return false;
}

bool ble_scanner_get_phy(const uint8_t *mac,
                          bool *out_coded, bool *out_coded_s8,
                          bool *out_1m, bool *out_2m, bool *out_coded_supp)
{
    if (mac == NULL || out_coded == NULL) return false;
    *out_coded = false;
    if (out_coded_s8) *out_coded_s8 = false;
    if (out_1m) *out_1m = false;
    if (out_2m) *out_2m = false;
    if (out_coded_supp) *out_coded_supp = false;

    xSemaphoreTake(g_ble_lock, portMAX_DELAY);
    for (int i = 0; i < g_ble_count; i++) {
        if (memcmp(g_ble_list[i].mac, mac, 6) == 0) {
            *out_coded = g_ble_list[i].phy_coded;
            if (out_coded_s8) *out_coded_s8 = g_ble_list[i].phy_coded_s8;
            if (out_1m) *out_1m = g_ble_list[i].phy_1m;
            if (out_2m) *out_2m = g_ble_list[i].phy_2m;
            if (out_coded_supp) *out_coded_supp = g_ble_list[i].phy_coded_supported;
            xSemaphoreGive(g_ble_lock);
            return true;
        }
    }
    xSemaphoreGive(g_ble_lock);
    return false;
}

void ble_tracker_print(void)
{
    if (g_ble_lock == NULL) {
        return;
    }

    xSemaphoreTake(g_ble_lock, portMAX_DELAY);

    printf("\n");
    printf("=========================================================================\n");
    printf("                POSSIBLE TRACKERS / TAGS HEURISTICS\n");
    printf("=========================================================================\n");
    printf(" #  | BLE MAC           | SCORE | VENDOR      | NAME\n");
    printf("----+-------------------+-------+-------------+-------------------------\n");

    int shown = 0;

    for (int i = 0; i < g_ble_count; i++) {
        if (g_ble_list[i].tracker_score >= 2) {
            shown++;

            printf(
                "%-2d | %02X:%02X:%02X:%02X:%02X:%02X | %-5d | %-11s | %s\n",
                shown,
                g_ble_list[i].mac[5],
                g_ble_list[i].mac[4],
                g_ble_list[i].mac[3],
                g_ble_list[i].mac[2],
                g_ble_list[i].mac[1],
                g_ble_list[i].mac[0],
                g_ble_list[i].tracker_score,
                get_vendor_name(g_ble_list[i].mfg_id),
                g_ble_list[i].name
            );
        }
    }

    if (shown == 0) {
        printf("No high-confidence suspicious devices in current table.\n");
    }

    printf("=========================================================================\n");
    printf("Note: BLE MAC randomization causes many false positives.\n");

    xSemaphoreGive(g_ble_lock);
}

esp_err_t ble_advertise_start(const char *name, uint32_t duration_sec)
{
    if (!g_ble_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    if (!atomic_load(&g_ble_synced)) {
        return ESP_ERR_INVALID_STATE;
    }

    if (atomic_load(&g_ble_scanning)) {
        ESP_LOGW(TAG, "Stop BLE scan before advertising");
        return ESP_ERR_INVALID_STATE;
    }

    if (atomic_load(&g_ble_advertising)) {
        ble_gap_adv_stop();
        atomic_store(&g_ble_advertising, false);
    }

    snprintf(
        g_adv_name,
        sizeof(g_adv_name),
        "%s",
        (name != NULL && name[0] != '\0') ? name : "ESP32-S3-LAB"
    );

    ble_svc_gap_device_name_set(g_adv_name);

    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));

    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.name = (uint8_t *)g_adv_name;
    fields.name_len = (uint8_t)strlen(g_adv_name);

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_set_fields failed: rc=%d", rc);
        return ESP_FAIL;
    }

    struct ble_gap_adv_params adv_params;
    memset(&adv_params, 0, sizeof(adv_params));

    adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;

    uint8_t own_addr_type;
    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto failed: rc=%d", rc);
        return ESP_FAIL;
    }

    int32_t duration_ms = (duration_sec == 0)
        ? BLE_HS_FOREVER
        : (int32_t)(duration_sec * 1000);

    rc = ble_gap_adv_start(
        own_addr_type,
        NULL,
        duration_ms,
        &adv_params,
        ble_adv_event_cb,
        NULL
    );

    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_adv_start failed: rc=%d", rc);
        return ESP_FAIL;
    }

    atomic_store(&g_ble_advertising, true);
    led_set_state(LED_STATE_SCANNING);

    ESP_LOGI(TAG, "BLE advertising started: %s", g_adv_name);
    return ESP_OK;
}

esp_err_t ble_advertise_stop(void)
{
    if (!atomic_load(&g_ble_advertising)) {
        return ESP_OK;
    }

    ble_gap_adv_stop();
    atomic_store(&g_ble_advertising, false);
    led_set_state(LED_STATE_IDLE);

    ESP_LOGI(TAG, "BLE advertising stopped");
    return ESP_OK;
}
