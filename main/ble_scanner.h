#ifndef BLE_SCANNER_H
#define BLE_SCANNER_H

#include "common_types.h"

esp_err_t ble_scanner_init(void);
esp_err_t ble_scanner_start(uint32_t duration_sec);
esp_err_t ble_scanner_stop(void);

void ble_scanner_print_results(void);
void ble_scanner_fprint(FILE *out);
esp_err_t ble_scanner_save_report(const char *path);
uint16_t ble_scanner_get_count(void);

void ble_tracker_print(void);

bool ble_scanner_get_ext_adv(const uint8_t *mac,
                              bool *out_ext_adv, bool *out_aux_ptr,
                              bool *out_adi, uint8_t *out_adv_mode,
                              bool *out_scan_rsp, uint8_t *out_tx_power);

bool ble_scanner_get_periodic(const uint8_t *mac,
                              bool *out_periodic_seen,
                              bool *out_has_sync_info,
                              bool *out_sync_transfer_seen,
                              uint16_t *out_interval_1_25ms,
                              uint8_t *out_sid);

esp_err_t ble_advertise_start(const char *name, uint32_t duration_sec);
esp_err_t ble_advertise_stop(void);

#endif // BLE_SCANNER_H
