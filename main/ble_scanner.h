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

esp_err_t ble_advertise_start(const char *name, uint32_t duration_sec);
esp_err_t ble_advertise_stop(void);

#endif // BLE_SCANNER_H
