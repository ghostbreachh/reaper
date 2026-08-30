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

esp_err_t ble_advertise_start(const char *name, uint32_t duration_sec);
esp_err_t ble_advertise_stop(void);

#endif // BLE_SCANNER_H
