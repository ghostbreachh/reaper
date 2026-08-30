#ifndef USB_CDC_H
#define USB_CDC_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t bit_rate;
    uint8_t  data_bits;
    uint8_t  parity;
    uint8_t  stop_bits;
} usb_cdc_line_coding_t;

typedef struct {
    bool     connected;
    bool     dtr_active;
    bool     rts_active;
    uint16_t vid;
    uint16_t pid;
    char     serial[32];
    char     manufacturer[64];
    char     product[64];
    uint32_t tx_avail;
    size_t   tx_pending;
} usb_cdc_caps_t;

esp_err_t usb_cdc_init(void);
esp_err_t usb_cdc_set_vid_pid(uint16_t vid, uint16_t pid);
esp_err_t usb_cdc_get_vid_pid(uint16_t *out_vid, uint16_t *out_pid);
uint32_t usb_cdc_get_vidpid(void);

const char *usb_cdc_manufacturer_string(void);
const char *usb_cdc_product_string(void);
const char *usb_cdc_serial_string(void);

esp_err_t usb_cdc_set_line_coding(const usb_cdc_line_coding_t *coding);
esp_err_t usb_cdc_get_line_coding(usb_cdc_line_coding_t *out);
esp_err_t usb_cdc_line_coding_to_json(char *buf, size_t bufsz);

bool usb_cdc_break_signaled(void);
void usb_cdc_break_clear(void);
esp_err_t usb_cdc_break_to_json(char *buf, size_t bufsz);

bool usb_cdc_write_available(size_t needed_bytes);
esp_err_t usb_cdc_write(const uint8_t *buf, size_t len);
void usb_cdc_flow_resume(void);
size_t usb_cdc_tx_pending(void);

esp_err_t usb_cdc_get_capabilities(usb_cdc_caps_t *out);
esp_err_t usb_cdc_caps_to_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif /* USB_CDC_H */
