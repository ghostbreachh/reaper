#ifndef USB_CDC_H
#define USB_CDC_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Line coding struct (mirrors TinyUSB cdc_line_coding_t). */
typedef struct {
    uint32_t bit_rate;      /* baud rate */
    uint8_t  data_bits;     /* usually 8 */
    uint8_t  parity;        /* 0=none, 1=odd, 2=even, 3=mark, 4=space */
    uint8_t  stop_bits;     /* 0=1, 1=1.5, 2=2 */
} usb_cdc_line_coding_t;

esp_err_t usb_cdc_init(void);
esp_err_t usb_cdc_set_vid_pid(uint16_t vid, uint16_t pid);
esp_err_t usb_cdc_get_vid_pid(uint16_t *out_vid, uint16_t *out_pid);
uint32_t usb_cdc_get_vidpid(void);

const char *usb_cdc_manufacturer_string(void);
const char *usb_cdc_product_string(void);
const char *usb_cdc_serial_string(void);

/* Line coding API */
esp_err_t usb_cdc_set_line_coding(const usb_cdc_line_coding_t *coding);
esp_err_t usb_cdc_get_line_coding(usb_cdc_line_coding_t *out);
esp_err_t usb_cdc_line_coding_to_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif /* USB_CDC_H */
