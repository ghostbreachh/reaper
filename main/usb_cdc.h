#ifndef USB_CDC_H
#define USB_CDC_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Line coding struct (mirrors TinyUSB cdc_line_coding_t). */
typedef struct {
    uint32_t bit_rate;
    uint8_t  data_bits;
    uint8_t  parity;
    uint8_t  stop_bits;
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

/* Break/interrupt signal: monitors DTR transitions.
 * Call usb_cdc_poll_break() from long-running task loops.
 * Returns true if a break (Ctrl-C equivalent) was detected since last call. */
bool usb_cdc_break_signaled(void);
void usb_cdc_break_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* USB_CDC_H */
