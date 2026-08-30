#ifndef USB_CDC_H
#define USB_CDC_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Get custom VID/PID as a 32-bit packed value (VID<<16 | PID). */
uint32_t usb_cdc_get_vidpid(void);

/* Return human-readable string for descriptor. */
const char *usb_cdc_product_string(void);
const char *usb_cdc_manufacturer_string(void);
const char *usb_cdc_serial_string(void);

#ifdef __cplusplus
}
#endif

#endif /* USB_CDC_H */
