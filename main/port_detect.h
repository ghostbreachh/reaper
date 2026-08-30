#ifndef PORT_DETECT_H
#define PORT_DETECT_H

#include "common_types.h"

esp_err_t boot_port_detect(port_detect_result_t *out_result);
const char *port_transport_name(port_transport_t t);
void port_print_banner(const port_detect_result_t *res);

/* Global cache of boot-time detection. Other modules may read this
 * after `boot_port_detect()` has been called. */
extern port_detect_result_t g_boot_port;

#endif // PORT_DETECT_H
