#ifndef PORT_DETECT_H
#define PORT_DETECT_H

#include "common_types.h"

esp_err_t boot_port_detect(port_detect_result_t *out_result);
const char *port_transport_name(port_transport_t t);
void port_print_banner(const port_detect_result_t *res);

#endif // PORT_DETECT_H
