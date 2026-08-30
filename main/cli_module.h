#ifndef CLI_MODULE_H
#define CLI_MODULE_H

#include "common_types.h"

esp_err_t cli_start(void);
void cli_dispatch_command(int argc, char *argv[]);

#endif // CLI_MODULE_H
