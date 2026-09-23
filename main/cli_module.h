#ifndef CLI_MODULE_H
#define CLI_MODULE_H

#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * Note: cli_start() is declared in cli_transport.h, as the transport layer 
 * owns the task lifecycle. This header only exposes the dispatcher.
 */

void cli_dispatch_command(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

#endif // CLI_MODULE_H
