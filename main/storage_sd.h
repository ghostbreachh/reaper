#ifndef STORAGE_SD_H
#define STORAGE_SD_H

#include "common_types.h"
#include "sdmmc_cmd.h"
#include <stdbool.h>
#include <stdatomic.h>

extern atomic_bool g_storage_ready;
esp_err_t storage_init(void);
void storage_deinit(void);
bool storage_is_ready(void);
extern sdmmc_card_t *g_sd_card;

#endif // STORAGE_SD_H
