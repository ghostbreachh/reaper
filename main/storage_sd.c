#include <stdbool.h>
#include <stdatomic.h>
#include "storage_sd.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "esp_vfs_fat.h"
#include "esp_system.h"
#include <stdatomic.h>

atomic_bool g_storage_ready = ATOMIC_VAR_INIT(false);

#define SD_SPI_HOST     SPI2_HOST
#define SD_PIN_MOSI     11
#define SD_PIN_MISO     13
#define SD_PIN_CLK      12
#define SD_PIN_CS       10



static const char *TAG = "storage";
sdmmc_card_t *g_sd_card = NULL;

esp_err_t storage_init(void)
{
    if (atomic_load(&g_storage_ready)) {
        return ESP_OK;
    }

    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = false,
        .max_files = 5,
        .allocation_unit_size = 16 * 1024
    };

    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = SD_SPI_HOST;

    spi_bus_config_t bus_cfg = {
        .mosi_io_num = SD_PIN_MOSI,
        .miso_io_num = SD_PIN_MISO,
        .sclk_io_num = SD_PIN_CLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 4000,
    };

    esp_err_t ret = spi_bus_initialize(SD_SPI_HOST, &bus_cfg, SDSPI_DEFAULT_DMA);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "SPI bus init failed (%s), storage unavailable", esp_err_to_name(ret));
        return ret;
    }

    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.gpio_cs = SD_PIN_CS;
    slot_config.host_id = SD_SPI_HOST;

    ret = esp_vfs_fat_sdspi_mount("/sd", &host, &slot_config, &mount_config, &g_sd_card);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "SD card mount failed (%s), storage unavailable", esp_err_to_name(ret));
        return ret;
    }

    atomic_store(&g_storage_ready, true);
    ESP_LOGI(TAG, "SD Card mounted successfully at /sd");
    return ESP_OK;
}

void storage_deinit(void)
{
    if (!atomic_load(&g_storage_ready)) {
        return;
    }
    if (g_sd_card != NULL) {
        esp_vfs_fat_sdcard_unmount("/sd", g_sd_card);
        g_sd_card = NULL;
    }
    spi_bus_free(SD_SPI_HOST);
    atomic_store(&g_storage_ready, false);
    ESP_LOGI(TAG, "SD storage unmounted");
}

bool storage_is_ready(void)
{
    return atomic_load(&g_storage_ready);
}
