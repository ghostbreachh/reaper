#include "storage_sd.h"

#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_vfs_fat.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "storage_sd";

#define SD_MOUNT_POINT "/sd"

/* 
 * Hardware pin configuration. 
 * Adjust these to match your specific ESP32-S3 board wiring.
 */
#define SD_SPI_HOST     SPI2_HOST
#define SD_PIN_MOSI     11
#define SD_PIN_MISO     13
#define SD_PIN_CLK      12
#define SD_PIN_CS       10

static atomic_bool g_storage_ready = ATOMIC_VAR_INIT(false);
static sdmmc_card_t *g_sd_card = NULL;
static SemaphoreHandle_t g_lock = NULL;

esp_err_t storage_init(void)
{
    if (atomic_load(&g_storage_ready)) {
        return ESP_OK;
    }

    if (g_lock == NULL) {
        g_lock = xSemaphoreCreateMutex();
        if (g_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    /* Double-check after acquiring lock */
    if (atomic_load(&g_storage_ready)) {
        xSemaphoreGive(g_lock);
        return ESP_OK;
    }

    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = false, /* Never auto-format user SD cards */
        .max_files = 8,                  /* Increased slightly for concurrent exports */
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

    /* 
     * Initialize the SPI bus. 
     * If another module already initialized it, spi_bus_initialize returns 
     * ESP_ERR_INVALID_STATE. We can safely ignore that and continue.
     */
    esp_err_t ret = spi_bus_initialize(SD_SPI_HOST, &bus_cfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Failed to initialize SPI bus (%s)", esp_err_to_name(ret));
        xSemaphoreGive(g_lock);
        return ret;
    }

    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.gpio_cs = SD_PIN_CS;
    slot_config.host_id = SD_SPI_HOST;

    ret = esp_vfs_fat_sdspi_mount(SD_MOUNT_POINT, &host, &slot_config, &mount_config, &g_sd_card);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "SD card mount failed (%s). Check if card is inserted.", esp_err_to_name(ret));
        /* Do not free SPI bus here, as another module might be using it */
        xSemaphoreGive(g_lock);
        return ret;
    }

    atomic_store(&g_storage_ready, true);
    
    /* Calculate and log capacity */
    uint64_t capacity_bytes = (uint64_t)g_sd_card->csd.capacity * g_sd_card->csd.sector_size;
    ESP_LOGI(TAG, "SD Card mounted successfully at %s (%.2f MB)", 
             SD_MOUNT_POINT, 
             (double)capacity_bytes / (1024.0 * 1024.0));
             
    xSemaphoreGive(g_lock);
    return ESP_OK;
}

void storage_deinit(void)
{
    if (!atomic_load(&g_storage_ready)) {
        return;
    }

    if (g_lock == NULL) return;

    if (xSemaphoreTake(g_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return;
    }

    if (!atomic_load(&g_storage_ready)) {
        xSemaphoreGive(g_lock);
        return;
    }

    if (g_sd_card != NULL) {
        esp_vfs_fat_sdcard_unmount(SD_MOUNT_POINT, g_sd_card);
        g_sd_card = NULL;
    }
    
    /* 
     * Note: We intentionally do NOT call spi_bus_free(SD_SPI_HOST) here.
     * If other peripherals (like an SPI display or sensor) share this bus,
     * freeing it would break them. The bus will be safely torn down on system reboot.
     */

    atomic_store(&g_storage_ready, false);
    ESP_LOGI(TAG, "SD storage unmounted");
    
    xSemaphoreGive(g_lock);
}

bool storage_is_ready(void)
{
    return atomic_load(&g_storage_ready);
}

const char* storage_sd_get_mount_point(void)
{
    return SD_MOUNT_POINT;
}
