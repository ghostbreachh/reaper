#include "btm.h"

#include <string.h>
#include <stdatomic.h>

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "btm";

/* 802.11 Action frame offsets */
#define FRAME_HDR_LEN       24
#define WNM_CATEGORY        10
#define BTM_REQUEST_ACTION  7
#define BTM_MIN_LEN         30  /* Need bytes 28-29 for disassoc timer */

static btm_request_t s_reqs[BTM_MAX_REQUESTS];
static size_t s_count = 0;
static atomic_bool s_init = ATOMIC_VAR_INIT(false);
static SemaphoreHandle_t s_lock = NULL;

esp_err_t btm_init(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
        if (s_lock == NULL) return ESP_ERR_NO_MEM;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    memset(s_reqs, 0, sizeof(s_reqs));
    s_count = 0;
    xSemaphoreGive(s_lock);

    atomic_store(&s_init, true);
    ESP_LOGI(TAG, "802.11v BTM parser initialized");
    return ESP_OK;
}

void btm_parse_request(const uint8_t *frame, size_t len)
{
    if (!atomic_load(&s_init) || !frame || len < BTM_MIN_LEN) return;
    if (s_lock == NULL) return;

    /* Validate this is a WNM BTM Request */
    uint8_t category = frame[FRAME_HDR_LEN];
    uint8_t action   = frame[FRAME_HDR_LEN + 1];

    if (category != WNM_CATEGORY || action != BTM_REQUEST_ACTION) {
        return;
    }

    if (xSemaphoreTake(s_lock, 0) != pdTRUE) return; /* Non-blocking for hot path */

    if (s_count >= BTM_MAX_REQUESTS) {
        xSemaphoreGive(s_lock);
        return;
    }

    btm_request_t *r = &s_reqs[s_count];

    /* Addr2 (Transmitter/AP) at offset 10 */
    memcpy(r->src_bssid, frame + 10, 6);

    /* Addr1 (Receiver/Client) at offset 4 — used as dst since BTM targets a client */
    memcpy(r->dst_bssid, frame + 4, 6);

    /* Disassociation Timer: 2 bytes at offset 28-29 (little-endian) */
    r->disassoc_timer = (uint16_t)frame[28] | ((uint16_t)frame[29] << 8);

    r->valid = true;
    s_count++;

    xSemaphoreGive(s_lock);

    ESP_LOGI(TAG, "BTM Request captured: disassoc_timer=%u", r->disassoc_timer);
}

size_t btm_list(btm_request_t *out, size_t max)
{
    if (!out || max == 0 || !atomic_load(&s_init) || s_lock == NULL) return 0;

    size_t n = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        n = (s_count < max) ? s_count : max;
        memcpy(out, s_reqs, n * sizeof(btm_request_t));
        xSemaphoreGive(s_lock);
    }
    return n;
}

void btm_clear(void)
{
    if (!atomic_load(&s_init) || s_lock == NULL) return;

    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        memset(s_reqs, 0, sizeof(s_reqs));
        s_count = 0;
        xSemaphoreGive(s_lock);
    }
}
