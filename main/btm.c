#include "btm.h"
#include <string.h>
#include "esp_log.h"

static btm_request_t s_reqs[BTM_MAX_REQUESTS];
static size_t s_count = 0;
static bool s_init = false;
static const char *TAG = "btm";

esp_err_t btm_init(void)
{
    memset(s_reqs, 0, sizeof(s_reqs));
    s_count = 0;
    s_init = true;
    ESP_LOGI(TAG, "802.11v BTM parser initialized");
    return ESP_OK;
}

void btm_parse_request(const uint8_t *frame, size_t len)
{
    if (!s_init || !frame || len < 25) return;
    if (s_count >= BTM_MAX_REQUESTS) return;
    memcpy(s_reqs[s_count].src_bssid, frame + 10, 6);
    memcpy(s_reqs[s_count].dst_bssid, frame + 16, 6);
    s_reqs[s_count].disassoc_timer = frame[24];
    s_reqs[s_count].valid = true;
    s_count++;
}

size_t btm_list(btm_request_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_count < max ? s_count : max;
    memcpy(out, s_reqs, n * sizeof(btm_request_t));
    return n;
}

void btm_clear(void)
{
    memset(s_reqs, 0, sizeof(s_reqs));
    s_count = 0;
}
