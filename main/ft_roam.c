#include "ft_roam.h"
#include <string.h>
#include "esp_log.h"

static ft_target_t s_targets[FT_MAX_TARGETS];
static size_t s_count = 0;
static bool s_init = false;
static const char *TAG = "ft_roam";

esp_err_t ft_roam_init(void)
{
    memset(s_targets, 0, sizeof(s_targets));
    s_count = 0;
    s_init = true;
    ESP_LOGI(TAG, "802.11r FT attack module initialized");
    return ESP_OK;
}

void ft_roam_record_target(const uint8_t *bssid, uint8_t channel,
                            uint8_t mobility_domain)
{
    if (!s_init || !bssid || s_count >= FT_MAX_TARGETS) return;
    memcpy(s_targets[s_count].bssid, bssid, 6);
    s_targets[s_count].channel = channel;
    s_targets[s_count].mobility_domain = mobility_domain;
    s_targets[s_count].valid = true;
    s_count++;
}

size_t ft_roam_targets(ft_target_t *out, size_t max)
{
    if (!out || !max) return 0;
    size_t n = s_count < max ? s_count : max;
    memcpy(out, s_targets, n * sizeof(ft_target_t));
    return n;
}

bool ft_roam_inject_reassoc_request(const uint8_t *src_bssid,
                                    const uint8_t *dst_bssid)
{
    (void)src_bssid; (void)dst_bssid;
    return false;
}
