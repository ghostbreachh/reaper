#ifndef AI_ROGUE_DETECTOR_H
#define AI_ROGUE_DETECTOR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of alerts retained from the last scan. */
#define AI_ROGUE_MAX_ALERTS 16

/* Rogue/evil-twin alert types. */
#define AI_ROGUE_FLAG_DIFF_OUI     0x01  /* Same SSID, different OUI */
#define AI_ROGUE_FLAG_DIFF_CHAN    0x02  /* Same SSID, different channels */
#define AI_ROGUE_FLAG_DIFF_CIPHER  0x04  /* Same SSID, mixed security profile */
#define AI_ROGUE_FLAG_MAC_ANOMALY  0x08  /* Locally administered BSSID */
#define AI_ROGUE_FLAG_VENDOR_MIX   0x10  /* Reserved for future vendor-class mix */

/* Detected rogue candidate. */
typedef struct {
    char    ssid[33];
    uint8_t bssid[6];
    uint8_t oui[3];
    uint8_t channel;
    uint8_t flags;        /* bitmask of AI_ROGUE_FLAG_* */
    uint8_t peer_count;   /* other BSSIDs with same SSID */
    char    reason[64];
} ai_rogue_alert_t;

/**
 * @brief Initialize rogue AP detector.
 */
esp_err_t ai_rogue_detector_init(void);

/**
 * @brief Deinit detector.
 */
void ai_rogue_detector_deinit(void);

/**
 * @brief Scan current AP list for evil-twin candidates.
 *
 * Call after AP table is populated by sniffer.
 * Internally throttled.
 */
esp_err_t ai_rogue_detector_scan(void);

/**
 * @brief Get number of alerts from last scan.
 */
uint8_t ai_rogue_detector_alert_count(void);

/**
 * @brief Get alert by index.
 */
esp_err_t ai_rogue_detector_get_alert(uint8_t idx, ai_rogue_alert_t *out);

/**
 * @brief Return alerts as JSON array.
 */
esp_err_t ai_rogue_detector_json(char *buf, size_t bufsz);

#ifdef __cplusplus
}
#endif

#endif /* AI_ROGUE_DETECTOR_H */
