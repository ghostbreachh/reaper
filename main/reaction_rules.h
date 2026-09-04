#ifndef REACTION_RULES_H
#define REACTION_RULES_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define REACTION_MAX_RULES 8

typedef enum {
    REACTION_TRIG_AP_SEEN = 0,
    REACTION_TRIG_CLIENT_JOIN,
    REACTION_TRIG_ANOMALY_HIGH,
    REACTION_TRIG_BLE_SEEN,
    REACTION_TRIG_HANDSHAKE,
    REACTION_TRIG_ROGUE_AP
} reaction_trigger_t;

typedef enum {
    REACTION_ACT_DEAUTH = 0,
    REACTION_ACT_WARDRIVE_START,
    REACTION_ACT_STEALTH_PASSIVE,
    REACTION_ACT_TRAIN_START,
    REACTION_ACT_TRAIN_STOP,
    REACTION_ACT_ALERT
} reaction_action_t;

typedef struct {
    bool enabled;
    reaction_trigger_t trigger;
    uint8_t param[32];      /* bssid, ssid prefix, threshold, etc. */
    reaction_action_t action;
    uint8_t action_param[32]; /* mode string, target, etc. */
} reaction_rule_t;

/* Initialize reaction engine. */
esp_err_t reaction_rules_init(void);

/* Add rule; returns index or negative error. */
int reaction_rules_add(const reaction_rule_t *rule);

/* Remove rule by index. */
esp_err_t reaction_rules_remove(uint8_t index);

/* Get rule by index. */
esp_err_t reaction_rules_get(uint8_t index, reaction_rule_t *out);

/* List all rules as JSON. */
esp_err_t reaction_rules_json(char *buf, size_t bufsz);

/* Trigger checks — call from existing modules. */
esp_err_t reaction_rules_check_ap(const uint8_t *bssid, const char *ssid);
esp_err_t reaction_rules_check_client(const uint8_t *client, const uint8_t *ap);
esp_err_t reaction_rules_check_anomaly(float score);
esp_err_t reaction_rules_check_ble(const uint8_t *addr);
esp_err_t reaction_rules_check_handshake(void);
esp_err_t reaction_rules_check_rogue(const char *ssid);

/* Deinit. */
esp_err_t reaction_rules_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* REACTION_RULES_H */
