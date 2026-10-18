#include "ai_ble_profiler.h"
#include "ai_model.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_err.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "ai_ble";

typedef struct {
    uint8_t  ad_flags;
    uint16_t mfg_id;
    bool     has_name;
    bool     has_tx_power;
    int8_t   tx_power;
} ble_adv_features_t;

static char g_model_name[64] = {0};

static bool g_init_done = false;

static uint32_t g_total_count = 0;
static uint32_t g_model_count = 0;
static uint32_t g_heuristic_count = 0;

static uint32_t g_infer_every = AI_BLE_PROFILER_DEFAULT_INFER_EVERY;

static SemaphoreHandle_t g_lock = NULL;
static SemaphoreHandle_t g_infer_lock = NULL;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static const char *ble_class_name(ai_ble_class_t cls)
{
    switch (cls) {
        case AI_BLE_TAG:     return "tag";
        case AI_BLE_PHONE:   return "phone";
        case AI_BLE_SENSOR:  return "sensor";
        case AI_BLE_TRACKER: return "tracker";
        case AI_BLE_BEACON:  return "beacon";
        default:             return "unknown";
    }
}

const char *ai_ble_profiler_class_name(ai_ble_class_t cls)
{
    return ble_class_name(cls);
}

static void sanitize_model_name(char *dst, size_t dst_sz, const char *src)
{
    if (dst == NULL || dst_sz == 0) {
        return;
    }

    size_t j = 0;

    if (src != NULL) {
        for (size_t i = 0; src[i] != '\0' && j + 1 < dst_sz; i++) {
            unsigned char c = (unsigned char)src[i];

            if (isprint(c) && c != '"' && c != '\\') {
                dst[j++] = (char)c;
            } else {
                dst[j++] = '_';
            }
        }
    }

    dst[j] = '\0';
}

/* -------------------------------------------------------------------------
 *  Advertisement parsing
 * ----------------------------------------------------------------------- */

static void parse_adv_fields(const uint8_t *data, size_t len, ble_adv_features_t *feat)
{
    memset(feat, 0, sizeof(*feat));

    if (data == NULL || len == 0) {
        return;
    }

    size_t pos = 0;

    while (pos + 1 < len) {
        uint8_t ad_len = data[pos];

        if (ad_len == 0) {
            break;
        }

        if (pos + 1 + ad_len > len) {
            break;
        }

        uint8_t ad_type = data[pos + 1];
        const uint8_t *val = data + pos + 2;
        size_t val_len = ad_len - 1;

        switch (ad_type) {
            case 0x01: /* Flags */
                if (val_len >= 1) {
                    feat->ad_flags = val[0];
                }
                break;

            case 0x08: /* Shortened Local Name */
            case 0x09: /* Complete Local Name */
                if (val_len > 0) {
                    feat->has_name = true;
                }
                break;

            case 0x0A: /* TX Power Level */
                if (val_len >= 1) {
                    feat->has_tx_power = true;
                    feat->tx_power = (int8_t)val[0];
                }
                break;

            case 0xFF: /* Manufacturer Specific Data */
                if (val_len >= 2) {
                    feat->mfg_id = (uint16_t)(val[0] | ((uint16_t)val[1] << 8));
                }
                break;

            default:
                break;
        }

        pos += 1 + ad_len;
    }
}

static int32_t get_tx_dbm(const ble_info_t *info, const ble_adv_features_t *feat)
{
    if (feat->has_tx_power) {
        return (int32_t)feat->tx_power;
    }

    /*
     * Scanner uses 0x7F as "unknown".
     * Also treat 0 as unknown because many parsers initialize to zero.
     */
    if (info->tx_power == 0 || info->tx_power == 0x7F) {
        return 0;
    }

    /*
     * If tx_power is stored as a raw signed byte, reinterpret it.
     */
    return (int32_t)(int8_t)info->tx_power;
}

static uint8_t normalize_tx_feature(int32_t tx_dbm)
{
    /*
     * Normalize roughly -100..+20 dBm into 0..255.
     */
    if (tx_dbm < -100) {
        tx_dbm = -100;
    }

    if (tx_dbm > 20) {
        tx_dbm = 20;
    }

    int32_t normalized = ((tx_dbm + 100) * 255) / 120;

    if (normalized < 0) {
        normalized = 0;
    }

    if (normalized > 255) {
        normalized = 255;
    }

    return (uint8_t)normalized;
}

/* -------------------------------------------------------------------------
 *  Feature tensor
 * ----------------------------------------------------------------------- */

static void build_ble_tensor(const ble_info_t *info,
                             const ble_adv_features_t *feat,
                             uint8_t tensor[AI_BLE_PROFILER_FEAT_SZ])
{
    memset(tensor, 0, AI_BLE_PROFILER_FEAT_SZ);

    /*
     * Layout:
     *
     * [0] MAC/OUI byte 0
     * [1] MAC/OUI byte 1
     * [2] MAC/OUI byte 2
     * [3] behavior flags
     * [4] normalized TX power
     * [5] adv_mode
     * [6] AD flags
     * [7] manufacturer ID low byte
     */

    tensor[0] = info->mac[0];
    tensor[1] = info->mac[1];
    tensor[2] = info->mac[2];

    uint8_t flags = 0;

    if (info->has_scan_rsp) {
        flags |= 0x01;
    }

    if (info->adv_mode == 1) {
        flags |= 0x02;
    }

    if (info->phy_coded_s8) {
        flags |= 0x04;
    }

    if (info->periodic_adv_seen) {
        flags |= 0x08;
    }

    if (info->rpa_seen) {
        flags |= 0x10;
    }

    if (info->ext_adv_seen) {
        flags |= 0x20;
    }

    if (feat->has_name) {
        flags |= 0x40;
    }

    if (feat->has_tx_power) {
        flags |= 0x80;
    }

    tensor[3] = flags;

    int32_t tx_dbm = get_tx_dbm(info, feat);
    tensor[4] = normalize_tx_feature(tx_dbm);

    tensor[5] = info->adv_mode;
    tensor[6] = feat->ad_flags;
    tensor[7] = (uint8_t)(feat->mfg_id & 0xFFu);
}

/* -------------------------------------------------------------------------
 *  Heuristic fallback
 * ----------------------------------------------------------------------- */

static ai_ble_class_t heuristic_classify(const ble_info_t *info,
                                         const ble_adv_features_t *feat)
{
    int32_t tx_dbm = get_tx_dbm(info, feat);

    /*
     * Periodic non-connectable advertisers are often beacons.
     */
    if (info->periodic_adv_seen && info->adv_mode == 1) {
        return AI_BLE_BEACON;
    }

    /*
     * Apple/Samsung manufacturer data + random MAC + no name is suspicious.
     */
    if ((feat->mfg_id == 0x004C || feat->mfg_id == 0x0075) &&
        info->addr_type != 0 &&
        !feat->has_name) {

        if (info->rpa_seen || info->phy_coded_s8) {
            return AI_BLE_TRACKER;
        }

        return AI_BLE_TAG;
    }

    /*
     * Original behavior preserved as much as possible.
     */
    if (info->has_scan_rsp && info->adv_mode == 1) {
        return AI_BLE_TRACKER;
    }

    if (info->phy_coded_s8 && tx_dbm < -50) {
        return AI_BLE_SENSOR;
    }

    if (info->adv_mode == 1 && !info->has_scan_rsp) {
        return AI_BLE_TAG;
    }

    if (info->rpa_seen && info->has_scan_rsp) {
        return AI_BLE_PHONE;
    }

    return AI_BLE_UNKNOWN;
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t ai_ble_profiler_init(void)
{
    if (g_init_done) {
        return ESP_OK;
    }

    if (g_lock == NULL) {
        g_lock = xSemaphoreCreateMutex();
        if (g_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    if (g_infer_lock == NULL) {
        g_infer_lock = xSemaphoreCreateMutex();
        if (g_infer_lock == NULL) {
            vSemaphoreDelete(g_lock);
            g_lock = NULL;
            return ESP_ERR_NO_MEM;
        }
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_model_name, 0, sizeof(g_model_name));

    g_init_done = true;
    g_total_count = 0;
    g_model_count = 0;
    g_heuristic_count = 0;
    g_infer_every = AI_BLE_PROFILER_DEFAULT_INFER_EVERY;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "BLE profiler initialized");
    return ESP_OK;
}

void ai_ble_profiler_deinit(void)
{
    if (g_lock == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_model_name, 0, sizeof(g_model_name));

    g_init_done = false;
    g_total_count = 0;
    g_model_count = 0;
    g_heuristic_count = 0;
    g_infer_every = AI_BLE_PROFILER_DEFAULT_INFER_EVERY;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "BLE profiler deinitialized");
}

/* -------------------------------------------------------------------------
 *  Configuration
 * ----------------------------------------------------------------------- */

esp_err_t ai_ble_profiler_set_model(const char *model_name)
{
    if (model_name == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    sanitize_model_name(g_model_name, sizeof(g_model_name), model_name);
    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "BLE profiler model set: '%s'", g_model_name);
    return ESP_OK;
}

esp_err_t ai_ble_profiler_set_infer_every(uint32_t every_n)
{
    if (every_n == 0) {
        every_n = 1;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);
    g_infer_every = every_n;
    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "BLE profiler model inference every %" PRIu32 " advertisements", every_n);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Classification
 * ----------------------------------------------------------------------- */

esp_err_t ai_ble_profiler_classify(const ble_info_t *info,
                                   const uint8_t *adv_data,
                                   size_t adv_len,
                                   ai_ble_profile_t *out)
{
    if (info == NULL || out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (adv_data == NULL && adv_len > 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    memset(out, 0, sizeof(*out));
    memcpy(out->oui, info->mac, 3);

    ble_adv_features_t feat;
    parse_adv_fields(adv_data, adv_len, &feat);

    uint8_t tensor[AI_BLE_PROFILER_FEAT_SZ];
    build_ble_tensor(info, &feat, tensor);

    char model_local[sizeof(g_model_name)] = {0};
    bool should_infer = false;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    g_total_count++;

    bool model_enabled = (g_model_name[0] != '\0');

    if (model_enabled) {
        if (g_infer_every <= 1 || (g_total_count % g_infer_every) == 0) {
            snprintf(model_local, sizeof(model_local), "%s", g_model_name);
            should_infer = true;
        }
    }

    xSemaphoreGive(g_lock);

    /*
     * Try model inference outside the state lock.
     */
    if (should_infer) {
        uint8_t model_out[4] = {0};
        size_t out_len = 0;

        uint64_t t0 = esp_timer_get_time();

        if (g_infer_lock != NULL) {
            xSemaphoreTake(g_infer_lock, portMAX_DELAY);
        }

        esp_err_t rc = ai_model_zoo_infer(
            model_local,
            tensor,
            sizeof(tensor),
            model_out,
            sizeof(model_out),
            &out_len
        );

        if (g_infer_lock != NULL) {
            xSemaphoreGive(g_infer_lock);
        }

        uint64_t dt = esp_timer_get_time() - t0;

        if (rc == ESP_OK && out_len >= 4) {
            uint8_t cls_byte = model_out[0];

            if (cls_byte <= AI_BLE_BEACON) {
                out->cls = (ai_ble_class_t)cls_byte;
            } else {
                out->cls = AI_BLE_UNKNOWN;
            }

            snprintf(out->label, sizeof(out->label), "%s", ble_class_name(out->cls));

            out->adv_type = info->adv_mode;
            out->flags = model_out[1];
            out->model_loaded = true;
            out->inference_us = (uint32_t)dt;

            xSemaphoreTake(g_lock, portMAX_DELAY);
            g_model_count++;
            xSemaphoreGive(g_lock);

            return ESP_OK;
        }

        ESP_LOGD(TAG, "Model inference failed; falling back to heuristic");
    }

    /*
     * Heuristic fallback.
     */
    ai_ble_class_t cls = heuristic_classify(info, &feat);

    out->cls = cls;
    snprintf(out->label, sizeof(out->label), "%s", ble_class_name(cls));
    out->adv_type = info->adv_mode;
    out->flags = feat.ad_flags;
    out->model_loaded = false;
    out->inference_us = 0;

    xSemaphoreTake(g_lock, portMAX_DELAY);
    g_heuristic_count++;
    xSemaphoreGive(g_lock);

    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Stats / JSON
 * ----------------------------------------------------------------------- */

esp_err_t ai_ble_profiler_json(char *buf, size_t bufsz)
{
    if (buf == NULL || bufsz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    uint32_t total;
    uint32_t model;
    uint32_t heuristic;
    char model_name[sizeof(g_model_name)];

    xSemaphoreTake(g_lock, portMAX_DELAY);

    total = g_total_count;
    model = g_model_count;
    heuristic = g_heuristic_count;
    snprintf(model_name, sizeof(model_name), "%s", g_model_name);

    xSemaphoreGive(g_lock);

    int w = snprintf(
        buf,
        bufsz,
        "{\"total\":%" PRIu32
        ",\"model\":%" PRIu32
        ",\"heuristic\":%" PRIu32
        ",\"model_name\":\"%s\"}",
        total,
        model,
        heuristic,
        model_name
    );

    if (w < 0 || (size_t)w >= bufsz) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}
