#include "ai_fingerprint.h"
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

static const char *TAG = "ai_fp";

static char g_model_name[64] = {0};

static bool g_init_done = false;

static uint32_t g_total_count = 0;
static uint32_t g_model_count = 0;
static uint32_t g_heuristic_count = 0;
static uint32_t g_last_infer_us = 0;

static uint32_t g_infer_every = AI_FINGERPRINT_DEFAULT_INFER_EVERY;

static SemaphoreHandle_t g_lock = NULL;
static SemaphoreHandle_t g_infer_lock = NULL;

/* -------------------------------------------------------------------------
 *  Helpers
 * ----------------------------------------------------------------------- */

static const char *fp_class_name(ai_fp_class_t cls)
{
    switch (cls) {
        case AI_FP_PHONE:   return "phone";
        case AI_FP_LAPTOP:  return "laptop";
        case AI_FP_IOT:     return "iot";
        case AI_FP_AP:      return "ap";
        case AI_FP_ROUTER:  return "router";
        default:            return "unknown";
    }
}

const char *ai_fingerprint_class_name(ai_fp_class_t cls)
{
    return fp_class_name(cls);
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

static bool mac_is_zero(const uint8_t *mac)
{
    if (mac == NULL) {
        return true;
    }

    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0) {
            return false;
        }
    }

    return true;
}

static bool mac_is_multicast(const uint8_t *mac)
{
    if (mac == NULL) {
        return true;
    }

    return (mac[0] & 0x01u) != 0;
}

static bool mac_is_locally_administered(const uint8_t *mac)
{
    if (mac == NULL) {
        return true;
    }

    return (mac[0] & 0x02u) != 0;
}

static bool oui_is_reliable(const uint8_t *mac)
{
    if (mac_is_zero(mac)) {
        return false;
    }

    if (mac_is_multicast(mac)) {
        return false;
    }

    if (mac_is_locally_administered(mac)) {
        return false;
    }

    return true;
}

/* -------------------------------------------------------------------------
 *  IE extraction
 * ----------------------------------------------------------------------- */

static uint8_t extract_rates(const uint8_t *ie,
                             size_t ie_len,
                             uint8_t *out_rates,
                             size_t max_rates)
{
    if (ie == NULL || out_rates == NULL || max_rates == 0) {
        return 0;
    }

    size_t count = 0;
    size_t off = 0;

    while (off + 2 <= ie_len && count < max_rates) {
        uint8_t id = ie[off];
        uint8_t tag_len = ie[off + 1];

        if (off + 2 + tag_len > ie_len) {
            break;
        }

        if (id == 1 || id == 50) {
            size_t copy = tag_len;

            if (copy > max_rates - count) {
                copy = max_rates - count;
            }

            memcpy(out_rates + count, ie + off + 2, copy);
            count += copy;
        }

        off += 2 + tag_len;
    }

    return (uint8_t)count;
}

static uint8_t extract_ext_cap(const uint8_t *ie,
                               size_t ie_len,
                               uint8_t *out_cap,
                               size_t max_cap)
{
    if (ie == NULL || out_cap == NULL || max_cap == 0) {
        return 0;
    }

    size_t off = 0;

    while (off + 2 <= ie_len) {
        uint8_t id = ie[off];
        uint8_t tag_len = ie[off + 1];

        if (off + 2 + tag_len > ie_len) {
            break;
        }

        if (id == 127) {
            size_t copy = tag_len;

            if (copy > max_cap) {
                copy = max_cap;
            }

            memcpy(out_cap, ie + off + 2, copy);
            return (uint8_t)copy;
        }

        off += 2 + tag_len;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 *  Feature tensor
 * ----------------------------------------------------------------------- */

static void build_fp_tensor(const uint8_t *oui,
                            bool oui_reliable,
                            uint8_t rate_count,
                            const uint8_t *rates,
                            uint8_t ext_cap_len,
                            const uint8_t *ext_cap,
                            uint8_t subtype,
                            uint8_t tensor[8])
{
    memset(tensor, 0, 8);

    /*
     * If the MAC is randomized/local, do not feed OUI bytes to the model.
     */
    if (oui_reliable && oui != NULL) {
        tensor[0] = oui[0];
        tensor[1] = oui[1];
        tensor[2] = oui[2];
    }

    tensor[3] = rate_count;
    tensor[4] = ext_cap_len;
    tensor[5] = subtype;
    tensor[6] = (rates != NULL && rate_count > 0) ? rates[0] : 0;
    tensor[7] = (ext_cap != NULL && ext_cap_len > 0) ? ext_cap[0] : 0;
}

/* -------------------------------------------------------------------------
 *  Heuristic fallback
 * ----------------------------------------------------------------------- */

static void heuristic_classify(uint8_t subtype,
                               const uint8_t *oui,
                               bool oui_reliable,
                               uint8_t rate_count,
                               ai_fp_class_t *out_cls,
                               char *label,
                               size_t label_sz)
{
    ai_fp_class_t cls = AI_FP_UNKNOWN;
    const char *text = "unknown";

    /*
     * Standard management subtypes:
     *
     *   8 = Beacon
     *   5 = Probe Response
     *   4 = Probe Request
     */
    if (subtype == 8 || subtype == 5) {
        cls = AI_FP_AP;
        text = "ap";

        if (oui_reliable) {
            /* Cisco */
            if (oui[0] == 0x00 && oui[1] == 0x1A && oui[2] == 0x2B) {
                cls = AI_FP_ROUTER;
                text = "router (Cisco)";
            }
        }
    } else if (subtype == 4) {
        cls = AI_FP_UNKNOWN;
        text = "unknown";

        if (oui_reliable) {
            /* Apple */
            if (oui[0] == 0x3C && oui[1] == 0x22 && oui[2] == 0xFB) {
                cls = AI_FP_PHONE;
                text = "phone (Apple)";
            }
            /* Raspberry Pi */
            else if (oui[0] == 0xB8 && oui[1] == 0x27 && oui[2] == 0xEB) {
                cls = AI_FP_IOT;
                text = "iot (Raspberry Pi)";
            }
            /* Espressif */
            else if (oui[0] == 0x24 && oui[1] == 0x0A && oui[2] == 0xC4) {
                cls = AI_FP_IOT;
                text = "iot (Espressif)";
            }
        }

        if (cls == AI_FP_UNKNOWN) {
            if (rate_count >= 8) {
                cls = AI_FP_LAPTOP;
                text = "laptop";
            } else if (rate_count >= 4) {
                cls = AI_FP_PHONE;
                text = "phone";
            } else if (rate_count > 0) {
                cls = AI_FP_IOT;
                text = "iot";
            }
        }
    }

    *out_cls = cls;
    snprintf(label, label_sz, "%s", text);
}

/* -------------------------------------------------------------------------
 *  Lifecycle
 * ----------------------------------------------------------------------- */

esp_err_t ai_fingerprint_init(void)
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

    g_total_count = 0;
    g_model_count = 0;
    g_heuristic_count = 0;
    g_last_infer_us = 0;
    g_infer_every = AI_FINGERPRINT_DEFAULT_INFER_EVERY;

    g_init_done = true;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Fingerprint module initialized");
    return ESP_OK;
}

void ai_fingerprint_deinit(void)
{
    if (g_lock == NULL) {
        return;
    }

    xSemaphoreTake(g_lock, portMAX_DELAY);

    memset(g_model_name, 0, sizeof(g_model_name));

    g_total_count = 0;
    g_model_count = 0;
    g_heuristic_count = 0;
    g_last_infer_us = 0;
    g_infer_every = AI_FINGERPRINT_DEFAULT_INFER_EVERY;

    g_init_done = false;

    xSemaphoreGive(g_lock);

    ESP_LOGI(TAG, "Fingerprint module deinitialized");
}

/* -------------------------------------------------------------------------
 *  Configuration
 * ----------------------------------------------------------------------- */

esp_err_t ai_fingerprint_set_model(const char *model_name)
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

    ESP_LOGI(TAG, "Fingerprint model set: '%s'", g_model_name);
    return ESP_OK;
}

esp_err_t ai_fingerprint_set_infer_every(uint32_t every_n)
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

    ESP_LOGI(TAG, "Fingerprint inference every %" PRIu32 " calls", every_n);
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 *  Classification
 * ----------------------------------------------------------------------- */

esp_err_t ai_fingerprint_classify(const uint8_t *ie_data,
                                  size_t ie_len,
                                  uint8_t subtype,
                                  const uint8_t *oui_mac,
                                  ai_fp_result_t *out)
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (ie_len > 0 && ie_data == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (g_lock == NULL || !g_init_done) {
        return ESP_ERR_INVALID_STATE;
    }

    memset(out, 0, sizeof(*out));

    uint8_t oui[3] = {0};

    if (oui_mac != NULL) {
        memcpy(oui, oui_mac, 3);
    }

    bool oui_reliable = oui_is_reliable(oui_mac);

    uint8_t rates[8] = {0};
    uint8_t ext_cap[8] = {0};

    uint8_t rate_count = extract_rates(ie_data, ie_len, rates, sizeof(rates));
    uint8_t ext_cap_len = extract_ext_cap(ie_data, ie_len, ext_cap, sizeof(ext_cap));

    uint8_t tensor[8];
    build_fp_tensor(
        oui,
        oui_reliable,
        rate_count,
        rates,
        ext_cap_len,
        ext_cap,
        subtype,
        tensor
    );

    char model_local[sizeof(g_model_name)] = {0};
    bool should_infer = false;

    xSemaphoreTake(g_lock, portMAX_DELAY);

    g_total_count++;

    bool model_enabled = (g_model_name[0] != '\0');

    if (model_enabled) {
        if (g_infer_every <= 1 ||
            g_total_count == 1 ||
            (g_total_count % g_infer_every) == 0) {
            snprintf(model_local, sizeof(model_local), "%s", g_model_name);
            should_infer = true;
        }
    }

    xSemaphoreGive(g_lock);

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

        if (rc == ESP_OK && out_len >= 1) {
            uint8_t cls_byte = model_out[0];

            if (cls_byte <= AI_FP_ROUTER) {
                out->cls = (ai_fp_class_t)cls_byte;
            } else {
                out->cls = AI_FP_UNKNOWN;
            }

            snprintf(out->label, sizeof(out->label), "%s", fp_class_name(out->cls));

            memcpy(out->oui, oui, 3);
            memcpy(out->rates, rates, rate_count);
            out->rate_count = rate_count;
            memcpy(out->ext_cap, ext_cap, ext_cap_len);
            out->ext_cap_len = ext_cap_len;

            out->model_loaded = true;
            out->inference_us = (uint32_t)dt;

            xSemaphoreTake(g_lock, portMAX_DELAY);
            g_model_count++;
            g_last_infer_us = (uint32_t)dt;
            xSemaphoreGive(g_lock);

            return ESP_OK;
        }

        ESP_LOGD(TAG, "Model inference failed or invalid; using heuristic");
    }

    ai_fp_class_t heuristic_cls = AI_FP_UNKNOWN;
    char heuristic_label[32] = "unknown";

    heuristic_classify(
        subtype,
        oui,
        oui_reliable,
        rate_count,
        &heuristic_cls,
        heuristic_label,
        sizeof(heuristic_label)
    );

    out->cls = heuristic_cls;
    snprintf(out->label, sizeof(out->label), "%s", heuristic_label);

    memcpy(out->oui, oui, 3);
    memcpy(out->rates, rates, rate_count);
    out->rate_count = rate_count;
    memcpy(out->ext_cap, ext_cap, ext_cap_len);
    out->ext_cap_len = ext_cap_len;

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

esp_err_t ai_fingerprint_json(char *buf, size_t bufsz)
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
    uint32_t last_infer_us;
    uint32_t infer_every;
    char model_name[sizeof(g_model_name)];

    xSemaphoreTake(g_lock, portMAX_DELAY);

    total = g_total_count;
    model = g_model_count;
    heuristic = g_heuristic_count;
    last_infer_us = g_last_infer_us;
    infer_every = g_infer_every;
    snprintf(model_name, sizeof(model_name), "%s", g_model_name);

    xSemaphoreGive(g_lock);

    int w = snprintf(
        buf,
        bufsz,
        "{\"total\":%" PRIu32
        ",\"model\":%" PRIu32
        ",\"heuristic\":%" PRIu32
        ",\"last_infer_us\":%" PRIu32
        ",\"infer_every\":%" PRIu32
        ",\"model_name\":\"%s\"}",
        total,
        model,
        heuristic,
        last_infer_us,
        infer_every,
        model_name
    );

    if (w < 0 || (size_t)w >= bufsz) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}
