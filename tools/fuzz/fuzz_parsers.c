/* REAPER AFL++ fuzzing harness for packet parsers.
 * Compile with:
 *   afl-clang-fast -I main -I . fuzz_parsers.c -o fuzz_parsers
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Stub out ESP-IDF types so harness compiles on host */
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_ERR_NOT_FOUND -1
#define ESP_ERR_INVALID_ARG -2
#include "wifi_sniffer.h"
#include "ai_classifier.h"
#include "ai_anomaly.h"
#include "ai_fingerprint.h"
#include "ai_rogue_detector.h"
#include "pcap_ring.h"
#include "export.h"

/* Minimal extern stubs for symbols referenced by headers.
 * Real ESP-IDF linkage is not needed; we only exercise parser branches. */
extern bool mac_is_valid_unicast(const uint8_t *mac);
extern void channel_hop_record_locked(uint8_t channel, uint8_t type,
                                      uint8_t subtype, int8_t rssi, size_t len);
extern void ai_channel_predictor_record(void);
extern void ai_rogue_detector_scan(void);
extern void ai_fingerprint_classify(const uint8_t *data, size_t len,
                                    uint8_t subtype, const uint8_t *bssid,
                                    void *out);
extern void ai_anomaly_feed(int8_t rssi, size_t len, uint64_t ts);
extern void ai_classifier_predict(const uint8_t *data, size_t len, void *out);

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    unsigned char *data = NULL;
    size_t len = 0;

    {
        size_t cap = 4096;
        data = (unsigned char *)malloc(cap);
        if (!data) return 1;
        size_t n = fread(data, 1, cap, stdin);
        len = n;
    }

    if (len < 24) {
        free(data);
        return 0;
    }

    wifi_sniffer_get_ap_count();
    {
        uint8_t fake[6] = {0,0,0,0,0,0};
        int8_t rssi = 0;
        wifi_sniffer_get_rssi(fake, &rssi);
    }
    {
        ap_info_t ap;
        wifi_sniffer_get_ap(0, &ap);
    }

    uint8_t type = data[0] >> 2;
    uint8_t subtype = data[0] & 0xF;
    int8_t rssi = (int8_t)(data[1] - 128);
    uint8_t channel = data[2];
    ai_classifier_predict(data, (size_t)len > 2304 ? 2304 : len, NULL);
    ai_anomaly_feed(rssi, (size_t)len > 2304 ? 2304 : len, 0);
    ai_rogue_detector_scan();
    channel_hop_record_locked(channel, type, subtype, rssi,
                              (size_t)len > 2304 ? 2304 : len);
    ai_channel_predictor_record();
    ai_fingerprint_classify(data + 24, (size_t)len > 24 ? len - 24 : 0,
                            subtype, data + 10, NULL);

    free(data);
    return 0;
}
