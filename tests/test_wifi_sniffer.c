#include "unity.h"
#include "wifi_sniffer.h"
#include "string.h"

void setUp(void) { }
void tearDown(void) { }

void test_wifi_sniffer_get_ap_count_initial(void)
{
    uint16_t count = wifi_sniffer_get_ap_count();
    TEST_ASSERT_EQUAL_UINT16(0, count);
}

void test_wifi_sniffer_get_rssi_invalid(void)
{
    uint8_t fake[6] = {0,0,0,0,0,0};
    int8_t rssi = 0;
    bool ok = wifi_sniffer_get_rssi(fake, &rssi);
    TEST_ASSERT_FALSE(ok);
}

void test_wifi_sniffer_get_ap_invalid_index(void)
{
    ap_info_t ap;
    esp_err_t rc = wifi_sniffer_get_ap(0, &ap);
    TEST_ASSERT_TRUE(rc == ESP_ERR_NOT_FOUND || rc == ESP_ERR_INVALID_ARG);
}
