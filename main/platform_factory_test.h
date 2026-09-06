#ifndef PLATFORM_FACTORY_TEST_H
#define PLATFORM_FACTORY_TEST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FACTORY_TEST_IDLE = 0,
    FACTORY_TEST_RUNNING,
    FACTORY_TEST_PASS,
    FACTORY_TEST_FAIL
} factory_test_state_t;

esp_err_t factory_test_init(void);
esp_err_t factory_test_run(void);
factory_test_state_t factory_test_get_state(void);
size_t factory_test_results(char *out, size_t max_len);

#ifdef __cplusplus
}
#endif
#endif
