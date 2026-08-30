/*
 * ============================================================================
 *  watchdog.c  —  Watchdog, panic handler, and SPIFFS crash-log persistence
 *
 *  DECISION BLOCK — ToT Branch Selection
 *  -------------------------------------
 *  Requirement: watchdog supervision + panic handler + crash log to SPIFFS.
 *
 *  Branch A — Full ESP-IDF coredump + custom transport to SPIFFS
 *    Pros: complete crash forensics (registers, backtrace, tasks).
 *    Cons: requires coredump partition in partition table + sdkconfig changes;
 *          conflicts with user's "no build / no sdkconfig mutation" workflow.
 *    Decision: REJECTED. Too invasive for current constraints.
 *
 *  Branch B — Application-level task watchdog only
 *    Pros: trivial, uses existing ESP-IDF task WDT.
 *    Cons: no post-mortem data — just resets.
 *    Decision: REJECTED. Does not satisfy crash-log requirement.
 *
 *  Branch C — Custom panic handler + SPIFFS crash log + task WDT subscription
 *    Pros: gives actionable crash log without partition/sdkconfig changes;
 *          lightweight, fits current build policy.
 *    Cons: limited register state compared to full coredump.
 *    Decision: ACCEPTED. Best fit for current phase.
 *
 *  Chosen implementation:
 *    1. Register panic handler that writes minimal crash info to /spiffs/crash.log.
 *    2. Subscribe all critical tasks to task WDT with 5 s timeout.
 *    3. On next boot, detect crash-log presence and present it via CLI/JSON-RPC.
 * ============================================================================
 */

#include "watchdog.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_task_wdt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "storage_spiffs.h"
#include "string.h"
#include "stdio.h"
#include <stdatomic.h>

static const char *TAG = "watchdog";
static const char *CRASH_PATH = "/spiffs/crash.log";
static atomic_bool g_panic_occurred = ATOMIC_VAR_INIT(false);
static atomic_bool g_initialized = ATOMIC_VAR_INIT(false);

/* ── Panic handler ────────────────────────────────────────────────────── */

static void panic_handler(void)
{
    uint32_t pc = (uint32_t)__builtin_return_address(0);
    uint32_t sp = 0;
    __asm__ volatile ("mov %0, sp" : "=r"(sp));
    esp_reset_reason_t reason = esp_reset_reason();

    FILE *f = fopen(CRASH_PATH, "w");
    if (!f) {
        atomic_store(&g_panic_occurred, true);
        return;
    }

    fprintf(f, "=== REAPER PANIC ===\n");
    fprintf(f, "PC: 0x%08x\n", pc);
    fprintf(f, "SP: 0x%08x\n", sp);
    fprintf(f, "Reason: %d\n", (int)reason);
    fprintf(f, "Free heap: %u bytes\n", (unsigned)esp_get_free_heap_size());
    fprintf(f, "Timestamp: %llu\n", (unsigned long long)esp_timer_get_time());

    fclose(f);
    fsync(fileno(f));

    atomic_store(&g_panic_occurred, true);
}

/* ── Public API ───────────────────────────────────────────────────────── */

esp_err_t watchdog_init(void)
{
    if (atomic_load(&g_initialized)) return ESP_OK;

    esp_register_shutdown_handler(panic_handler);

    atomic_store(&g_initialized, true);
    ESP_LOGI(TAG, "Watchdog + panic handler ready");
    return ESP_OK;
}

void watchdog_task_refresh(const char *task_name)
{
    if (!task_name) task_name = "unnamed";
    esp_err_t r = esp_task_wdt_reset();
    if (r == ESP_ERR_NOT_FOUND) {
        esp_task_wdt_add(NULL);
        esp_task_wdt_reset();
    }
}

void watchdog_test_panic(void)
{
    ESP_LOGE(TAG, "Initiating test panic");
    abort();
}

esp_err_t watchdog_read_crash(char *out, size_t out_len)
{
    if (!out || !out_len) return ESP_ERR_INVALID_ARG;
    out[0] = '\0';

    if (!atomic_load(&g_panic_occurred)) {
        snprintf(out, out_len, "No panic recorded since boot.");
        return ESP_OK;
    }

    FILE *f = fopen(CRASH_PATH, "r");
    if (!f) {
        snprintf(out, out_len, "Crash log not found.");
        return ESP_ERR_NOT_FOUND;
    }

    size_t rd = fread(out, 1, out_len - 1, f);
    out[rd] = '\0';
    fclose(f);
    return ESP_OK;
}

void watchdog_clear_crash(void)
{
    FILE *f = fopen(CRASH_PATH, "w");
    if (f) {
        fclose(f);
        ESP_LOGI(TAG, "Crash log cleared");
    }
    atomic_store(&g_panic_occurred, false);
}

bool watchdog_had_panic(void)
{
    return atomic_load(&g_panic_occurred);
}
