#ifndef STRUCTURED_LOG_H
#define STRUCTURED_LOG_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Log levels */
typedef enum {
    LOG_LEVEL_VERBOSE = 0,
    LOG_LEVEL_DEBUG   = 1,
    LOG_LEVEL_INFO    = 2,
    LOG_LEVEL_WARN    = 3,
    LOG_LEVEL_ERROR   = 4,
} log_level_t;

/* Initialize the structured logging subsystem. */
esp_err_t structured_log_init(void);

/* Write one log entry. */
void structured_log_write(const char *tag, log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* Filter by tag substring and minimum level. */
void structured_log_set_filter(const char *tag_substr, log_level_t min_level);

/* Export buffered entries as a JSON array to a file path. */
esp_err_t structured_log_export_json(const char *path);

/* Clear the ring buffer. */
void structured_log_clear(void);

/* Current usage stats. */
size_t structured_log_count(void);
size_t structured_log_capacity(void);

#ifdef __cplusplus
}
#endif

#endif // STRUCTURED_LOG_H
