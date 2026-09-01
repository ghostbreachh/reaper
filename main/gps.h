#ifndef GPS_H
#define GPS_H

#include <stdint.h>
#include <stdbool.h>
#include "common_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize GPS subsystem (UART, NMEA parser). */
esp_err_t gps_init(void);

/* Start GPS polling task. */
esp_err_t gps_start(void);

/* Stop GPS polling. */
esp_err_t gps_stop(void);

/* Get latest GPS fix (thread-safe snapshot). */
bool gps_get_fix(gps_fix_t *out);

/* Get monotonic timestamp in microseconds from GPS sync. */
uint64_t gps_get_timestamp_us(void);

/* Convert GPS lat/lon to a compact string. */
int gps_format_coords(char *buf, size_t bufsz, const gps_fix_t *fix);

/* Check whether GPS has a valid fix. */
bool gps_is_valid(void);

#ifdef __cplusplus
}
#endif
#endif /* GPS_H */
