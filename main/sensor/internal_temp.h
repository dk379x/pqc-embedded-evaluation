#ifndef INTERNAL_TEMP_H
#define INTERNAL_TEMP_H

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t internal_temp_init(void);
esp_err_t internal_temp_read_celsius(float *temperature_c);
void internal_temp_start_log_task(void);

#ifdef __cplusplus
}
#endif

#endif // INTERNAL_TEMP_H