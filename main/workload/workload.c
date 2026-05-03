#include "workload.h"

#include <stdio.h>
#include <string.h>
#include <math.h>

#include "esp_log.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "../sensor/internal_temp.h"
#include "../wireless/bt_le.h"

#define TEMP_WINDOW_SIZE 16

static const char *TAG = "WORKLOAD";

static float temp_window[TEMP_WINDOW_SIZE];
static int temp_index = 0;
static int temp_count = 0;

static float temp_min = 1000.0f;
static float temp_max = -1000.0f;
static float last_avg = 0.0f;

static float compute_average(void)
{
    float sum = 0.0f;

    for (int i = 0; i < temp_count; i++) {
        sum += temp_window[i];
    }

    return temp_count > 0 ? sum / temp_count : 0.0f;
}

static const char *compute_trend(float avg)
{
    float diff = avg - last_avg;

    if (diff > 0.05f) {
        return "UP";
    } else if (diff < -0.05f) {
        return "DOWN";
    }

    return "STABLE";
}

static void synthetic_processing_load(float input)
{
    volatile float acc = input;

    for (int i = 0; i < 20000; i++) {
        acc += (float)(i % 13) * 0.0001f;
        acc *= 0.99999f;
    }
}

static void workload_task(void *arg)
{
    (void)arg;

    ESP_ERROR_CHECK(internal_temp_init());

    while (1) {
        float temp = 0.0f;

        if (internal_temp_read_celsius(&temp) == ESP_OK) {
            temp_window[temp_index] = temp;
            temp_index = (temp_index + 1) % TEMP_WINDOW_SIZE;

            if (temp_count < TEMP_WINDOW_SIZE) {
                temp_count++;
            }

            if (temp < temp_min) {
                temp_min = temp;
            }

            if (temp > temp_max) {
                temp_max = temp;
            }

            synthetic_processing_load(temp);

            float avg = compute_average();
            const char *trend = compute_trend(avg);
            last_avg = avg;

            size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);

            char payload[160];
            snprintf(payload, sizeof(payload),
                     "TEMP=%.2f;AVG=%.2f;MIN=%.2f;MAX=%.2f;TREND=%s;HEAP=%u",
                     temp, avg, temp_min, temp_max, trend, (unsigned)free_heap);

            bt_le_update_payload(payload);

            // Uncomment for sending payload to terminal - DEBUG
            //ESP_LOGI(TAG, "%s", payload);
        } else {
            ESP_LOGW(TAG, "Temperature read failed");
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void workload_start(void)
{
    xTaskCreate(
        workload_task,
        "workload_task",
        4096,
        NULL,
        2,
        NULL
    );
}