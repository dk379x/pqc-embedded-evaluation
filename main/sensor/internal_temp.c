#include "internal_temp.h"

#include "driver/temperature_sensor.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "INTERNAL_TEMP";

static temperature_sensor_handle_t s_temp_handle = NULL;
static bool s_temp_initialized = false;

esp_err_t internal_temp_init(void)
{
    if (s_temp_initialized) {
        return ESP_OK;
    }

    temperature_sensor_config_t config = {
        .range_min = 10,
        .range_max = 80,
    };

    esp_err_t err = temperature_sensor_install(&config, &s_temp_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "temperature_sensor_install failed: %s", esp_err_to_name(err));
        return err;
    }

    err = temperature_sensor_enable(s_temp_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "temperature_sensor_enable failed: %s", esp_err_to_name(err));
        return err;
    }

    s_temp_initialized = true;
    ESP_LOGI(TAG, "Internal temperature sensor initialized");

    return ESP_OK;
}

esp_err_t internal_temp_read_celsius(float *temperature_c)
{
    if (temperature_c == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!s_temp_initialized) {
        esp_err_t err = internal_temp_init();
        if (err != ESP_OK) {
            return err;
        }
    }

    return temperature_sensor_get_celsius(s_temp_handle, temperature_c);
}

static void internal_temp_log_task(void *arg)
{
    (void)arg;

    esp_err_t err = internal_temp_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Temperature task stopped: init failed");
        vTaskDelete(NULL);
        return;
    }

    while (1) {
        float temp_c = 0.0f;
        err = internal_temp_read_celsius(&temp_c);

        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Internal temperature: %.2f C", temp_c);
        } else {
            ESP_LOGE(TAG, "Temperature read failed: %s", esp_err_to_name(err));
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void internal_temp_start_log_task(void)
{
    xTaskCreate(
        internal_temp_log_task,
        "internal_temp_log",
        4096,
        NULL,
        2,
        NULL
    );
}