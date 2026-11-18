/*
 * PQC EMBEDDED EVALUATION FRAMEWORK
 *
 * by Daniel Karcz [dk379x]
 */

 #include <stdio.h>
 #include <inttypes.h>
 #include "sdkconfig.h"
 #include "freertos/FreeRTOS.h"
 #include "freertos/task.h"
 #include "esp_log.h"
 #include "esp_timer.h"
 #include "esp_task_wdt.h"
 #include "esp_heap_caps.h"
 #include "nvs_flash.h"
 
 #include <stdlib.h>
 #include <string.h>

#include <oqs.h>

// BENCH
#include "bench/mlkem/bench_mlkem.h"
#include "bench/mldsa/bench_mldsa.h"
#include "bench/slhdsa/bench_slhdsa.h"

// MEASURE
#include "measure/ppk2_trigger.h"

// SENSOR
#include "sensor/internal_temp.h"

// WIRELESS
#include "wireless/bt_le.h"
#include "wireless/wifi.h"

// WORKLOAD
#include "workload/workload.h"

// HARDWARE CRYPTO
#include "hardware/sha2/oqs_sha2_esp.h"

// COMBINED
#include "bench/combined/mlkem_mldsa.h"

// Wybór benchmarku uruchamianego w osobnym tasku FreeRTOS
typedef enum {
    BENCHMARK_COMBINED,
    BENCHMARK_MLKEM,
    BENCHMARK_MLDSA,
    BENCHMARK_SLHDSA,
} benchmark_kind_t;

// Przekazanie wybranego benchmarku i handlera taska
typedef struct {
    TaskHandle_t caller;
    benchmark_kind_t kind;
} benchmark_task_args_t;

// Wykonanie benchmarku z ustawioną liczbą iteracji
static void benchmark_task(void *arg)
{
    benchmark_task_args_t *args = (benchmark_task_args_t *)arg;
    const int warmup = CONFIG_PQC_WARMUP_ITERS;
    const int runs = CONFIG_PQC_RUN_ITERS;

    switch (args->kind) {
        case BENCHMARK_COMBINED:
            printf("\n[RUN] COMBINED ML-KEM + ML-DSA\n");
            bench_mlkem_mldsa_all_full(warmup, runs);
            break;
        case BENCHMARK_MLKEM:
            printf("\n[RUN] ML-KEM\n");
            bench_mlkem_all_full(warmup, runs);
            break;
        case BENCHMARK_MLDSA:
            printf("\n[RUN] ML-DSA\n");
            bench_mldsa_all_full(warmup, runs);
            break;
        case BENCHMARK_SLHDSA:
            printf("\n[RUN] SLH-DSA\n");
            bench_slhdsa_all_full(warmup, runs);
            break;
    }

    xTaskNotifyGive(args->caller);
    vTaskDelete(NULL);
}

// Utworzenie taska z własnym stosem
static void run_benchmark_task(benchmark_kind_t kind, uint32_t stack_size)
{
    benchmark_task_args_t args = {
        .caller = xTaskGetCurrentTaskHandle(),
        .kind = kind,
    };

    BaseType_t created = xTaskCreate(
        benchmark_task,
        "pqc_benchmark",
        stack_size,
        &args,
        5,
        NULL
    );

    if (created != pdPASS) {
        printf("[ERR] Failed to create benchmark task (stack=%u)\n",
               (unsigned)stack_size);
        return;
    }

    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
}

void app_main(void)
{

    printf("PQC EMBEDDED EVALUATION FRAMEWORK by dk379x\n");
    printf("pqc-embedded-evaluation | ESP32-C6 | liboqs | PPK2\n");

    //ppk2_trigger_init();
    //printf("\n[MEAS] PPK2 trigger initialized\n");


    // BLUETOOTH LE

    //ESP_ERROR_CHECK(bt_le_init());

    //bt_le_update_payload("TEMP=25.4;ALG=IDLE;TIME_MS=0;HEAP=331000");

    // Start WI-FI 

    esp_err_t ret = nvs_flash_init();

    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||

        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {

        ESP_ERROR_CHECK(nvs_flash_erase());

        ret = nvs_flash_init();

    }

    ESP_ERROR_CHECK(ret);

    // then init netif/event loop/wifi

    // Moduł radiowy Wi-Fi dostarcza entropię sprzętowemu RNG
    wifi_start_sta();
   
    //esp_log_level_set("NimBLE", ESP_LOG_ERROR);

    //ESP_ERROR_CHECK(bt_le_init());
    workload_start();

    //printf("Please connect to BLE\n");

    //vTaskDelay(pdMS_TO_TICKS(10000));
   

#if CONFIG_ENABLE_INTERNAL_TEMP_SENSOR
    //internal_temp_start_log_task();
#endif

//#if CONFIG_PQC_RUN_MLKEM
    //printf("\n[RUN] ML-KEM\n");
    //bench_mlkem_all_full(warmup, runs);
//#endif

//#if CONFIG_PQC_RUN_MLDSA
    //printf("\n[RUN] ML-DSA\n");
    //bench_mldsa_all_full(warmup, runs);
//#endif

//#if CONFIG_PQC_RUN_SLHDSA

    // HARDWARE SHA
    //oqs_sha2_esp_install();
    

    /*
    printf("\n[RUN] SLH-DSA\n");
    bench_slhdsa_all_full(1, 3);
    */
//#endif

#if CONFIG_PQC_RUN_MLKEM && CONFIG_PQC_RUN_MLDSA
    run_benchmark_task(BENCHMARK_COMBINED,
                       CONFIG_PQC_BENCHMARK_TASK_STACK_SIZE);
#endif

#if CONFIG_PQC_RUN_MLKEM
    run_benchmark_task(BENCHMARK_MLKEM, 98304);
#endif

#if CONFIG_PQC_RUN_MLDSA
    run_benchmark_task(BENCHMARK_MLDSA, 98304);
#endif

#if CONFIG_PQC_RUN_SLHDSA
    run_benchmark_task(BENCHMARK_SLHDSA, 32768);
#endif


/*
#if CONFIG_POWER_MODE_IDLE

    printf("[MEAS] Idle baseline measurement started\n");
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
#endif

#if CONFIG_POWER_MODE_EMPTY_CONTROL

    vTaskDelay(pdMS_TO_TICKS(10000));

    printf("\n[MEAS] Empty control window measurement started\n");

    ppk2_trigger_start();
    for (volatile int i = 0; i < 1000; i++) {}
    ppk2_trigger_stop();

    printf("\n[MEAS] Empty control window measurement stopped\n");
#endif
*/
    /*
    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(2500));
    }
    */

    printf("\nAll enabled benchmarks finished.\n");

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        //bt_le_update_payload("TEMP=25.4;ALG=IDLE;TIME_MS=0;HEAP=331000");
    }
}

 