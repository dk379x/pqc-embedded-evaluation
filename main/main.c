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
 
 #include <stdlib.h>
 #include <string.h>

#include <oqs.h>

// BENCH
#include "bench/mlkem/bench_mlkem.h"
#include "bench/mldsa/bench_mldsa.h"
#include "bench/slhdsa/bench_slhdsa.h"

// MEASURE
#include "measure/ppk2_trigger.h"

void app_main(void)
{

    printf("PQC EMBEDDED EVALUATION FRAMEWORK by dk379x\n");
    printf("pqc-embedded-evaluation | ESP32-C6 | liboqs\n");

    const int warmup = CONFIG_PQC_WARMUP_ITERS;
    const int runs   = CONFIG_PQC_RUN_ITERS;

    ppk2_trigger_init();
    printf("\n[MEAS] PPK2 trigger initialized\n");

#if CONFIG_PQC_RUN_MLKEM
    printf("\n[RUN] ML-KEM\n");
    bench_mlkem_all_full(warmup, runs);
#endif

#if CONFIG_PQC_RUN_MLDSA
    printf("\n[RUN] ML-DSA\n");
    bench_mldsa_all_full(warmup, runs);
#endif

#if CONFIG_PQC_RUN_SLHDSA
    printf("\n[RUN] SLH-DSA\n");
    bench_slhdsa_all_full(0, 1);
#endif

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

    /*
    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(2500));
    }
    */

    printf("\nAll enabled benchmarks finished.\n");

    while (1) vTaskDelay(pdMS_TO_TICKS(1000));

}

 