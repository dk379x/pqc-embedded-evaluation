/*
 * SPDX-FileCopyrightText: 2010-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
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

#include "bench/mlkem/bench_mlkem.h"
#include "bench/mldsa/bench_mldsa.h"
#include "bench/slhdsa/bench_slhdsa.h"

static const char *TAG = "PQC_BENCH";

/* ===== KONFIG BENCHMARKU ===== */

#define MSG_TEXT            "Hello PQ world!"



/* ===== GLOBALNY STAN DLA TICKERA ===== */

typedef enum {
    PHASE_IDLE = 0,
    PHASE_KEYGEN,
    PHASE_SIGN,
    PHASE_VERIFY,
} bench_phase_t;

static volatile uint64_t     g_t0_us       = 0;
static volatile const char  *g_alg_name    = NULL;
static volatile bench_phase_t g_phase      = PHASE_IDLE;
static volatile uint32_t     g_iter        = 0;
static volatile uint32_t     g_iter_max    = 0;
static volatile int          g_all_done    = 0;

static const char *phase_to_str(bench_phase_t p) {
    switch (p) {
        case PHASE_KEYGEN: return "KEYGEN";
        case PHASE_SIGN:   return "SIGN  ";
        case PHASE_VERIFY: return "VERIFY";
        default:           return "IDLE  ";
    }
}

/* ===== TICKER TASK ===== */

static void ticker_task(void *arg)
{
    while (1) {
        uint64_t now = esp_timer_get_time();
        double elapsed = (now - g_t0_us) / 1e6;

        printf("\r[+%8.3fs] alg=%-28s phase=%s it=%3lu/%-3lu (heap=%u)",
       elapsed,
       g_alg_name ? g_alg_name : "-",
       phase_to_str(g_phase),
       (unsigned long)g_iter,
       (unsigned long)g_iter_max,
       (unsigned)heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
        fflush(stdout);

        if (g_all_done) {
            printf("\n[+] Benchmark finished.\n");
            vTaskDelete(NULL);
        }

        vTaskDelay(pdMS_TO_TICKS(200));
    }
}

/* ===== POMOCNICZA FUNKCJA POMIARU CZASU ===== */

static uint64_t measure_us(uint64_t (*func)(void *), void *ctx)
{
    // generic version
    // bardziej wyrafinowane pomiary; na razie zrobimy proste w app_main.
    (void)func;
    (void)ctx;
    return 0;
}



/* ===== GŁÓWNY BENCH ===== */

void app_main(void)
{
    //printf("ESP32 PQC Benchmark by dk379x\n");

    /*g_t0_us = esp_timer_get_time();
    g_alg_name = "-";
    g_phase = PHASE_IDLE;
    g_iter = 0;
    g_iter_max = 0;
    g_all_done = 0;

    // odpal ticker
    xTaskCreate(ticker_task, "ticker", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);

    const uint8_t message[] = MSG_TEXT;
    size_t msg_len = strlen(MSG_TEXT);

    */
     // >>> TU DODAJEMY BENCHMARK ML-KEM <<<
    //bench_mlkem_all();

    //benchmark_ml_dsa();

    //bench_slh_dsa_all();       // NOWY: wszystkie warianty SLH-DSA / SPHINCS+


    //g_all_done = 1;


    printf("ESP32 PQC Benchmark by dk379x\n");
    printf("pqc-embedded-evaluation | ESP32-C6 | liboqs\n");

    const int warmup = CONFIG_PQC_WARMUP_ITERS;
    const int runs   = CONFIG_PQC_RUN_ITERS;

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

    printf("\nAll enabled benchmarks finished.\n");

    while (1) vTaskDelay(pdMS_TO_TICKS(1000));

}

 