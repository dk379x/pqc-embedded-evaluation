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

static const char *TAG = "PQC_BENCH";

/* ===== KONFIG BENCHMARKU ===== */

#define MSG_TEXT            "Hello PQ world!"
#define NUM_KEYGEN_ITERS    1      // na start po 1
#define NUM_SIGN_ITERS      1
#define NUM_VERIFY_ITERS    1

// TESTOWANE ALGORYTMY
static const char *g_sig_algs[] = {
    // NIST ML-DSA (Dilithium)
    // OQS_SIG_alg_ml_dsa_44,
    // OQS_SIG_alg_ml_dsa_65,
    // OQS_SIG_alg_ml_dsa_87,


    OQS_SIG_alg_sphincs_shake_128s_simple,
    OQS_SIG_alg_sphincs_shake_256s_simple,
 
};

static const size_t g_sig_algs_count = sizeof(g_sig_algs) / sizeof(g_sig_algs[0]);

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
    printf("ESP32 PQC Benchmark by dk379x\n");

    g_t0_us = esp_timer_get_time();
    g_alg_name = "-";
    g_phase = PHASE_IDLE;
    g_iter = 0;
    g_iter_max = 0;
    g_all_done = 0;

    // odpal ticker
    xTaskCreate(ticker_task, "ticker", 4096, NULL, tskIDLE_PRIORITY + 1, NULL);

    const uint8_t message[] = MSG_TEXT;
    size_t msg_len = strlen(MSG_TEXT);

    for (size_t a = 0; a < g_sig_algs_count; a++) {

        const char *alg_id = g_sig_algs[a];
        g_alg_name = alg_id;
        ESP_LOGI(TAG, "\n==============================");
        ESP_LOGI(TAG, "Benchmarking signature alg: %s", alg_id);
        ESP_LOGI(TAG, "==============================");

        OQS_SIG *sig = OQS_SIG_new(alg_id);
        if (sig == NULL) {
            ESP_LOGE(TAG, "OQS_SIG_new(%s) failed, skipping", alg_id);
            continue;
        }

        uint8_t *pk  = malloc(sig->length_public_key);
        uint8_t *sk  = malloc(sig->length_secret_key);
        uint8_t *sig_buf = malloc(sig->length_signature);

        if (!pk || !sk || !sig_buf) {
            ESP_LOGE(TAG, "malloc failed for %s, skipping", alg_id);
            free(pk); free(sk); free(sig_buf);
            OQS_SIG_free(sig);
            continue;
        }

        /* --- KEYGEN --- */
        g_phase = PHASE_KEYGEN;
        g_iter = 0;
        g_iter_max = NUM_KEYGEN_ITERS;

        uint64_t t_keygen_total = 0;
        for (uint32_t i = 0; i < NUM_KEYGEN_ITERS; i++) {
            g_iter = i + 1;
            uint64_t t0 = esp_timer_get_time();
            OQS_STATUS st = OQS_SIG_keypair(sig, pk, sk);
            uint64_t t1 = esp_timer_get_time();

            if (st != OQS_SUCCESS) {
                ESP_LOGE(TAG, "keypair failed on iter %u", i);
                break;
            }
            t_keygen_total += (t1 - t0);
        }
        double keygen_ms = (double)t_keygen_total / 1000.0 / NUM_KEYGEN_ITERS;
        ESP_LOGI(TAG, "%s: avg keygen time: %.3f ms", alg_id, keygen_ms);

        /* --- SIGN --- */
        g_phase = PHASE_SIGN;
        g_iter = 0;
        g_iter_max = NUM_SIGN_ITERS;

        uint64_t t_sign_total = 0;
        size_t sig_len = 0;

        for (uint32_t i = 0; i < NUM_SIGN_ITERS; i++) {
            g_iter = i + 1;
            uint64_t t0 = esp_timer_get_time();
            OQS_STATUS st = OQS_SIG_sign(sig,
                                         sig_buf, &sig_len,
                                         message, msg_len,
                                         sk);
            uint64_t t1 = esp_timer_get_time();

            if (st != OQS_SUCCESS) {
                ESP_LOGE(TAG, "sign failed on iter %u", i);
                break;
            }
            t_sign_total += (t1 - t0);
        }
        double sign_ms = (double)t_sign_total / 1000.0 / NUM_SIGN_ITERS;
        ESP_LOGI(TAG, "%s: avg sign time: %.3f ms (sig_len=%zu)", alg_id, sign_ms, sig_len);

        /* --- VERIFY --- */
        g_phase = PHASE_VERIFY;
        g_iter = 0;
        g_iter_max = NUM_VERIFY_ITERS;

        uint64_t t_verify_total = 0;
        for (uint32_t i = 0; i < NUM_VERIFY_ITERS; i++) {
            g_iter = i + 1;
            uint64_t t0 = esp_timer_get_time();
            OQS_STATUS st = OQS_SIG_verify(sig,
                                           message, msg_len,
                                           sig_buf, sig_len,
                                           pk);
            uint64_t t1 = esp_timer_get_time();

            if (st != OQS_SUCCESS) {
                ESP_LOGE(TAG, "verify FAILED on iter %u", i);
                break;
            }
            t_verify_total += (t1 - t0);
        }
        double verify_ms = (double)t_verify_total / 1000.0 / NUM_VERIFY_ITERS;
        ESP_LOGI(TAG, "%s: avg verify time: %.3f ms", alg_id, verify_ms);

        /* --- LOG POD TABELĘ DO ARTYKUŁU (jedna linia CSV) --- */
        printf("\nRESULT_SIG;%s;keygen_ms=%.3f;sign_ms=%.3f;verify_ms=%.3f;"
               "pk_bytes=%zu;sk_bytes=%zu;sig_bytes=%zu\n",
               alg_id,
               keygen_ms, sign_ms, verify_ms,
               (size_t)sig->length_public_key,
               (size_t)sig->length_secret_key,
               (size_t)sig->length_signature);

        /* sprzątanie */
        free(pk);
        free(sk);
        free(sig_buf);
        OQS_SIG_free(sig);

        g_phase = PHASE_IDLE;
        g_iter = 0;
        g_iter_max = 0;
    }

    g_all_done = 1;

    // żeby główne zadanie nie padło
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

 