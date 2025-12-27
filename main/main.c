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


/* ================== SLH-DSA / SPHINCS+ BENCHMARK (wszystkie warianty) ================== */

typedef struct {
    const char *nice_name;   // nazwa do logów / CSV
    const char *oqs_id;      // identyfikator z liboqs (OQS_SIG_alg_...)
} SlhDsaCase;

static const SlhDsaCase slh_dsa_cases[] = {
    /* SHA2 profile (SLH-DSA-SHA2) */
    { "SLH-DSA-SHA2-128s",  OQS_SIG_alg_sphincs_sha2_128s_simple  },
    { "SLH-DSA-SHA2-128f",  OQS_SIG_alg_sphincs_sha2_128f_simple  },
    { "SLH-DSA-SHA2-192s",  OQS_SIG_alg_sphincs_sha2_192s_simple  },
    { "SLH-DSA-SHA2-192f",  OQS_SIG_alg_sphincs_sha2_192f_simple  },
    { "SLH-DSA-SHA2-256s",  OQS_SIG_alg_sphincs_sha2_256s_simple  },
    { "SLH-DSA-SHA2-256f",  OQS_SIG_alg_sphincs_sha2_256f_simple  },

    /* SHAKE profile (SLH-DSA-SHAKE) */
    { "SLH-DSA-SHAKE-128s", OQS_SIG_alg_sphincs_shake_128s_simple },
    { "SLH-DSA-SHAKE-128f", OQS_SIG_alg_sphincs_shake_128f_simple },
    { "SLH-DSA-SHAKE-192s", OQS_SIG_alg_sphincs_shake_192s_simple },
    { "SLH-DSA-SHAKE-192f", OQS_SIG_alg_sphincs_shake_192f_simple },
    { "SLH-DSA-SHAKE-256s", OQS_SIG_alg_sphincs_shake_256s_simple },
    { "SLH-DSA-SHAKE-256f", OQS_SIG_alg_sphincs_shake_256f_simple },
};

static const size_t SLH_DSA_CASES_COUNT =
    sizeof(slh_dsa_cases) / sizeof(slh_dsa_cases[0]);

static void bench_slh_dsa_all(void)
{
    printf("\n\n=== SLH-DSA / SPHINCS+ benchmark (wszystkie warianty NIST) ===\n");

    const uint8_t message[] = MSG_TEXT;
    size_t msg_len = strlen(MSG_TEXT);

    for (size_t i = 0; i < SLH_DSA_CASES_COUNT; i++) {
        const SlhDsaCase *c = &slh_dsa_cases[i];

        printf("----- %s (%s) -----\n", c->nice_name, c->oqs_id);
        fflush(stdout);

        g_alg_name = c->nice_name;
        g_phase    = PHASE_IDLE;
        g_iter     = 0;
        g_iter_max = 0;

        OQS_SIG *sig = OQS_SIG_new(c->oqs_id);
        if (sig == NULL) {
            printf("  [SKIP] OQS_SIG_new(%s) failed – alg not enabled in liboqs.\n",
                   c->oqs_id);
            fflush(stdout);
            continue;
        }

        uint8_t *pk      = malloc(sig->length_public_key);
        uint8_t *sk      = malloc(sig->length_secret_key);
        uint8_t *sig_buf = malloc(sig->length_signature);

        if (!pk || !sk || !sig_buf) {
            printf("  [ERR] malloc failed (pk/sk/sig_buf)\n");
            fflush(stdout);
            if (pk) free(pk);
            if (sk) free(sk);
            if (sig_buf) free(sig_buf);
            OQS_SIG_free(sig);
            g_phase = PHASE_IDLE;
            g_iter = g_iter_max = 0;
            continue;
        }

        uint64_t t_keygen = 0, t_sign = 0, t_verify = 0;
        uint64_t t0, t1;
        size_t sig_len = 0;
        OQS_STATUS st;

        /* ---------- KEYGEN ---------- */
        g_phase    = PHASE_KEYGEN;
        g_iter     = 1;
        g_iter_max = 1;

        t0 = esp_timer_get_time();
        st = OQS_SIG_keypair(sig, pk, sk);
        t1 = esp_timer_get_time();
        t_keygen = t1 - t0;

        printf("  keypair:   %s   time = %.3f ms\n",
               st == OQS_SUCCESS ? "OK" : "FAIL",
               t_keygen / 1000.0);
        fflush(stdout);

        if (st != OQS_SUCCESS) {
            goto slh_cleanup_variant;
        }

        /* ---------- SIGN ---------- */
        g_phase    = PHASE_SIGN;
        g_iter     = 1;
        g_iter_max = 1;

        t0 = esp_timer_get_time();
        st = OQS_SIG_sign(sig,
                          sig_buf, &sig_len,
                          message, msg_len,
                          sk);
        t1 = esp_timer_get_time();
        t_sign = t1 - t0;

        printf("  sign:      %s   time = %.3f ms (sig_len=%zu)\n",
               st == OQS_SUCCESS ? "OK" : "FAIL",
               t_sign / 1000.0,
               sig_len);
        fflush(stdout);

        if (st != OQS_SUCCESS) {
            goto slh_cleanup_variant;
        }

        /* ---------- VERIFY ---------- */
        g_phase    = PHASE_VERIFY;
        g_iter     = 1;
        g_iter_max = 1;

        t0 = esp_timer_get_time();
        st = OQS_SIG_verify(sig,
                            message, msg_len,
                            sig_buf, sig_len,
                            pk);
        t1 = esp_timer_get_time();
        t_verify = t1 - t0;

        printf("  verify:    %s   time = %.3f ms\n",
               st == OQS_SUCCESS ? "OK" : "FAIL",
               t_verify / 1000.0);
        fflush(stdout);

        /* linia pod tabelę do artykułu */
        printf("RESULT_SLHDSA;%s;keygen_ms=%.3f;sign_ms=%.3f;verify_ms=%.3f;"
               "pk_bytes=%zu;sk_bytes=%zu;sig_bytes=%zu\n",
               c->nice_name,
               t_keygen / 1000.0,
               t_sign   / 1000.0,
               t_verify / 1000.0,
               (size_t)sig->length_public_key,
               (size_t)sig->length_secret_key,
               (size_t)sig->length_signature);
        fflush(stdout);

slh_cleanup_variant:
        free(pk);
        free(sk);
        free(sig_buf);
        OQS_SIG_free(sig);

        g_phase    = PHASE_IDLE;
        g_iter     = 0;
        g_iter_max = 0;
    }

    g_alg_name = "-";
    g_phase    = PHASE_IDLE;
    g_iter     = 0;
    g_iter_max = 0;

    printf("=== SLH-DSA benchmark END ===\n");
    fflush(stdout);
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
    // bench_slhdsa_all();
#endif

    printf("\nAll enabled benchmarks finished.\n");

    while (1) vTaskDelay(pdMS_TO_TICKS(1000));

}

 