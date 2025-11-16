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

//static const size_t g_sig_algs_count = sizeof(g_sig_algs) / sizeof(g_sig_algs[0]);

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


/* ================== ML-KEM BENCHMARK (wszystkie warianty) ================== */

typedef struct {
    const char *name;      // nazwa do logów
    const char *oqs_id;    // identyfikator z liboqs, np. OQS_KEM_alg_ml_kem_768
    uint32_t iters_keygen;
    uint32_t iters_enc;
    uint32_t iters_dec;
} KemCase;

static const KemCase mlkem_cases[] = {
    { "ML-KEM-512",  OQS_KEM_alg_ml_kem_512,  5, 10, 10 },
    { "ML-KEM-768",  OQS_KEM_alg_ml_kem_768,  5, 10, 10 },
    { "ML-KEM-1024", OQS_KEM_alg_ml_kem_1024, 3,  5,  5 },
};

static const size_t MLKEM_CASES_COUNT = sizeof(mlkem_cases) / sizeof(mlkem_cases[0]);

static void bench_mlkem_variant(const KemCase *c)
{
    printf("\n\n===== ML-KEM benchmark: %s (%s) =====\n", c->name, c->oqs_id);

    OQS_KEM *kem = OQS_KEM_new(c->oqs_id);
    if (kem == NULL) {
        printf("  [SKIP] OQS_KEM_new(%s) failed – alg not enabled in liboqs.\n",
               c->oqs_id);
        return;
    }

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *ss_enc     = malloc(kem->length_shared_secret);
    uint8_t *ss_dec     = malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext || !ss_enc || !ss_dec) {
        printf("  [ERR] malloc failed\n");
        goto cleanup;
    }

    uint64_t t_keygen_us = 0;
    uint64_t t_enc_us    = 0;
    uint64_t t_dec_us    = 0;

    /* --- KEYGEN --- */
    for (uint32_t i = 0; i < c->iters_keygen; i++) {
        uint64_t t0 = esp_timer_get_time();
        OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
        uint64_t t1 = esp_timer_get_time();
        t_keygen_us += (t1 - t0);

        if (rc != OQS_SUCCESS) {
            printf("  [ERR] keypair failed at iter %" PRIu32 "\n", i);
            goto cleanup;
        }
    }

    /* --- ENC --- */
    for (uint32_t i = 0; i < c->iters_enc; i++) {
        uint64_t t0 = esp_timer_get_time();
        OQS_STATUS rc = OQS_KEM_encaps(kem, ciphertext, ss_enc, public_key);
        uint64_t t1 = esp_timer_get_time();
        t_enc_us += (t1 - t0);

        if (rc != OQS_SUCCESS) {
            printf("  [ERR] encaps failed at iter %" PRIu32 "\n", i);
            goto cleanup;
        }
    }

    /* --- DEC --- */
    for (uint32_t i = 0; i < c->iters_dec; i++) {
        uint64_t t0 = esp_timer_get_time();
        OQS_STATUS rc = OQS_KEM_decaps(kem, ss_dec, ciphertext, secret_key);
        uint64_t t1 = esp_timer_get_time();
        t_dec_us += (t1 - t0);

        if (rc != OQS_SUCCESS) {
            printf("  [ERR] decaps failed at iter %" PRIu32 "\n", i);
            goto cleanup;
        }
    }

    /* correctness na ostatnim sec vec */
    if (memcmp(ss_enc, ss_dec, kem->length_shared_secret) != 0) {
        printf("  [ERR] shared secret mismatch!\n");
        goto cleanup;
    }

    printf("  pk len : %u bytes\n", (unsigned)kem->length_public_key);
    printf("  sk len : %u bytes\n", (unsigned)kem->length_secret_key);
    printf("  ct len : %u bytes\n", (unsigned)kem->length_ciphertext);
    printf("  ss len : %u bytes\n", (unsigned)kem->length_shared_secret);

    double avg_keygen_ms = (double)t_keygen_us / 1000.0 / (double)c->iters_keygen;
    double avg_enc_ms    = (double)t_enc_us    / 1000.0 / (double)c->iters_enc;
    double avg_dec_ms    = (double)t_dec_us    / 1000.0 / (double)c->iters_dec;

    printf("  avg keygen : %8.3f ms (%" PRIu32 " iters)\n",
           avg_keygen_ms, c->iters_keygen);
    printf("  avg encap  : %8.3f ms (%" PRIu32 " iters)\n",
           avg_enc_ms, c->iters_enc);
    printf("  avg decap  : %8.3f ms (%" PRIu32 " iters)\n",
           avg_dec_ms, c->iters_dec);

cleanup:
    if (public_key)  free(public_key);
    if (secret_key)  free(secret_key);
    if (ciphertext)  free(ciphertext);
    if (ss_enc)      free(ss_enc);
    if (ss_dec)      free(ss_dec);
    if (kem)         OQS_KEM_free(kem);
}

static void bench_mlkem_all(void)
{
    printf("\n\n=== Starting ML-KEM benchmark (512 / 768 / 1024) ===\n");
    for (size_t i = 0; i < MLKEM_CASES_COUNT; i++) {
        bench_mlkem_variant(&mlkem_cases[i]);
    }
    printf("=== ML-KEM benchmark DONE ===\n");
}


/* ================== ML-DSA BENCHMARK (wszystkie warianty) ================== */

static const char *ml_dsa_algs[] = {
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87"
};
static const size_t ml_dsa_count = sizeof(ml_dsa_algs) / sizeof(ml_dsa_algs[0]);


static void benchmark_ml_dsa(void) {
    printf("\n=== ML-DSA benchmark START ===\n");

    for (size_t i = 0; i < ml_dsa_count; i++) {
        const char *alg = ml_dsa_algs[i];

        printf("----- ML-DSA variant: %s -----\n", alg);
        fflush(stdout);

        g_alg_name = alg;
        g_phase    = PHASE_IDLE;
        g_iter     = 0;
        g_iter_max = 0;

        OQS_SIG *sig = OQS_SIG_new(alg);
        if (sig == NULL) {
            printf("  [SKIP] OQS_SIG_new(%s) failed – algorithm not enabled\n", alg);
            fflush(stdout);
            continue;
        }

        uint8_t *pk      = malloc(sig->length_public_key);
        uint8_t *sk      = malloc(sig->length_secret_key);
        uint8_t *sig_out = malloc(sig->length_signature);
        const uint8_t msg[] = "Test message for ML-DSA benchmark";
        size_t sig_len = 0;

        if (!pk || !sk || !sig_out) {
            printf("  [FAIL] malloc failed (pk/sk/sig_out)\n");
            fflush(stdout);
            free(pk);
            free(sk);
            free(sig_out);
            OQS_SIG_free(sig);
            continue;
        }

        uint64_t t0, t1;
        OQS_STATUS r1, r2, r3;

        /* ---------- KEYGEN ---------- */
        g_phase    = PHASE_KEYGEN;
        g_iter     = 1;
        g_iter_max = 1;

        t0 = esp_timer_get_time();
        r1 = OQS_SIG_keypair(sig, pk, sk);
        t1 = esp_timer_get_time();

        printf("  keypair:   %s   time = %.3f ms\n",
               r1 == OQS_SUCCESS ? "OK" : "FAIL",
               (t1 - t0) / 1000.0);
        fflush(stdout);

        if (r1 != OQS_SUCCESS) {
            printf("  -> aborting this variant after keypair failure\n");
            fflush(stdout);
            free(pk);
            free(sk);
            free(sig_out);
            OQS_SIG_free(sig);
            g_phase = PHASE_IDLE;
            continue;
        }

        /* ---------- SIGN ---------- */
        g_phase    = PHASE_SIGN;
        g_iter     = 1;
        g_iter_max = 1;

        t0 = esp_timer_get_time();
        r2 = OQS_SIG_sign(sig,
                          sig_out,
                          &sig_len,
                          msg,
                          strlen((const char *)msg),
                          sk);
        t1 = esp_timer_get_time();

        printf("  sign:      %s   time = %.3f ms (sig len = %u)\n",
               r2 == OQS_SUCCESS ? "OK" : "FAIL",
               (t1 - t0) / 1000.0,
               (unsigned)sig_len);
        fflush(stdout);

        if (r2 != OQS_SUCCESS) {
            printf("  -> aborting this variant after sign failure\n");
            fflush(stdout);
            free(pk);
            free(sk);
            free(sig_out);
            OQS_SIG_free(sig);
            g_phase = PHASE_IDLE;
            continue;
        }

        /* ---------- VERIFY ---------- */
        g_phase    = PHASE_VERIFY;
        g_iter     = 1;
        g_iter_max = 1;

        t0 = esp_timer_get_time();
        r3 = OQS_SIG_verify(sig,
                            msg, strlen((const char *)msg),
                            sig_out, sig_len,
                            pk);
        t1 = esp_timer_get_time();

        printf("  verify:    %s   time = %.3f ms\n",
               r3 == OQS_SUCCESS ? "OK" : "FAIL",
               (t1 - t0) / 1000.0);
        fflush(stdout);

        /* ---------- CLEANUP ---------- */
        free(pk);
        free(sk);
        free(sig_out);
        OQS_SIG_free(sig);

        g_phase    = PHASE_IDLE;
        g_iter     = 0;
        g_iter_max = 0;
    }

    g_alg_name = "-";
    g_phase    = PHASE_IDLE;
    g_iter     = 0;
    g_iter_max = 0;

    printf("=== ML-DSA benchmark END ===\n\n");
    fflush(stdout);
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


     // >>> TU DODAJEMY BENCHMARK ML-KEM <<<
    //bench_mlkem_all();

    //benchmark_ml_dsa();

    bench_slh_dsa_all();       // NOWY: wszystkie warianty SLH-DSA / SPHINCS+

    /*
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

        // --- KEYGEN --- 
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

        // --- SIGN --- 
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

        // --- VERIFY --- 
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

        // --- LOG POD TABELĘ DO ARTYKUŁU (jedna linia CSV) --- 
        printf("\nRESULT_SIG;%s;keygen_ms=%.3f;sign_ms=%.3f;verify_ms=%.3f;"
               "pk_bytes=%zu;sk_bytes=%zu;sig_bytes=%zu\n",
               alg_id,
               keygen_ms, sign_ms, verify_ms,
               (size_t)sig->length_public_key,
               (size_t)sig->length_secret_key,
               (size_t)sig->length_signature);

        // sprzątanie 
        free(pk);
        free(sk);
        free(sig_buf);
        OQS_SIG_free(sig);

        g_phase = PHASE_IDLE;
        g_iter = 0;
        g_iter_max = 0;
    }

    */

    g_all_done = 1;



    // żeby główne zadanie nie padło
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

 