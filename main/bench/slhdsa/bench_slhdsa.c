/*
 * SPDX-FileCopyrightText: 2010-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "esp_timer.h"
#include "esp_heap_caps.h"

#include <oqs.h>

#include "bench_slhdsa.h"

/* Wspólny tekst jak w innych benchach (możesz spiąć z Kconfig jeśli chcesz) */
#ifndef PQC_BENCH_MSG_TEXT
#define PQC_BENCH_MSG_TEXT "Hello PQ world!"
#endif

typedef struct {
    const char *nice_name;  /* do logów i CSV */
    const char *oqs_id;     /* identyfikator liboqs */
} slhdsa_case_t;

/* NIST SLH-DSA / SPHINCS+ (simple) – zgodnie z Twoją listą */
static const slhdsa_case_t g_cases[] = {
    /* SHA2 profile */
    { "SLH-DSA-SHA2-128s",  OQS_SIG_alg_sphincs_sha2_128s_simple  },
    { "SLH-DSA-SHA2-128f",  OQS_SIG_alg_sphincs_sha2_128f_simple  },
    { "SLH-DSA-SHA2-192s",  OQS_SIG_alg_sphincs_sha2_192s_simple  },
    { "SLH-DSA-SHA2-192f",  OQS_SIG_alg_sphincs_sha2_192f_simple  },
    { "SLH-DSA-SHA2-256s",  OQS_SIG_alg_sphincs_sha2_256s_simple  },
    { "SLH-DSA-SHA2-256f",  OQS_SIG_alg_sphincs_sha2_256f_simple  },

    /* SHAKE profile */
    { "SLH-DSA-SHAKE-128s", OQS_SIG_alg_sphincs_shake_128s_simple },
    { "SLH-DSA-SHAKE-128f", OQS_SIG_alg_sphincs_shake_128f_simple },
    { "SLH-DSA-SHAKE-192s", OQS_SIG_alg_sphincs_shake_192s_simple },
    { "SLH-DSA-SHAKE-192f", OQS_SIG_alg_sphincs_shake_192f_simple },
    { "SLH-DSA-SHAKE-256s", OQS_SIG_alg_sphincs_shake_256s_simple },
    { "SLH-DSA-SHAKE-256f", OQS_SIG_alg_sphincs_shake_256f_simple },
};

static const size_t g_cases_count = sizeof(g_cases) / sizeof(g_cases[0]);

static inline uint32_t heap_free_now(void) {
    return (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
}

static inline uint32_t heap_largest_block_now(void) {
    return (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);
}

static void print_case_header(const char *nice, const char *oqs_id,
                              size_t pk, size_t sk, size_t sig_len_max)
{
    printf("\n=== SLH-DSA %s (%s) ===\n", nice, oqs_id);
    printf("# %s sizes: pk=%zu sk=%zu sig=%zu\n", nice, pk, sk, sig_len_max);
}

static void update_min(uint32_t v, uint32_t *min_v) {
    if (v < *min_v) *min_v = v;
}

static uint64_t bench_keygen(OQS_SIG *sig, uint8_t *pk, uint8_t *sk) {
    uint64_t t0 = esp_timer_get_time();
    OQS_STATUS st = OQS_SIG_keypair(sig, pk, sk);
    uint64_t t1 = esp_timer_get_time();
    return (st == OQS_SUCCESS) ? (t1 - t0) : UINT64_MAX;
}

static uint64_t bench_sign(OQS_SIG *sig, uint8_t *sig_buf, size_t *sig_len,
                           const uint8_t *msg, size_t msg_len,
                           const uint8_t *sk)
{
    uint64_t t0 = esp_timer_get_time();
    OQS_STATUS st = OQS_SIG_sign(sig, sig_buf, sig_len, msg, msg_len, sk);
    uint64_t t1 = esp_timer_get_time();
    return (st == OQS_SUCCESS) ? (t1 - t0) : UINT64_MAX;
}

static uint64_t bench_verify(OQS_SIG *sig,
                             const uint8_t *msg, size_t msg_len,
                             const uint8_t *sig_buf, size_t sig_len,
                             const uint8_t *pk)
{
    uint64_t t0 = esp_timer_get_time();
    OQS_STATUS st = OQS_SIG_verify(sig, msg, msg_len, sig_buf, sig_len, pk);
    uint64_t t1 = esp_timer_get_time();
    return (st == OQS_SUCCESS) ? (t1 - t0) : UINT64_MAX;
}

static void bench_one_case(const slhdsa_case_t *c, int warmup, int runs)
{
    OQS_SIG *sig = OQS_SIG_new(c->oqs_id);
    if (!sig) {
        printf("\n=== SLH-DSA %s (%s) ===\n", c->nice_name, c->oqs_id);
        printf("  [SKIP] OQS_SIG_new failed – algorithm not enabled in liboqs\n");
        return;
    }

    const uint8_t msg[] = PQC_BENCH_MSG_TEXT;
    const size_t msg_len = strlen((const char *)msg);

    print_case_header(c->nice_name, c->oqs_id,
                      sig->length_public_key,
                      sig->length_secret_key,
                      sig->length_signature);

    uint8_t *pk = (uint8_t *)malloc(sig->length_public_key);
    uint8_t *sk = (uint8_t *)malloc(sig->length_secret_key);
    uint8_t *sig_buf = (uint8_t *)malloc(sig->length_signature);

    if (!pk || !sk || !sig_buf) {
        printf("  [FAIL] malloc failed (pk/sk/sig)\n");
        if (pk) free(pk);
        if (sk) free(sk);
        if (sig_buf) free(sig_buf);
        OQS_SIG_free(sig);
        return;
    }

    /* Warmup: nie raportujemy, ale robimy real work */
    for (int i = 0; i < warmup; i++) {
        size_t sig_len = 0;
        (void)bench_keygen(sig, pk, sk);
        (void)bench_sign(sig, sig_buf, &sig_len, msg, msg_len, sk);
        (void)bench_verify(sig, msg, msg_len, sig_buf, sig_len, pk);
    }

    /* Pomiar: raportujemy jak ML-KEM */
    uint32_t heap_min_case = UINT32_MAX;
    uint32_t largest_free_min_case = UINT32_MAX;

    /* KEYGEN */
    for (int i = 0; i < runs; i++) {
        uint64_t dt = bench_keygen(sig, pk, sk);
        uint32_t hf = heap_free_now();
        uint32_t lb = heap_largest_block_now();

        update_min(hf, &heap_min_case);
        update_min(lb, &largest_free_min_case);

        if (dt == UINT64_MAX) {
            printf("  %s keygen run=%03d    FAIL heap=%u largest=%u\n",
                   c->nice_name, i, (unsigned)hf, (unsigned)lb);
            continue;
        }

        printf("  %s keygen run=%03d    %8.3f ms heap=%u (d=0) largest=%u\n",
               c->nice_name, i,
               dt / 1000.0,
               (unsigned)hf,
               (unsigned)lb);
    }

    /* SIGN */
    for (int i = 0; i < runs; i++) {
        size_t sig_len = 0;
        uint64_t dt = bench_sign(sig, sig_buf, &sig_len, msg, msg_len, sk);
        uint32_t hf = heap_free_now();
        uint32_t lb = heap_largest_block_now();

        update_min(hf, &heap_min_case);
        update_min(lb, &largest_free_min_case);

        if (dt == UINT64_MAX) {
            printf("  %s sign   run=%03d    FAIL heap=%u largest=%u\n",
                   c->nice_name, i, (unsigned)hf, (unsigned)lb);
            continue;
        }

        printf("  %s sign   run=%03d    %8.3f ms heap=%u (d=0) largest=%u\n",
               c->nice_name, i,
               dt / 1000.0,
               (unsigned)hf,
               (unsigned)lb);
    }

    /* VERIFY */
    for (int i = 0; i < runs; i++) {
        /* musimy mieć poprawny podpis do verify */
        size_t sig_len = 0;
        uint64_t sdt = bench_sign(sig, sig_buf, &sig_len, msg, msg_len, sk);
        if (sdt == UINT64_MAX) {
            printf("  %s verify run=%03d    SKIP(sign FAIL)\n", c->nice_name, i);
            continue;
        }

        uint64_t dt = bench_verify(sig, msg, msg_len, sig_buf, sig_len, pk);
        uint32_t hf = heap_free_now();
        uint32_t lb = heap_largest_block_now();

        update_min(hf, &heap_min_case);
        update_min(lb, &largest_free_min_case);

        if (dt == UINT64_MAX) {
            printf("  %s verify run=%03d    FAIL heap=%u largest=%u\n",
                   c->nice_name, i, (unsigned)hf, (unsigned)lb);
            continue;
        }

        printf("  %s verify run=%03d    %8.3f ms heap=%u (d=0) largest=%u\n",
               c->nice_name, i,
               dt / 1000.0,
               (unsigned)hf,
               (unsigned)lb);
    }

    printf("# %s heap_min_case=%u heap_largest_free_min_case=%u\n",
           c->nice_name,
           (unsigned)heap_min_case,
           (unsigned)largest_free_min_case);

    free(pk);
    free(sk);
    free(sig_buf);
    OQS_SIG_free(sig);
}

void bench_slhdsa_all_full(int warmup, int runs)
{
    printf("\n=== SLH-DSA BENCHMARK START ===\n");

    for (size_t i = 0; i < g_cases_count; i++) {
        bench_one_case(&g_cases[i], warmup, runs);
    }

    printf("\n=== SLH-DSA BENCHMARK END ===\n");
}