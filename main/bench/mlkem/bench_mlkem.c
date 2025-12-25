#include "bench_mlkem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "esp_timer.h"
#include "esp_heap_caps.h"

#include <oqs.h>

/* ================= ML-KEM CASES ================= */

typedef struct {
    const char *name;    /* do logów */
    const char *oqs_id;  /* identyfikator liboqs */
} KemCase;

static const KemCase mlkem_cases[] = {
    { "ML-KEM-512",  OQS_KEM_alg_ml_kem_512  },
    { "ML-KEM-768",  OQS_KEM_alg_ml_kem_768  },
    { "ML-KEM-1024", OQS_KEM_alg_ml_kem_1024 },
};

static const size_t MLKEM_CASES_COUNT =
    sizeof(mlkem_cases) / sizeof(mlkem_cases[0]);

/* ================= BENCH CORE ================= */

static void bench_one_mlkem_case(const KemCase *c,
                                 int warmup_iters,
                                 int run_iters)
{
    printf("\n=== ML-KEM %s (%s) ===\n", c->name, c->oqs_id);
    fflush(stdout);

    OQS_KEM *kem = OQS_KEM_new(c->oqs_id);
    if (!kem) {
        printf("SKIP_MLKEM;%s;reason=init_failed\n", c->name);
        return;
    }

    uint8_t *pk  = malloc(kem->length_public_key);
    uint8_t *sk  = malloc(kem->length_secret_key);
    uint8_t *ct  = malloc(kem->length_ciphertext);
    uint8_t *ss1 = malloc(kem->length_shared_secret);
    uint8_t *ss2 = malloc(kem->length_shared_secret);

    if (!pk || !sk || !ct || !ss1 || !ss2) {
        printf("FAIL_MLKEM;%s;reason=malloc\n", c->name);
        goto cleanup;
    }

    /* rozmiary – do tabeli w paperze */
    printf("SIZES_MLKEM;%s;pk=%u;sk=%u;ct=%u;ss=%u\n",
           c->name,
           (unsigned)kem->length_public_key,
           (unsigned)kem->length_secret_key,
           (unsigned)kem->length_ciphertext,
           (unsigned)kem->length_shared_secret);

    /* ================= KEYGEN ================= */

    for (int i = 0; i < warmup_iters; i++)
        OQS_KEM_keypair(kem, pk, sk);

    for (int i = 0; i < run_iters; i++) {
        uint64_t t0 = esp_timer_get_time();
        OQS_STATUS st = OQS_KEM_keypair(kem, pk, sk);
        uint64_t t1 = esp_timer_get_time();

        if (st != OQS_SUCCESS) break;

        printf("RESULT_MLKEM;%s;keygen;run=%d;time_us=%" PRIu64 ";heap=%u\n",
               c->name, i,
               (t1 - t0),
               (unsigned)heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
        fflush(stdout);
    }

    /* ================= ENCAP ================= */

    for (int i = 0; i < warmup_iters; i++)
        OQS_KEM_encaps(kem, ct, ss1, pk);

    for (int i = 0; i < run_iters; i++) {
        uint64_t t0 = esp_timer_get_time();
        OQS_STATUS st = OQS_KEM_encaps(kem, ct, ss1, pk);
        uint64_t t1 = esp_timer_get_time();

        if (st != OQS_SUCCESS) break;

        printf("RESULT_MLKEM;%s;encap;run=%d;time_us=%" PRIu64 ";heap=%u\n",
               c->name, i,
               (t1 - t0),
               (unsigned)heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
        fflush(stdout);
    }

    /* ================= DECAP ================= */

    for (int i = 0; i < warmup_iters; i++)
        OQS_KEM_decaps(kem, ss2, ct, sk);

    for (int i = 0; i < run_iters; i++) {
        uint64_t t0 = esp_timer_get_time();
        OQS_STATUS st = OQS_KEM_decaps(kem, ss2, ct, sk);
        uint64_t t1 = esp_timer_get_time();

        if (st != OQS_SUCCESS) break;

        printf("RESULT_MLKEM;%s;decap;run=%d;time_us=%" PRIu64 ";heap=%u\n",
               c->name, i,
               (t1 - t0),
               (unsigned)heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
        fflush(stdout);
    }

    /* correctness check */
    if (memcmp(ss1, ss2, kem->length_shared_secret) != 0)
        printf("FAIL_MLKEM;%s;reason=ss_mismatch\n", c->name);

cleanup:
    free(pk);
    free(sk);
    free(ct);
    free(ss1);
    free(ss2);
    OQS_KEM_free(kem);
}

/* ================= PUBLIC ENTRY ================= */

void bench_mlkem_all_full(int warmup_iters, int run_iters)
{
    printf("\n=== ML-KEM BENCHMARK START ===\n");
    for (size_t i = 0; i < MLKEM_CASES_COUNT; i++) {
        bench_one_mlkem_case(&mlkem_cases[i],
                             warmup_iters,
                             run_iters);
    }
    printf("=== ML-KEM BENCHMARK END ===\n");
}