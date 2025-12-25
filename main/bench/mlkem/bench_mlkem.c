#include "bench_mlkem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>

#include "sdkconfig.h"
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

/* ================= LOG HELPERS ================= */

static inline void log_csv_header_once(void)
{
#if CONFIG_PQC_LOG_CSV
    /* rozbudowany CSV (paper-ready) */
    printf("CSV,kind,alg,op,run,time_us,"
           "heap_before,heap_after,heap_delta,heap_largest_free,"
           "pk_bytes,sk_bytes,ct_bytes,ss_bytes,rc\n");
    fflush(stdout);
#endif
}

static inline void log_visual_case_header(const char *alg, const char *oqs_id)
{
#if CONFIG_PQC_LOG_VISUAL
    printf("\n=== ML-KEM %s (%s) ===\n", alg, oqs_id);
    fflush(stdout);
#else
    (void)alg; (void)oqs_id;
#endif
}

static inline void log_sizes(const char *alg,
                             uint32_t pk, uint32_t sk,
                             uint32_t ct, uint32_t ss)
{
#if CONFIG_PQC_LOG_VISUAL
    printf("# %s sizes: pk=%" PRIu32 " sk=%" PRIu32 " ct=%" PRIu32 " ss=%" PRIu32 "\n",
           alg, pk, sk, ct, ss);
#endif

#if CONFIG_PQC_LOG_CSV
    /* kind=sizes, bez timingów/heapów */
    printf("CSV,sizes,%s,,,,,,,,,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",\n",
           alg, pk, sk, ct, ss);
#endif
    fflush(stdout);
}

static inline void log_skip(const char *alg, const char *reason)
{
#if CONFIG_PQC_LOG_VISUAL
    printf("  [SKIP] %s (%s)\n", alg, reason);
#endif
#if CONFIG_PQC_LOG_CSV
    printf("CSV,skip,%s,,,,,,,,,,,,%s\n", alg, reason);
#endif
    fflush(stdout);
}

static inline void log_fail(const char *alg, const char *reason)
{
#if CONFIG_PQC_LOG_VISUAL
    printf("  [FAIL] %s (%s)\n", alg, reason);
#endif
#if CONFIG_PQC_LOG_CSV
    printf("CSV,fail,%s,,,,,,,,,,,,%s\n", alg, reason);
#endif
    fflush(stdout);
}

/* summary per case (minimum observed heap) */
static inline void log_case_summary(const char *alg,
                                   uint32_t heap_min_case,
                                   uint32_t heap_largest_free_min_case)
{
#if CONFIG_PQC_LOG_VISUAL
    printf("# %s heap_min_case=%" PRIu32 " heap_largest_free_min_case=%" PRIu32 "\n",
           alg, heap_min_case, heap_largest_free_min_case);
#endif
#if CONFIG_PQC_LOG_CSV
    printf("CSV,case_summary,%s,,,,,%" PRIu32 ",,,%" PRIu32 ",,,,,\n",
           alg, heap_min_case, heap_largest_free_min_case);
#endif
    fflush(stdout);
}

static inline void log_result(const char *alg, const char *op, int run,
                              uint64_t time_us,
                              uint32_t heap_before,
                              uint32_t heap_after,
                              int32_t heap_delta,
                              uint32_t heap_largest_free,
                              int rc)
{
    const int every = CONFIG_PQC_LOG_EVERY;
    if (every > 1 && (run % every) != 0) {
        return;
    }

#if CONFIG_PQC_LOG_CSV
    printf("CSV,result,%s,%s,%d,%" PRIu64 ","
           "%" PRIu32 ",%" PRIu32 ",%" PRIi32 ",%" PRIu32 ","
           ",,,,%d\n",
           alg, op, run, time_us,
           heap_before, heap_after, heap_delta, heap_largest_free,
           rc);
#endif

#if CONFIG_PQC_LOG_VISUAL
    printf("  %-10s %-6s run=%03d %10.3f ms heap=%" PRIu32 " (d=%" PRIi32 ") largest=%" PRIu32 "\n",
           alg, op, run, (double)time_us / 1000.0,
           heap_after, heap_delta, heap_largest_free);
#endif

    fflush(stdout);
}

/* ================= BENCH CORE ================= */

static void bench_one_mlkem_case(const KemCase *c,
                                 int warmup_iters,
                                 int run_iters)
{
    log_visual_case_header(c->name, c->oqs_id);

    OQS_KEM *kem = OQS_KEM_new(c->oqs_id);
    if (!kem) {
        log_skip(c->name, "init_failed");
        return;
    }

    uint8_t *pk  = malloc(kem->length_public_key);
    uint8_t *sk  = malloc(kem->length_secret_key);
    uint8_t *ct  = malloc(kem->length_ciphertext);
    uint8_t *ss1 = malloc(kem->length_shared_secret);
    uint8_t *ss2 = malloc(kem->length_shared_secret);

    if (!pk || !sk || !ct || !ss1 || !ss2) {
        log_fail(c->name, "malloc");
        goto cleanup;
    }

    /* sizes */
    log_sizes(c->name,
              (uint32_t)kem->length_public_key,
              (uint32_t)kem->length_secret_key,
              (uint32_t)kem->length_ciphertext,
              (uint32_t)kem->length_shared_secret);

    /* case-level minima */
    uint32_t heap_min_case = UINT32_MAX;
    uint32_t heap_largest_free_min_case = UINT32_MAX;

    /* helper lambda-ish */
    #define UPDATE_CASE_MINIMA() do { \
        uint32_t _hf = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT); \
        uint32_t _lf = (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT); \
        if (_hf < heap_min_case) heap_min_case = _hf; \
        if (_lf < heap_largest_free_min_case) heap_largest_free_min_case = _lf; \
    } while (0)

    UPDATE_CASE_MINIMA();

    /* ================= KEYGEN ================= */

    for (int i = 0; i < warmup_iters; i++) {
        (void)OQS_KEM_keypair(kem, pk, sk);
    }

    for (int i = 0; i < run_iters; i++) {
        uint32_t heap_before = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);

        uint64_t t0 = esp_timer_get_time();
        OQS_STATUS st = OQS_KEM_keypair(kem, pk, sk);
        uint64_t t1 = esp_timer_get_time();

        uint32_t heap_after = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
        int32_t heap_delta = (int32_t)heap_after - (int32_t)heap_before;
        uint32_t largest = (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);

        if (heap_after < heap_min_case) heap_min_case = heap_after;
        if (heap_before < heap_min_case) heap_min_case = heap_before;
        if (largest < heap_largest_free_min_case) heap_largest_free_min_case = largest;

        log_result(c->name, "keygen", i, (t1 - t0),
                   heap_before, heap_after, heap_delta, largest, (int)st);

        if (st != OQS_SUCCESS) {
            log_fail(c->name, "keygen_failed");
            goto cleanup;
        }
    }

    /* ================= ENCAP ================= */

    for (int i = 0; i < warmup_iters; i++) {
        (void)OQS_KEM_encaps(kem, ct, ss1, pk);
    }

    for (int i = 0; i < run_iters; i++) {
        uint32_t heap_before = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);

        uint64_t t0 = esp_timer_get_time();
        OQS_STATUS st = OQS_KEM_encaps(kem, ct, ss1, pk);
        uint64_t t1 = esp_timer_get_time();

        uint32_t heap_after = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
        int32_t heap_delta = (int32_t)heap_after - (int32_t)heap_before;
        uint32_t largest = (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);

        if (heap_after < heap_min_case) heap_min_case = heap_after;
        if (heap_before < heap_min_case) heap_min_case = heap_before;
        if (largest < heap_largest_free_min_case) heap_largest_free_min_case = largest;

        log_result(c->name, "encap", i, (t1 - t0),
                   heap_before, heap_after, heap_delta, largest, (int)st);

        if (st != OQS_SUCCESS) {
            log_fail(c->name, "encap_failed");
            goto cleanup;
        }
    }

    /* ================= DECAP ================= */

    for (int i = 0; i < warmup_iters; i++) {
        (void)OQS_KEM_decaps(kem, ss2, ct, sk);
    }

    for (int i = 0; i < run_iters; i++) {
        uint32_t heap_before = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);

        uint64_t t0 = esp_timer_get_time();
        OQS_STATUS st = OQS_KEM_decaps(kem, ss2, ct, sk);
        uint64_t t1 = esp_timer_get_time();

        uint32_t heap_after = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
        int32_t heap_delta = (int32_t)heap_after - (int32_t)heap_before;
        uint32_t largest = (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);

        if (heap_after < heap_min_case) heap_min_case = heap_after;
        if (heap_before < heap_min_case) heap_min_case = heap_before;
        if (largest < heap_largest_free_min_case) heap_largest_free_min_case = largest;

        log_result(c->name, "decap", i, (t1 - t0),
                   heap_before, heap_after, heap_delta, largest, (int)st);

        if (st != OQS_SUCCESS) {
            log_fail(c->name, "decap_failed");
            goto cleanup;
        }
    }

    /* correctness check */
    if (memcmp(ss1, ss2, kem->length_shared_secret) != 0) {
        log_fail(c->name, "ss_mismatch");
    }

    /* case summary */
    log_case_summary(c->name, heap_min_case, heap_largest_free_min_case);

cleanup:
    free(pk);
    free(sk);
    free(ct);
    free(ss1);
    free(ss2);
    OQS_KEM_free(kem);

    #undef UPDATE_CASE_MINIMA
}

/* ================= PUBLIC ENTRY ================= */

void bench_mlkem_all_full(int warmup_iters, int run_iters)
{
#if CONFIG_PQC_LOG_VISUAL
    printf("\n=== ML-KEM BENCHMARK START ===\n");
    printf("# warmup=%d runs=%d log_every=%d csv=%d visual=%d\n",
           warmup_iters, run_iters, CONFIG_PQC_LOG_EVERY,
#ifdef CONFIG_PQC_LOG_CSV
           CONFIG_PQC_LOG_CSV,
#else
           0,
#endif
#ifdef CONFIG_PQC_LOG_VISUAL
           CONFIG_PQC_LOG_VISUAL
#else
           0
#endif
    );
    fflush(stdout);
#endif

    log_csv_header_once();

    for (size_t i = 0; i < MLKEM_CASES_COUNT; i++) {
        bench_one_mlkem_case(&mlkem_cases[i], warmup_iters, run_iters);
    }

#if CONFIG_PQC_LOG_VISUAL
    printf("=== ML-KEM BENCHMARK END ===\n");
    fflush(stdout);
#endif
}