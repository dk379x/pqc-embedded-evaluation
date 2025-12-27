#include "bench_mldsa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>

#include "sdkconfig.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"

#include <oqs.h>

/* ================= ML-DSA CASES ================= */

typedef struct {
    const char *name;   /* do logów */
    const char *oqs_id; /* identyfikator liboqs */
} SigCase;

/*
 * W liboqs dla ML-DSA zwykle działają stringi "ML-DSA-44/65/87"
 * (tak jak miałeś w main). Jeżeli u Ciebie są macro typu OQS_SIG_alg_ml_dsa_44,
 * to tylko podmień oqs_id na te makra.
 */
static const SigCase mldsa_cases[] = {
    { "ML-DSA-44", "ML-DSA-44" },
    { "ML-DSA-65", "ML-DSA-65" },
    { "ML-DSA-87", "ML-DSA-87" },
};

static const size_t MLDSA_CASES_COUNT =
    sizeof(mldsa_cases) / sizeof(mldsa_cases[0]);

/* ================= LOG HELPERS (ML-KEM compatible) ================= */

static inline void log_csv_header_once(void)
{
#if CONFIG_PQC_LOG_CSV
    /* dokładnie ten sam nagłówek co w ML-KEM */
    printf("CSV,kind,alg,op,run,time_us,"
           "heap_before,heap_after,heap_delta,heap_largest_free,"
           "pk_bytes,sk_bytes,ct_bytes,ss_bytes,rc\n");
    fflush(stdout);
#endif
}

static inline void log_visual_case_header(const char *alg, const char *oqs_id)
{
#if CONFIG_PQC_LOG_VISUAL
    printf("\n=== ML-DSA %s (%s) ===\n", alg, oqs_id);
    fflush(stdout);
#else
    (void)alg; (void)oqs_id;
#endif
}

/*
 * Dla SIG: mapujemy pola:
 *  - pk_bytes = public key
 *  - sk_bytes = secret key
 *  - ct_bytes = signature bytes (największy bufor)
 *  - ss_bytes = message bytes (tu: długość wiadomości testowej)
 */
static inline void log_sizes_sig(const char *alg,
                                 uint32_t pk, uint32_t sk,
                                 uint32_t sig_bytes, uint32_t msg_bytes)
{
#if CONFIG_PQC_LOG_VISUAL
    printf("# %s sizes: pk=%" PRIu32 " sk=%" PRIu32 " sig=%" PRIu32 " msg=%" PRIu32 "\n",
           alg, pk, sk, sig_bytes, msg_bytes);
#endif

#if CONFIG_PQC_LOG_CSV
    printf("CSV,sizes,%s,,,,,,,,,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",\n",
           alg, pk, sk, sig_bytes, msg_bytes);
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

static void bench_one_mldsa_case(const SigCase *c,
                                 int warmup_iters,
                                 int run_iters)
{
    log_visual_case_header(c->name, c->oqs_id);

    OQS_SIG *sig = OQS_SIG_new(c->oqs_id);
    if (!sig) {
        log_skip(c->name, "init_failed");
        return;
    }

    /* stała wiadomość – deterministyczna i prosta */
    static const uint8_t msg[] = "Test message for ML-DSA benchmark";
    const size_t msg_len = strlen((const char *)msg);

    uint8_t *pk      = malloc(sig->length_public_key);
    uint8_t *sk      = malloc(sig->length_secret_key);
    uint8_t *sig_buf = malloc(sig->length_signature);

    if (!pk || !sk || !sig_buf) {
        log_fail(c->name, "malloc");
        goto cleanup;
    }

    /* sizes */
    log_sizes_sig(c->name,
                  (uint32_t)sig->length_public_key,
                  (uint32_t)sig->length_secret_key,
                  (uint32_t)sig->length_signature,
                  (uint32_t)msg_len);

    /* minima per case */
    uint32_t heap_min_case = UINT32_MAX;
    uint32_t heap_largest_free_min_case = UINT32_MAX;

    #define UPDATE_CASE_MINIMA() do { \
        uint32_t _hf = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT); \
        uint32_t _lf = (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT); \
        if (_hf < heap_min_case) heap_min_case = _hf; \
        if (_lf < heap_largest_free_min_case) heap_largest_free_min_case = _lf; \
    } while (0)

    UPDATE_CASE_MINIMA();

    /* ================= KEYGEN ================= */

    for (int i = 0; i < warmup_iters; i++) {
        (void)OQS_SIG_keypair(sig, pk, sk);
    }

    for (int i = 0; i < run_iters; i++) {
        uint32_t heap_before = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);

        uint64_t t0 = esp_timer_get_time();
        OQS_STATUS st = OQS_SIG_keypair(sig, pk, sk);
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

    /* ================= SIGN ================= */

    for (int i = 0; i < warmup_iters; i++) {
        size_t sig_len = 0;
        (void)OQS_SIG_sign(sig, sig_buf, &sig_len, msg, msg_len, sk);
    }

    for (int i = 0; i < run_iters; i++) {
        uint32_t heap_before = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);

        size_t sig_len = 0;
        uint64_t t0 = esp_timer_get_time();
        OQS_STATUS st = OQS_SIG_sign(sig, sig_buf, &sig_len, msg, msg_len, sk);
        uint64_t t1 = esp_timer_get_time();

        uint32_t heap_after = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
        int32_t heap_delta = (int32_t)heap_after - (int32_t)heap_before;
        uint32_t largest = (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);

        if (heap_after < heap_min_case) heap_min_case = heap_after;
        if (heap_before < heap_min_case) heap_min_case = heap_before;
        if (largest < heap_largest_free_min_case) heap_largest_free_min_case = largest;

        log_result(c->name, "sign", i, (t1 - t0),
                   heap_before, heap_after, heap_delta, largest, (int)st);

        if (st != OQS_SUCCESS) {
            log_fail(c->name, "sign_failed");
            goto cleanup;
        }
        /* opcjonalnie: sanity check, że sig_len nie jest 0 */
        if (sig_len == 0) {
            log_fail(c->name, "siglen_zero");
            goto cleanup;
        }
    }

    /* ================= VERIFY ================= */

    /* najpierw zrób jedną poprawną sygnaturę do weryfikacji */
    size_t sig_len_ref = 0;
    if (OQS_SIG_sign(sig, sig_buf, &sig_len_ref, msg, msg_len, sk) != OQS_SUCCESS || sig_len_ref == 0) {
        log_fail(c->name, "prep_sign_failed");
        goto cleanup;
    }

    for (int i = 0; i < warmup_iters; i++) {
        (void)OQS_SIG_verify(sig, msg, msg_len, sig_buf, sig_len_ref, pk);
    }

    for (int i = 0; i < run_iters; i++) {
        uint32_t heap_before = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);

        uint64_t t0 = esp_timer_get_time();
        OQS_STATUS st = OQS_SIG_verify(sig, msg, msg_len, sig_buf, sig_len_ref, pk);
        uint64_t t1 = esp_timer_get_time();

        uint32_t heap_after = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
        int32_t heap_delta = (int32_t)heap_after - (int32_t)heap_before;
        uint32_t largest = (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);

        if (heap_after < heap_min_case) heap_min_case = heap_after;
        if (heap_before < heap_min_case) heap_min_case = heap_before;
        if (largest < heap_largest_free_min_case) heap_largest_free_min_case = largest;

        log_result(c->name, "verify", i, (t1 - t0),
                   heap_before, heap_after, heap_delta, largest, (int)st);

        if (st != OQS_SUCCESS) {
            log_fail(c->name, "verify_failed");
            goto cleanup;
        }
    }

    /* summary */
    log_case_summary(c->name, heap_min_case, heap_largest_free_min_case);

cleanup:
    if (pk) free(pk);
    if (sk) free(sk);
    if (sig_buf) free(sig_buf);
    OQS_SIG_free(sig);

    #undef UPDATE_CASE_MINIMA
}

/* ================= PUBLIC ENTRY ================= */

void bench_mldsa_all_full(int warmup_iters, int run_iters)
{
#if CONFIG_PQC_LOG_VISUAL
    printf("\n=== ML-DSA BENCHMARK START ===\n");
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

    for (size_t i = 0; i < MLDSA_CASES_COUNT; i++) {
        bench_one_mldsa_case(&mldsa_cases[i], warmup_iters, run_iters);
    }

#if CONFIG_PQC_LOG_VISUAL
    printf("=== ML-DSA BENCHMARK END ===\n");
    fflush(stdout);
#endif
}