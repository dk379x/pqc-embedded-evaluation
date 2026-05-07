#include "mlkem_mldsa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <oqs.h>

#include "esp_timer.h"
#include "esp_heap_caps.h"

static double elapsed_ms(int64_t start_us, int64_t end_us)
{
    return (double)(end_us - start_us) / 1000.0;
}

static void run_combined_pair(const char *kem_alg,
                              const char *sig_alg,
                              int warmup_runs,
                              int measured_runs)
{
    printf("\n=== COMBINED %s + %s ===\n", kem_alg, sig_alg);

    OQS_KEM *kem = OQS_KEM_new(kem_alg);
    if (kem == NULL) {
        printf("[ERR] Failed to initialize KEM: %s\n", kem_alg);
        return;
    }

    OQS_SIG *sig = OQS_SIG_new(sig_alg);
    if (sig == NULL) {
        printf("[ERR] Failed to initialize SIG: %s\n", sig_alg);
        OQS_KEM_free(kem);
        return;
    }

    printf("# Combined sizes: kem_pk=%zu kem_sk=%zu kem_ct=%zu kem_ss=%zu | "
           "sig_pk=%zu sig_sk=%zu sig_sig=%zu\n",
           kem->length_public_key,
           kem->length_secret_key,
           kem->length_ciphertext,
           kem->length_shared_secret,
           sig->length_public_key,
           sig->length_secret_key,
           sig->length_signature);

    uint8_t *kem_pk = malloc(kem->length_public_key);
    uint8_t *kem_sk = malloc(kem->length_secret_key);
    uint8_t *kem_ct = malloc(kem->length_ciphertext);
    uint8_t *kem_ss_enc = malloc(kem->length_shared_secret);
    uint8_t *kem_ss_dec = malloc(kem->length_shared_secret);

    uint8_t *sig_pk = malloc(sig->length_public_key);
    uint8_t *sig_sk = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);

    const uint8_t message[] = "pqc-embedded-evaluation combined ML-KEM ML-DSA benchmark";
    const size_t message_len = sizeof(message) - 1;
    size_t signature_len = 0;

    if (!kem_pk || !kem_sk || !kem_ct || !kem_ss_enc || !kem_ss_dec ||
        !sig_pk || !sig_sk || !signature) {
        printf("[ERR] Memory allocation failed for combined benchmark\n");
        goto cleanup;
    }

    const int total_runs = warmup_runs + measured_runs;

    uint32_t heap_min_case = UINT32_MAX;
    uint32_t heap_largest_min_case = UINT32_MAX;

    for (int run = 0; run < total_runs; run++) {
        int64_t start = esp_timer_get_time();

        OQS_STATUS rc;

        rc = OQS_KEM_keypair(kem, kem_pk, kem_sk);
        if (rc != OQS_SUCCESS) {
            printf("[ERR] %s keypair failed run=%03d\n", kem_alg, run);
            continue;
        }

        rc = OQS_KEM_encaps(kem, kem_ct, kem_ss_enc, kem_pk);
        if (rc != OQS_SUCCESS) {
            printf("[ERR] %s encaps failed run=%03d\n", kem_alg, run);
            continue;
        }

        rc = OQS_KEM_decaps(kem, kem_ss_dec, kem_ct, kem_sk);
        if (rc != OQS_SUCCESS) {
            printf("[ERR] %s decaps failed run=%03d\n", kem_alg, run);
            continue;
        }

        if (memcmp(kem_ss_enc, kem_ss_dec, kem->length_shared_secret) != 0) {
            printf("[ERR] %s shared secret mismatch run=%03d\n", kem_alg, run);
            continue;
        }

        rc = OQS_SIG_keypair(sig, sig_pk, sig_sk);
        if (rc != OQS_SUCCESS) {
            printf("[ERR] %s keypair failed run=%03d\n", sig_alg, run);
            continue;
        }

        rc = OQS_SIG_sign(sig, signature, &signature_len,
                          message, message_len, sig_sk);
        if (rc != OQS_SUCCESS) {
            printf("[ERR] %s sign failed run=%03d\n", sig_alg, run);
            continue;
        }

        rc = OQS_SIG_verify(sig, message, message_len,
                            signature, signature_len, sig_pk);
        if (rc != OQS_SUCCESS) {
            printf("[ERR] %s verify failed run=%03d\n", sig_alg, run);
            continue;
        }

        int64_t end = esp_timer_get_time();

        uint32_t heap_now = heap_caps_get_free_size(MALLOC_CAP_DEFAULT);
        uint32_t largest_now = heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);

        if (heap_now < heap_min_case) {
            heap_min_case = heap_now;
        }

        if (largest_now < heap_largest_min_case) {
            heap_largest_min_case = largest_now;
        }

        const char *phase = (run < warmup_runs) ? "warmup" : "run";

        printf("  COMBINED %s + %s %-6s=%03d total=%10.3f ms heap=%" PRIu32
               " largest=%" PRIu32 "\n",
               kem_alg,
               sig_alg,
               phase,
               (run < warmup_runs) ? run : (run - warmup_runs),
               elapsed_ms(start, end),
               heap_now,
               largest_now);
    }

    printf("# COMBINED %s + %s heap_min_case=%" PRIu32
           " heap_largest_free_min_case=%" PRIu32 "\n",
           kem_alg,
           sig_alg,
           heap_min_case,
           heap_largest_min_case);

cleanup:
    free(kem_pk);
    free(kem_sk);
    free(kem_ct);
    free(kem_ss_enc);
    free(kem_ss_dec);

    free(sig_pk);
    free(sig_sk);
    free(signature);

    OQS_SIG_free(sig);
    OQS_KEM_free(kem);
}

void bench_mlkem_mldsa_all_full(int warmup_runs, int measured_runs)
{
    printf("\n=== COMBINED ML-KEM + ML-DSA BENCHMARK START ===\n");

    run_combined_pair(OQS_KEM_alg_ml_kem_512,
                      OQS_SIG_alg_ml_dsa_44,
                      warmup_runs,
                      measured_runs);

    run_combined_pair(OQS_KEM_alg_ml_kem_768,
                      OQS_SIG_alg_ml_dsa_65,
                      warmup_runs,
                      measured_runs);

    run_combined_pair(OQS_KEM_alg_ml_kem_1024,
                      OQS_SIG_alg_ml_dsa_87,
                      warmup_runs,
                      measured_runs);

    printf("\n=== COMBINED ML-KEM + ML-DSA BENCHMARK END ===\n");
}