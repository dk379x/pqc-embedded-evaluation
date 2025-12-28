#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Run SLH-DSA (SPHINCS+) benchmarks for all supported variants.
 *
 * @param warmup  number of warmup iterations (not reported)
 * @param runs    number of measured iterations (reported)
 */
void bench_slhdsa_all_full(int warmup, int runs);

#ifdef __cplusplus
}
#endif