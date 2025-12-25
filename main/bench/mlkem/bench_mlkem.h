#pragma once

/* 
 * ML-KEM benchmark entry point
 * warmup_iters – liczba iteracji rozgrzewkowych
 * run_iters    – liczba iteracji mierzonych (np. 100)
 */
void bench_mlkem_all_full(int warmup_iters, int run_iters);