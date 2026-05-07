#include "oqs_sha2_esp.h"

#include <stdlib.h>
#include <string.h>

#include <oqs/sha2_ops.h>

#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

static void esp_sha256(uint8_t *output, const uint8_t *input, size_t inplen)
{
    mbedtls_sha256(input, inplen, output, 0);
}

static void esp_sha256_inc_init(OQS_SHA2_sha256_ctx *state)
{
    mbedtls_sha256_context *ctx = malloc(sizeof(mbedtls_sha256_context));
    mbedtls_sha256_init(ctx);
    mbedtls_sha256_starts(ctx, 0);

    state->ctx = ctx;
    state->data_len = 0;
}

static void esp_sha256_inc_ctx_clone(OQS_SHA2_sha256_ctx *dest,
                                     const OQS_SHA2_sha256_ctx *src)
{
    mbedtls_sha256_context *ctx = malloc(sizeof(mbedtls_sha256_context));
    mbedtls_sha256_init(ctx);
    mbedtls_sha256_clone(ctx, (const mbedtls_sha256_context *)src->ctx);

    dest->ctx = ctx;
    dest->data_len = src->data_len;
    memcpy(dest->data, src->data, sizeof(dest->data));
}

static void esp_sha256_inc(OQS_SHA2_sha256_ctx *state,
                           const uint8_t *in,
                           size_t len)
{
    mbedtls_sha256_update((mbedtls_sha256_context *)state->ctx, in, len);
}

static void esp_sha256_inc_blocks(OQS_SHA2_sha256_ctx *state,
                                  const uint8_t *in,
                                  size_t inblocks)
{
    mbedtls_sha256_update((mbedtls_sha256_context *)state->ctx,
                          in,
                          inblocks * 64);
}

static void esp_sha256_inc_finalize(uint8_t *out,
                                    OQS_SHA2_sha256_ctx *state,
                                    const uint8_t *in,
                                    size_t inlen)
{
    if (inlen > 0) {
        mbedtls_sha256_update((mbedtls_sha256_context *)state->ctx, in, inlen);
    }

    mbedtls_sha256_finish((mbedtls_sha256_context *)state->ctx, out);
    mbedtls_sha256_free((mbedtls_sha256_context *)state->ctx);
    free(state->ctx);
    state->ctx = NULL;
    state->data_len = 0;
}

static void esp_sha256_inc_ctx_release(OQS_SHA2_sha256_ctx *state)
{
    if (state->ctx != NULL) {
        mbedtls_sha256_free((mbedtls_sha256_context *)state->ctx);
        free(state->ctx);
        state->ctx = NULL;
    }
    state->data_len = 0;
}

static void esp_sha384(uint8_t *output, const uint8_t *input, size_t inplen)
{
    mbedtls_sha512(input, inplen, output, 1);
}

static void esp_sha384_inc_init(OQS_SHA2_sha384_ctx *state)
{
    mbedtls_sha512_context *ctx = malloc(sizeof(mbedtls_sha512_context));
    mbedtls_sha512_init(ctx);
    mbedtls_sha512_starts(ctx, 1);

    state->ctx = ctx;
    state->data_len = 0;
}

static void esp_sha384_inc_ctx_clone(OQS_SHA2_sha384_ctx *dest,
                                     const OQS_SHA2_sha384_ctx *src)
{
    mbedtls_sha512_context *ctx = malloc(sizeof(mbedtls_sha512_context));
    mbedtls_sha512_init(ctx);
    mbedtls_sha512_clone(ctx, (const mbedtls_sha512_context *)src->ctx);

    dest->ctx = ctx;
    dest->data_len = src->data_len;
    memcpy(dest->data, src->data, sizeof(dest->data));
}

static void esp_sha384_inc_blocks(OQS_SHA2_sha384_ctx *state,
                                  const uint8_t *in,
                                  size_t inblocks)
{
    mbedtls_sha512_update((mbedtls_sha512_context *)state->ctx,
                          in,
                          inblocks * 128);
}

static void esp_sha384_inc_finalize(uint8_t *out,
                                    OQS_SHA2_sha384_ctx *state,
                                    const uint8_t *in,
                                    size_t inlen)
{
    if (inlen > 0) {
        mbedtls_sha512_update((mbedtls_sha512_context *)state->ctx, in, inlen);
    }

    mbedtls_sha512_finish((mbedtls_sha512_context *)state->ctx, out);
    mbedtls_sha512_free((mbedtls_sha512_context *)state->ctx);
    free(state->ctx);
    state->ctx = NULL;
    state->data_len = 0;
}

static void esp_sha384_inc_ctx_release(OQS_SHA2_sha384_ctx *state)
{
    if (state->ctx != NULL) {
        mbedtls_sha512_free((mbedtls_sha512_context *)state->ctx);
        free(state->ctx);
        state->ctx = NULL;
    }
    state->data_len = 0;
}

static void esp_sha512(uint8_t *output, const uint8_t *input, size_t inplen)
{
    mbedtls_sha512(input, inplen, output, 0);
}

static void esp_sha512_inc_init(OQS_SHA2_sha512_ctx *state)
{
    mbedtls_sha512_context *ctx = malloc(sizeof(mbedtls_sha512_context));
    mbedtls_sha512_init(ctx);
    mbedtls_sha512_starts(ctx, 0);

    state->ctx = ctx;
    state->data_len = 0;
}

static void esp_sha512_inc_ctx_clone(OQS_SHA2_sha512_ctx *dest,
                                     const OQS_SHA2_sha512_ctx *src)
{
    mbedtls_sha512_context *ctx = malloc(sizeof(mbedtls_sha512_context));
    mbedtls_sha512_init(ctx);
    mbedtls_sha512_clone(ctx, (const mbedtls_sha512_context *)src->ctx);

    dest->ctx = ctx;
    dest->data_len = src->data_len;
    memcpy(dest->data, src->data, sizeof(dest->data));
}

static void esp_sha512_inc_blocks(OQS_SHA2_sha512_ctx *state,
                                  const uint8_t *in,
                                  size_t inblocks)
{
    mbedtls_sha512_update((mbedtls_sha512_context *)state->ctx,
                          in,
                          inblocks * 128);
}

static void esp_sha512_inc_finalize(uint8_t *out,
                                    OQS_SHA2_sha512_ctx *state,
                                    const uint8_t *in,
                                    size_t inlen)
{
    if (inlen > 0) {
        mbedtls_sha512_update((mbedtls_sha512_context *)state->ctx, in, inlen);
    }

    mbedtls_sha512_finish((mbedtls_sha512_context *)state->ctx, out);
    mbedtls_sha512_free((mbedtls_sha512_context *)state->ctx);
    free(state->ctx);
    state->ctx = NULL;
    state->data_len = 0;
}

static void esp_sha512_inc_ctx_release(OQS_SHA2_sha512_ctx *state)
{
    if (state->ctx != NULL) {
        mbedtls_sha512_free((mbedtls_sha512_context *)state->ctx);
        free(state->ctx);
        state->ctx = NULL;
    }
    state->data_len = 0;
}

void oqs_sha2_esp_install(void)
{
    static struct OQS_SHA2_callbacks callbacks = {
        .SHA2_sha256 = esp_sha256,
        .SHA2_sha256_inc_init = esp_sha256_inc_init,
        .SHA2_sha256_inc_ctx_clone = esp_sha256_inc_ctx_clone,
        .SHA2_sha256_inc = esp_sha256_inc,
        .SHA2_sha256_inc_blocks = esp_sha256_inc_blocks,
        .SHA2_sha256_inc_finalize = esp_sha256_inc_finalize,
        .SHA2_sha256_inc_ctx_release = esp_sha256_inc_ctx_release,

        .SHA2_sha384 = esp_sha384,
        .SHA2_sha384_inc_init = esp_sha384_inc_init,
        .SHA2_sha384_inc_ctx_clone = esp_sha384_inc_ctx_clone,
        .SHA2_sha384_inc_blocks = esp_sha384_inc_blocks,
        .SHA2_sha384_inc_finalize = esp_sha384_inc_finalize,
        .SHA2_sha384_inc_ctx_release = esp_sha384_inc_ctx_release,

        .SHA2_sha512 = esp_sha512,
        .SHA2_sha512_inc_init = esp_sha512_inc_init,
        .SHA2_sha512_inc_ctx_clone = esp_sha512_inc_ctx_clone,
        .SHA2_sha512_inc_blocks = esp_sha512_inc_blocks,
        .SHA2_sha512_inc_finalize = esp_sha512_inc_finalize,
        .SHA2_sha512_inc_ctx_release = esp_sha512_inc_ctx_release,
    };

    OQS_SHA2_set_callbacks(&callbacks);
}