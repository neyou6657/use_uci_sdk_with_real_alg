#include "fips202.h"

#include <openssl/evp.h>

#include <string.h>
#include <stdlib.h>

static void pq_xof(uint8_t *output, size_t outlen,
                   const uint8_t *input, size_t inlen,
                   const EVP_MD *md)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL) {
        abort();
    }
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1 ||
        EVP_DigestUpdate(ctx, input, inlen) != 1 ||
        EVP_DigestFinalXOF(ctx, output, outlen) != 1) {
        EVP_MD_CTX_free(ctx);
        abort();
    }
    EVP_MD_CTX_free(ctx);
}

static int pq_xof_inc_init(void **slot, const EVP_MD *md)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL) {
        abort();
    }
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        abort();
    }
    *slot = ctx;
    return 1;
}

static void pq_xof_inc_absorb(void *slot, const uint8_t *input, size_t inlen)
{
    EVP_MD_CTX *ctx = (EVP_MD_CTX *)slot;

    if (ctx == NULL) {
        abort();
    }
    (void)EVP_DigestUpdate(ctx, input, inlen);
}

static void pq_xof_inc_squeeze(void *slot, size_t *n_out, uint8_t *output, size_t outlen,
                               const EVP_MD *md)
{
    EVP_MD_CTX *src = (EVP_MD_CTX *)slot;
    EVP_MD_CTX *clone;

    if (src == NULL) {
        abort();
    }

    clone = EVP_MD_CTX_new();
    if (clone == NULL) {
        abort();
    }
    if (EVP_DigestInit_ex(clone, md, NULL) != 1 ||
        EVP_MD_CTX_copy_ex(clone, src) != 1) {
        EVP_MD_CTX_free(clone);
        abort();
    }

    if (*n_out == 0) {
        if (EVP_DigestFinalXOF(clone, output, outlen) == 1) {
            *n_out += outlen;
        }
    } else {
        uint8_t *tmp = malloc(*n_out + outlen);

        if (tmp == NULL) {
            EVP_MD_CTX_free(clone);
            abort();
        }
        if (EVP_DigestFinalXOF(clone, tmp, *n_out + outlen) != 1) {
            free(tmp);
            EVP_MD_CTX_free(clone);
            abort();
        }
        memcpy(output, tmp + *n_out, outlen);
        *n_out += outlen;
        free(tmp);
    }

    EVP_MD_CTX_free(clone);
}

static void pq_xof_inc_release(void **slot, size_t *n_out)
{
    EVP_MD_CTX *ctx = (EVP_MD_CTX *)*slot;

    EVP_MD_CTX_free(ctx);
    *slot = NULL;
    *n_out = 0;
}

void shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen)
{
    pq_xof(output, outlen, input, inlen, EVP_shake128());
}

void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen)
{
    pq_xof(output, outlen, input, inlen, EVP_shake256());
}

void shake128_inc_init(shake128incctx *state)
{
    if (state == NULL) {
        abort();
    }
    state->ctx = NULL;
    state->n_out = 0;
    (void)pq_xof_inc_init(&state->ctx, EVP_shake128());
}

void shake128_inc_absorb(shake128incctx *state, const uint8_t *input, size_t inlen)
{
    if (state == NULL) {
        abort();
    }
    pq_xof_inc_absorb(state->ctx, input, inlen);
}

void shake128_inc_finalize(shake128incctx *state)
{
    (void)state;
}

void shake128_inc_squeeze(uint8_t *output, size_t outlen, shake128incctx *state)
{
    if (state == NULL) {
        abort();
    }
    pq_xof_inc_squeeze(state->ctx, &state->n_out, output, outlen, EVP_shake128());
}

void shake128_inc_ctx_release(shake128incctx *state)
{
    if (state == NULL) {
        abort();
    }
    pq_xof_inc_release(&state->ctx, &state->n_out);
}

void shake256_inc_init(shake256incctx *state)
{
    if (state == NULL) {
        abort();
    }
    state->ctx = NULL;
    state->n_out = 0;
    (void)pq_xof_inc_init(&state->ctx, EVP_shake256());
}

void shake256_inc_absorb(shake256incctx *state, const uint8_t *input, size_t inlen)
{
    if (state == NULL) {
        return;
    }
    pq_xof_inc_absorb(state->ctx, input, inlen);
}

void shake256_inc_finalize(shake256incctx *state)
{
    (void)state;
}

void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *state)
{
    if (state == NULL) {
        return;
    }
    pq_xof_inc_squeeze(state->ctx, &state->n_out, output, outlen, EVP_shake256());
}

void shake256_inc_ctx_release(shake256incctx *state)
{
    if (state == NULL) {
        return;
    }
    pq_xof_inc_release(&state->ctx, &state->n_out);
}

void shake128_absorb_once(shake128incctx *state, const uint8_t *input, size_t inlen)
{
    shake128_inc_init(state);
    shake128_inc_absorb(state, input, inlen);
    shake128_inc_finalize(state);
}

void shake256_absorb_once(shake256incctx *state, const uint8_t *input, size_t inlen)
{
    shake256_inc_init(state);
    shake256_inc_absorb(state, input, inlen);
    shake256_inc_finalize(state);
}
