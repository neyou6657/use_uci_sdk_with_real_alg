#ifndef UCIAPI_EXPERIMENTAL_PQ_FIPS202_H
#define UCIAPI_EXPERIMENTAL_PQ_FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

typedef struct {
    void *ctx;
    size_t n_out;
} shake128incctx;

typedef struct {
    void *ctx;
    size_t n_out;
} shake256incctx;

void shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);
void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);

void shake128_inc_init(shake128incctx *state);
void shake128_inc_absorb(shake128incctx *state, const uint8_t *input, size_t inlen);
void shake128_inc_finalize(shake128incctx *state);
void shake128_inc_squeeze(uint8_t *output, size_t outlen, shake128incctx *state);
void shake128_inc_ctx_release(shake128incctx *state);

void shake256_inc_init(shake256incctx *state);
void shake256_inc_absorb(shake256incctx *state, const uint8_t *input, size_t inlen);
void shake256_inc_finalize(shake256incctx *state);
void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *state);
void shake256_inc_ctx_release(shake256incctx *state);

void shake128_absorb_once(shake128incctx *state, const uint8_t *input, size_t inlen);
void shake256_absorb_once(shake256incctx *state, const uint8_t *input, size_t inlen);

#define shake128_squeezeblocks(OUT, NBLOCKS, STATE) \
    shake128_inc_squeeze((OUT), (NBLOCKS) * SHAKE128_RATE, (STATE))

#define shake256_squeezeblocks(OUT, NBLOCKS, STATE) \
    shake256_inc_squeeze((OUT), (NBLOCKS) * SHAKE256_RATE, (STATE))

#endif
