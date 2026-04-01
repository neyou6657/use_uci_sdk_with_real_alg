#include "sha2.h"

#include <openssl/evp.h>

#include <stdlib.h>

void sha512(uint8_t *output, const uint8_t *input, size_t inplen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int outlen = 0;

    if (ctx == NULL) {
        abort();
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, input, inplen) != 1 ||
        EVP_DigestFinal_ex(ctx, output, &outlen) != 1 ||
        outlen != 64) {
        EVP_MD_CTX_free(ctx);
        abort();
    }

    EVP_MD_CTX_free(ctx);
}
