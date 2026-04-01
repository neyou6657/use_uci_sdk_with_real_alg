#ifndef UCIAPI_EXPERIMENTAL_PQ_SHA2_H
#define UCIAPI_EXPERIMENTAL_PQ_SHA2_H

#include <stddef.h>
#include <stdint.h>

void sha512(uint8_t *output, const uint8_t *input, size_t inplen);

#endif
