#include "randombytes.h"

#include <openssl/rand.h>

#include <limits.h>
#include <stdlib.h>

void randombytes(uint8_t *buf, size_t len)
{
    if (len == 0) {
        return;
    }
    if (len > (size_t)INT_MAX || RAND_bytes(buf, (int)len) != 1) {
        abort();
    }
}
