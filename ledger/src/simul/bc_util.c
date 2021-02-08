#include <stdlib.h>
#include <stdint.h>

#include "bc_util.h"

/* Dump bytes from n in bigendian to the given buffer */
void dump_bigendian(uint8_t* buffer, size_t bytes, uint64_t n) {
    for (int i = 0; i < bytes; i++) {
        buffer[bytes - i - 1] = (uint8_t)(n & 0xff);
        n >>= 8;
    }
}