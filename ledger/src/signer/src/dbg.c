#ifdef FEDHM_EMULATOR

// Only define LOG_HEX if we are running in emulator mode

#include <stdio.h>
#include <stdlib.h>

void LOG_HEX(const char *name, unsigned char *hash, size_t size) {
    fprintf(stderr, "%s: ", name);
    for (unsigned int i = 0; i < size; i++) {
        fprintf(stderr, "%02x", hash[i]);
    }
    fprintf(stderr, "\n");
}

#endif