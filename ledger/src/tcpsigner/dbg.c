#ifdef HSM_SIMULATOR

#include <stdio.h>
#include <stdlib.h>

#include "bigdigits.h"
#include "srlp.h"

/** Print buffer in hex format with prefix */
void LOG_HEX(const char *prefix, void *buffer, size_t size) {
    printf("%s ", prefix);
    if (size > 0) {
        for (unsigned int i = 0; i < size; i++) {
            printf("%02x", ((unsigned char*)buffer)[i]);
        }
    } else {
        printf("EMPTY");
    }
    printf("\n");
}

/** Print big integer in hex format with optional prefix and suffix strings */
void LOG_BIGD_HEX(const char *prefix, const DIGIT_T *a, size_t len, const char *suffix)
{
    if (prefix) printf("%s", prefix);
    /* Trim leading digits which are zero */
    while (len--)
    {
        if (a[len] != 0)
            break;
    }
    len++;
    if (0 == len) len = 1;
    /* print first digit without leading zeros */
    printf("%" PRIxBIGD, a[--len]);
    while (len--)
    {
        printf("%08" PRIxBIGD, a[len]);
    }
    if (suffix) printf("%s", suffix);
}

/** Print N copies of a given char */
void LOG_N_CHARS(const char c, unsigned int times) {
    for (unsigned int i = 0; i < times; i++)
        printf("%c", c);
}

/** Print the given SRLP context (see srlp.h) */
void LOG_SRLP_CTX(rlp_ctx_t ctx[], uint8_t ptr) {
#ifdef DEBUG_SRLP
    for (int i = ptr; i >= 0; --i) {
        rlp_ctx_t cur = ctx[i];
        printf("{%d, %u, %u} ; ", cur.state, cur.size, cur.cursor);
    }
    printf("{EOC}\n");
#endif
}

#endif