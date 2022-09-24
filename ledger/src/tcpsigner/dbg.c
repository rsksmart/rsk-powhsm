/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2021 RSK Labs Ltd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/*******************************************************************************
 *   powHSM
 *
 *   Debug functions for TCPSigner
 ********************************************************************************/

#ifdef HSM_SIMULATOR

#include <stdio.h>
#include <stdlib.h>

#include "bigdigits.h"
#include "srlp.h"

/** Print buffer in hex format with prefix */
void LOG_HEX(const char *prefix, void *buffer, size_t size) {
    printf("%s ", prefix);
    if (size > 0) {
        printf("0x");
        for (unsigned int i = 0; i < size; i++) {
            printf("%02x", ((unsigned char *)buffer)[i]);
        }
    } else {
        printf("EMPTY");
    }
    printf("\n");
}

/** Print big integer in hex format with optional prefix and suffix strings */
void LOG_BIGD_HEX(const char *prefix,
                  const DIGIT_T *a,
                  size_t len,
                  const char *suffix) {
    if (prefix)
        printf("%s", prefix);
    /* Trim leading digits which are zero */
    while (len--) {
        if (a[len] != 0)
            break;
    }
    len++;
    if (0 == len)
        len = 1;
    /* print first digit without leading zeros */
    printf("0x%" PRIxBIGD, a[--len]);
    while (len--) {
        printf("%08" PRIxBIGD, a[len]);
    }
    if (suffix)
        printf("%s", suffix);
}

/** Print N copies of a given char */
void LOG_N_CHARS(const char c, unsigned int times) {
    for (unsigned int i = 0; i < times; i++)
        printf("%c", c);
}

/** Print the given SRLP context (see srlp.h) */
void LOG_SRLP_CTX(uint8_t v, rlp_ctx_t ctx[], uint8_t ptr) {
#ifdef DEBUG_SRLP
    printf("'0x%02x' ; <%u> ; ", v, ptr);
    for (int i = ptr; i >= 0; --i) {
        rlp_ctx_t cur = ctx[i];
        printf("{%d, %u, %u} ; ", cur.state, cur.size, cur.cursor);
    }
    printf("{EOC}\n");
#endif
}

#endif