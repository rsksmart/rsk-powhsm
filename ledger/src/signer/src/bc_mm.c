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

#include "bc_mm.h"

/*
 * Helper function: encode a RLP list prefix to the given buffer.
 *
 * @arg[in] list_size list size in bytes
 * @arg[out] buf      pointer to destination buffer
 */
static uint8_t rlp_encode_list_prefix(uint16_t list_size, uint8_t* buf) {
    uint8_t prefix_size;
    if (list_size <= 55) {
        prefix_size = 1;
        buf[0] = (RLP_SHORT_LIST_BASE + list_size) & 0xFF;
    } else {
        prefix_size = 0;
        uint16_t remaining = list_size;
        while (remaining > 0) {
            prefix_size++;
            remaining >>= 8;
        }
        buf[0] = RLP_LONG_LIST_BASE + prefix_size;
        remaining = list_size;
        for (uint8_t i = 0; i < prefix_size; i++) {
            buf[prefix_size - i] = remaining & 0xff;
            remaining >>= 8;
        }
        prefix_size++;
    }

    return prefix_size;
}

/*
 * Helper function: encode a RLP str prefix to the given buffer.
 *
 * The first_str_byte para is ignored for "good" strings. Those
 * are strings whose length is greater than one. It is safe to
 * just pass a zero. If you have a "bad" single byte string,
 * pass 1 for str_size and the unique string byte in the
 * first_str_byte parameter.
 *
 * @arg[in] str_size       string size in bytes
 * @arb[in] first_str_byte first byte of the string.
 * @arg[out] buf           pointer to destination buffer
 */
static uint8_t rlp_encode_str_prefix(uint16_t str_size,
                                     uint8_t first_str_byte,
                                     uint8_t* buf) {
    uint8_t prefix_size;
    if (str_size == 1 && first_str_byte <= RLP_MAX_SINGLE_BYTE) {
        prefix_size = 0;
    } else if (str_size <= 55) {
        prefix_size = 1;
        buf[0] = (RLP_SHORT_STRING_BASE + str_size) & 0xff;
    } else {
        prefix_size = 0;
        uint16_t remaining = str_size;
        while (remaining > 0) {
            prefix_size++;
            remaining >>= 8;
        }
        buf[0] = RLP_LONG_STRING_BASE + prefix_size;
        remaining = str_size;
        for (uint8_t i = 0; i < prefix_size; i++) {
            buf[prefix_size - i] = remaining & 0xff;
            remaining >>= 8;
        }
        prefix_size++;
    }

    return prefix_size;
}

static uint8_t prefix_buf[MAX_RLP_PREFIX_SIZE];

/*
 * Hash a RLP prefix for a list of the given size.
 *
 * @arg[out] kctx     Keccak context for hashing
 * @arg[in] list_size list size in bytes
 */
void mm_hash_rlp_list_prefix(keccak_ctx_t* kctx, uint16_t list_size) {
    uint8_t prefix_size = rlp_encode_list_prefix(list_size, prefix_buf);
    KECCAK_UPDATE(kctx, prefix_buf, prefix_size);
}

/*
 * Hash a RLP prefix for a "good" string of the given size.
 * A string is "good" if the RLP prefix can be determined
 * from the string length alone. This will be the case
 * any string with lenght greater than one.
 *
 * @arg[out] kctx     Keccak context for hashing
 * @arg[in] str_size  string size in bytes, must be greater than one
 */
void mm_hash_good_rlp_str_prefix(keccak_ctx_t* kctx, uint16_t str_size) {
    uint8_t prefix_size = rlp_encode_str_prefix(str_size, 0, prefix_buf);
    KECCAK_UPDATE(kctx, prefix_buf, prefix_size);
}

/*
 * Hash a RLP prefix for a "bad" string. Bad strings are one byte
 * long, and the prefix length is determined by the contexts of
 * the string's single byte.
 *
 * @arg[out] kctx Keccak context for hashing
 * @arg[in]  str  pointer to the bad string's single byte
 */
void mm_hash_bad_rlp_str_prefix(keccak_ctx_t* kctx, const uint8_t* str) {
    uint8_t prefix_size = rlp_encode_str_prefix(1, *str, prefix_buf);
    KECCAK_UPDATE(kctx, prefix_buf, prefix_size);
}
