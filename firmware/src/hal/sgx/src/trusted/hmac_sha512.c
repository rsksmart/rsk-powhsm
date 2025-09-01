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

#include "hal/log.h"
#include "endian.h"
#include "hmac_sha512.h"

#include <mbedtls/md.h>

bool hmac_sha512(uint8_t *out,
                 const size_t out_length,
                 const uint8_t *key,
                 const unsigned int key_length,
                 const uint8_t *text,
                 const unsigned int text_length) {
    mbedtls_md_context_t ctx;
    int use_hmac;
    const mbedtls_md_info_t *md_info;

    if (out_length < SHA512_HASH_LENGTH) {
        LOG("Error: output buffer too small\n");
        return false;
    }

    mbedtls_md_init(&ctx);
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    if (!md_info) {
        LOG("Error: SHA-512 not supported\n");
        goto hmac_sha512_error;
    }

    use_hmac = 1;
    if (mbedtls_md_setup(&ctx, md_info, use_hmac) != 0) {
        goto hmac_sha512_error;
    }

    if (mbedtls_md_hmac_starts(&ctx, key, key_length) != 0) {
        goto hmac_sha512_error;
    }

    if (mbedtls_md_hmac_update(&ctx, text, text_length) != 0) {
        goto hmac_sha512_error;
    }

    if (mbedtls_md_hmac_finish(&ctx, out) != 0) {
        goto hmac_sha512_error;
    }

    mbedtls_md_free(&ctx);
    return true;

hmac_sha512_error:
    LOG("Error: failed to compute HMAC-SHA512\n");
    mbedtls_md_free(&ctx);
    return false;
}
