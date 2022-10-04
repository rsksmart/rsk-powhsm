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

#ifndef __WIPE
#define __WIPE

typedef unsigned int (*mnemonic_from_data_cb_t)(unsigned char *in,
                                                unsigned int in_len,
                                                unsigned char *out,
                                                unsigned int out_len);

// Wipe command context
typedef struct {
    unsigned char *pin_buffer;
    char *string_buffer;
    unsigned int string_buffer_len;
    char *words_buffer;
    unsigned int words_buffer_len;
    unsigned int *onboarding_kind;
    mnemonic_from_data_cb_t mnemonic_from_data_cb;
} wipe_t;

/*
 * Implements RSK WIPE command.
 *
 * Wipes and onboards the device.
 *
 * @arg[in] wipe_ctx          Context data with the device's pin, buffers to
 *                            hold the seed and mnemonic, the onboarding kind,
 *                            and a callback function used to generate the
 *                            mnemonic from the seed.
 * @arg[out] words_buffer_len The size of the generated words_buffer.
 * @ret                       Number of transmited bytes to the host.
 */
unsigned char do_rsk_wipe(wipe_t *wipe_ctx, unsigned int *words_buffer_len);

#endif