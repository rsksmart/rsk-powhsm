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

#ifndef __ONBOARD_H
#define __ONBOARD_H

#include "pin.h"

// 128 of words (215 => hashed to 64, or 128) + HMAC_LENGTH*2 = 256
#define WORDS_BUFFER_SIZE 257
// Onboard context
typedef struct {
    union {
        unsigned char words_buffer[WORDS_BUFFER_SIZE];
        unsigned char host_seed[SEED_LENGTH];
    };
    unsigned char seed[SEED_LENGTH];
    unsigned int words_buffer_length;
} onboard_t;

/*
 * Reset the given onboard context
 *
 * @arg[in] onboard_ctx onboard context
 */
void reset_onboard_ctx(onboard_t *onboard_ctx);

/*
 * Implement the RSK WIPE command.
 *
 * Wipes and onboards the device.
 *
 * @arg[out] onboard_ctx onboard context
 * @ret                  number of transmited bytes to the host
 */
unsigned int onboard_device(onboard_t *onboard_ctx);

/*
 * Implement the RSK SEED command.
 *
 * Receives one byte at a time and fills host_seed with the host-generated
 * seed.
 *
 * @arg[in]  rx          number of received bytes from the Host
 * @arg[out] onboard_ctx onboard context
 * @ret                  number of transmited bytes to the host
 */
unsigned int set_host_seed(volatile unsigned int rx, onboard_t *onboard_ctx);

/*
 * Implement the RSK IS_ONBOARD command.
 *
 * Returns onboard status to host
 *
 * @ret number of transmited bytes to the host
 */
unsigned int is_onboarded();

#endif // __ONBOARD_H
