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

#ifndef __BC_ADVANCE
#define __BC_ADVANCE

/*
 * Blockchain advance protocol definitions. These messages
 * define the protocol for advancing a blockchain over a
 * bunch of blocks.
 */

// Command code for advancing blockchain
#define INS_ADVANCE 0x10

// Command code for reading the advance blockchain precompiled parameters
#define INS_ADVANCE_PARAMS 0x11

// Operations for advancing blockchain protocol
#define OP_ADVANCE_INIT 0x02
#define OP_ADVANCE_HEADER_META 0x03
#define OP_ADVANCE_HEADER_CHUNK 0x04
#define OP_ADVANCE_PARTIAL 0x05
#define OP_ADVANCE_SUCCESS 0x06

#ifndef PARAM_MIN_REQUIRED_DIFFICULTY
#include "bc.h"
#include "bigdigits.h"
extern DIGIT_T MIN_REQUIRED_DIFFICULTY[BIGINT_LEN];
#endif

/*
 * Initialize Blockchain advance protocol state.
 */
void bc_init_advance();

/*
 * Advance blockchain state.
 *
 * @arg[in] rx number of received bytes from the Host
 * @ret     number of transmited bytes to the host
 */
unsigned int bc_advance(volatile unsigned int rx);

/*
 * Get advance blockchain protocol precompiled parameters.
 *
 * @ret number of transmited bytes to the host
 */
unsigned int bc_advance_get_params();

#endif
