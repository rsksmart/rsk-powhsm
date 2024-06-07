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

#ifndef __INSTRUCTIONS_H
#define __INSTRUCTIONS_H

/*
 * All APDU instructions
 */

typedef enum {
    // Signing-related
    INS_SIGN = 0x02,
    INS_GET_PUBLIC_KEY = 0x04,

    // Misc
    RSK_IS_ONBOARD = 0x06,
    RSK_MODE_CMD = 0x43,

    // Advance blockchain and blockchain state
    INS_ADVANCE = 0x10,
    INS_ADVANCE_PARAMS = 0x11,
    INS_GET_STATE = 0x20,
    INS_RESET_STATE = 0x21,
    INS_UPD_ANCESTOR = 0x30,

    // Attestation
    INS_ATTESTATION = 0x50,
    INS_HEARTBEAT = 0x60,

    // Exit
    INS_EXIT = 0xff,
} apdu_instruction_t;

#endif // __INSTRUCTIONS_H
