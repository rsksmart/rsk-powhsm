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

#ifndef __UI_INSTRUCTIONS_H
#define __UI_INSTRUCTIONS_H

/*
 * All APDU instructions
 */

typedef enum {
    RSK_PIN_CMD = 0x41,
    RSK_SEED_CMD = 0x44,
    RSK_ECHO_CMD = 0x02,
    RSK_IS_ONBOARD = 0x06,
    RSK_WIPE = 0x7,
    RSK_NEWPIN = 0x8,
    RSK_END_CMD = 0xff,
    RSK_END_CMD_NOSIG = 0xfa,
    RSK_UNLOCK_CMD = 0xfe,
    RSK_RETRIES = 0x45,
    RSK_MODE_CMD = 0x43,
    RSK_META_CMD_UIOP = 0x66,

    INS_ATTESTATION = 0x50,
    INS_SIGNER_AUTHORIZATION = 0x51,
    INS_UI_HEARTBEAT = 0x60,
} apdu_instruction_t;

#endif // __UI_INSTRUCTIONS_H
