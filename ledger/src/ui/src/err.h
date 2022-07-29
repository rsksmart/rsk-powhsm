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

#ifndef __ERR
#define __ERR

// Work-around for static_assert()
#define COMPILE_TIME_ASSERT(condition) \
    ((void)sizeof(char[1 - 2 * !(condition)]))

// Error codes for RSK operations
typedef enum {
    PROT_INVALID = 0x6a01, // Ledger got invalid or unexpected message

    ATT_NO_ONBOARD = 0x6a02, // Attestation: device not onboarded using the UI

    SIG_AUT_INVALID_ITERATION =
        0x6a03, // Signer authorization: invalid iteration given
    SIG_AUT_INVALID_SIGNATURE =
        0x6a04, // Signer authorization: invalid signature given
    SIG_AUT_INVALID_AUTH_INVALID_INDEX =
        0x6a05, // Signer authorization: invalid authorizer index

    INTERNAL = 0x6a99, // Internal error while generating attestation
} err_code_rsk_t;

// Error codes for UI operations
typedef enum {
    ERR_INVALID_PIN = 0x69A0,
} err_code_ui_t;

typedef enum {
    ERR_INVALID_CLA = 0x6E22,
} err_code_ui_apdu_t;

#endif