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

#ifndef __SIGNER_AUTHORIZATION_STATUS_H
#define __SIGNER_AUTHORIZATION_STATUS_H

#include <stdint.h>
#include <stdbool.h>
#include "defs.h"
#include "runtime.h"

// Signer version
typedef struct {
    uint8_t hash[HASH_LENGTH];
    uint16_t iteration;
} sigaut_signer_t;

// Signer status
typedef struct {
    bool initialized;
    sigaut_signer_t signer;
} sigaut_signer_status_t;

// Current signer status plus shorthand
extern NON_VOLATILE sigaut_signer_status_t N_current_signer_status_var;
#define N_current_signer_status \
    (*(sigaut_signer_status_t*)PIC(&N_current_signer_status_var))

/*
 * Get the current authorized signer information
 */
sigaut_signer_t* get_authorized_signer_info();

#endif // __SIGNER_AUTHORIZATION_STATUS_H
