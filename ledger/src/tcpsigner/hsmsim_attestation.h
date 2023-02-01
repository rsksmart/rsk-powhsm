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

#ifndef __SIMULATOR_HSMSIM_ATTESTATION_H
#define __SIMULATOR_HSMSIM_ATTESTATION_H

#include <stdbool.h>

#include "constants.h"

// An attestation ID (in lack of a better name)
// is simply a pair consisting of a secp256k1 private key
// representing the device attestation private key and
// a code hash representing the hash of the running
// application that is attestating. Together, they can
// be used to construct another secp256k1 private key
// which is the attestation private key used to sign the
// attestation messages.
typedef struct {
    unsigned char key[PRIVATE_KEY_LENGTH];
    unsigned char code_hash[HASH_LENGTH];
} attestation_id_t;

extern attestation_id_t attestation_id;

bool hsmsim_attestation_initialize(char* att_file_path);

#endif // __SIMULATOR_HSMSIM_ATTESTATION_H
