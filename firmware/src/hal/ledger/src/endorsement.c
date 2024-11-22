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

#include "os.h"
#include "hal/constants.h"
#include "hal/endorsement.h"

// Index of the ledger endorsement scheme
#define ENDORSEMENT_SCHEME_INDEX 2

static bool sign_performed;

bool endorsement_init() {
    sign_performed = false;
    return true;
}

uint8_t* endorsement_get_envelope() {
    return NULL;
}

size_t endorsement_get_envelope_length() {
    return 0;
}

bool endorsement_sign(uint8_t* msg,
                      size_t msg_size,
                      uint8_t* signature_out,
                      uint8_t* signature_out_length) {

    if (*signature_out_length < MAX_SIGNATURE_LENGTH) {
        return false;
    }

    *signature_out_length =
        os_endorsement_key2_derive_sign_data(msg, msg_size, signature_out);

    sign_performed = true;
    return true;
}

bool endorsement_get_code_hash(uint8_t* code_hash_out,
                               uint8_t* code_hash_out_length) {
    if (!sign_performed) {
        return false;
    }

    if (*code_hash_out_length < HASH_LENGTH) {
        return false;
    }

    *code_hash_out_length = os_endorsement_get_code_hash(code_hash_out);
    return true;
}

bool endorsement_get_public_key(uint8_t* public_key_out,
                                uint8_t* public_key_out_length) {
    if (!sign_performed) {
        return false;
    }

    if (*public_key_out_length < PUBKEY_UNCMP_LENGTH) {
        return false;
    }

    *public_key_out_length =
        os_endorsement_get_public_key(ENDORSEMENT_SCHEME_INDEX, public_key_out);
    return true;
}