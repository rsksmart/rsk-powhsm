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

#ifndef __HAL_ENDORSEMENT_H
#define __HAL_ENDORSEMENT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Endorses the given message
 *
 * @param msg The message to attest
 * @param msg_size The size of the message to attest
 * @param signature_out Where the signature should be output
 * @param signature_out_length [in/out] the length of the output buffer /
 *                          length of the produced signature
 *
 * @returns whether endorsement succeeded
 */
bool endorsement_sign(uint8_t* msg,
                      size_t msg_size,
                      uint8_t* signature_out,
                      uint8_t* signature_out_length);

/**
 * @brief Grabs the hash of the currently running code
 *
 * @param code_hash_out Where the code hash should be output
 * @param code_hash_out_length [in/out] the length of the output buffer /
 *                             length of the produced code hash
 *
 * @returns whether code hash gathering succeeded
 */
bool endorsement_get_code_hash(uint8_t* code_hash_out,
                               uint8_t* code_hash_out_length);

/**
 * @brief Grabs the endorsement public key
 *
 * @param public_key_out Where the public key should be output
 * @param public_key_out_length [in/out] the length of the output buffer /
 *                              length of the produced public key
 *
 * @returns whether public key gathering succeeded
 */
bool endorsement_get_public_key(uint8_t* public_key_out,
                                uint8_t* public_key_out_length);

// BEGINNING of platform-dependent code
#if defined(HSM_PLATFORM_X86)

#include "hal/constants.h"

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

/**
 * @brief Initializes the endorsement module
 *
 * @param att_file_path the path to the file that
 *                      contains the attestation id
 *
 * @returns whether the initialisation succeeded
 */
bool endorsement_init(char* att_file_path);

#endif
// END of platform-dependent code

#endif // __HAL_ENDORSEMENT_H