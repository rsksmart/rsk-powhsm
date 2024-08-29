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

#ifndef __HAL_SEED_H
#define __HAL_SEED_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Returns whether there's a generated seed
 *
 * @returns whether there's a generated seed
 */
bool seed_available();

/**
 * @brief Derives the main node using the given derivation path and
 * computes and outputs its public key in uncompressed format
 *
 * @param path the BIP32 path to use for derivation
 * @param path_length the BIP32 path length in parts (not bytes)
 * @param pubkey_out where the public key should be output
 * @param pubkey_out_length [in/out] the length of the output buffer /
 *                          length of the produced public key
 *
 * @returns whether the derivation succeeded
 */
bool seed_derive_pubkey(uint32_t* path,
                        uint8_t path_length,
                        uint8_t* pubkey_out,
                        uint8_t* pubkey_out_length);

/**
 * @brief Signs the given hash with the private key obtained
 * by deriving the main node using the given derivation path, and
 * outputs the signature in DER format.
 *
 * @param path the BIP32 path to use for derivation
 * @param hash32 the 32 byte hash to sign
 * @param sig_out where the public key should be output
 * @param sig_out_length [in/out] the length of the output buffer /
 *                       length of the produced signature
 *
 * @returns whether the signing succeeded
 */
bool seed_sign(uint32_t* path,
               uint8_t path_length,
               uint8_t* hash32,
               uint8_t* sig_out,
               uint8_t* sig_out_length);

// BEGINNING of platform-dependent code
#if defined(HSM_PLATFORM_X86)

typedef struct seed_data_s {
    bool is_onboarded;
} seed_data_t;

/**
 * @brief Derive the public key corresponding to the given
 *        private key and output it in either compressed
 *        or uncompressed format
 *
 * @param key the private key
 * @param dest the destination buffer for the derived public key
 * @param compressed whether to output in compressed or uncompressed format
 *
 * @returns the size of the output public key in bytes
 */
uint8_t seed_derive_pubkey_format(const unsigned char* key,
                                  unsigned char* dest,
                                  bool compressed);

/**
 * @brief Mock the return value of the seed_available() function
 *
 * @param is_onboarded the mock value
 */
void seed_set_is_onboarded(bool is_onboarded);

/**
 * @brief Initializes the seed module
 *
 * @param key_file_path the path to the file that
 *                      contains the private keys
 * @param bip32_paths an array containing the bip32 path strings
 * @param bip32_paths_count the number of bip32 paths
 *
 * @returns whether the initialisation succeeded
 */
bool seed_init(const char* key_file_path,
               const char* bip32_paths[],
               const size_t bip32_paths_count);

#elif defined(HSM_PLATFORM_SGX)

/**
 * @brief Initializes the seed module
 *
 * @returns whether the initialisation was successful
 */
bool seed_init();

/**
 * @brief Wipes the existing seed, if any
 *
 * @returns whether the wipe was successful
 */
bool seed_wipe();

/**
 * @brief Generates and persists a new random seed
 *
 * @param client_seed the client-provided seed
 *                    (should be randomly generated)
 * @param client_seed_size the size of the client-provided seed
 *
 * @returns whether the seed generation was successful
 */
bool seed_generate(uint8_t* client_seed, uint8_t client_seed_size);

#endif
// END of platform-dependent code

#endif // __HAL_SEED_H
