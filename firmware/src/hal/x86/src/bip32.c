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

#include "bip32.h"
#include "hal/constants.h"
#include "hal/log.h"
#include "hmac_sha512.h"
#include "endian.h"
#include "bigdigits.h"
#include "bigdigits_helper.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <secp256k1.h>

#define BIP32_PREFIX "m/"
#define MIN_PATH_LENGTH (strlen("m/0/0/0/0/0"))
#define MAX_PART_DECIMAL_DIGITS 10
#define EXPECTED_PARTS BIP32_PATH_NUMPARTS
#define NODE_LENGTH 64

#ifdef DEBUG_BIP32
#define DEBUG_LOG(...) LOG(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

static const uint8_t secp256k1_order[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
    0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

static secp256k1_context* sp_ctx = NULL;

size_t bip32_parse_path(const char* path, uint8_t* out) {
    size_t pos, start, pathlen;
    int parts;
    int index;
    bool number;
    char indexstr[MAX_PART_DECIMAL_DIGITS + 1];
    uint32_t indexint;

    if (strlen(path) < MIN_PATH_LENGTH) {
        DEBUG_LOG("BIP32 path too short: %s\n", path);
        return 0;
    }

    if (strncmp(path, BIP32_PREFIX, strlen(BIP32_PREFIX))) {
        DEBUG_LOG("Bad prefix for path: %s\n", path);
        return 0;
    }

    parts = 0;
    pathlen = strlen(path);
    pos = strlen(BIP32_PREFIX);
    start = pos;
    index = 0;
    number = true;
    while (pos < pathlen) {
        if (number && path[pos] >= '0' && path[pos] <= '9') {
            pos++;
            if (pos - start > MAX_PART_DECIMAL_DIGITS) {
                DEBUG_LOG("Path part %d too long for path: %s\n", parts, path);
                return 0;
            }
        } else if (number && path[pos] == '\'') {
            number = false;
            index = 0x80000000;
            pos++;
        } else if (path[pos] != '/') {
            DEBUG_LOG(
                "Unexpected path character: %c for path %s\n", path[pos], path);
            return 0;
        }

        if (pos == pathlen || path[pos] == '/') {
            // Compute the index
            memcpy(indexstr, path + start, pos - start);
            indexstr[pos - start] = '\0';
            indexint = (uint32_t)atol(indexstr);
            if (indexint >= 0x80000000) {
                DEBUG_LOG("Path part %d needs to be between 0 and 2^31-1 for "
                          "path: %s\n",
                          parts,
                          path);
                return 0;
            }
            index += indexint;
            // Output the index in LE
            for (int i = 0; i < (int)sizeof(uint32_t); i++) {
                out[1 + (parts * sizeof(uint32_t)) + i] =
                    (index >> (8 * i)) & 0xFF;
            }
            // Next!
            parts++;
            index = 0;
            number = true;
            start = ++pos;
            if (parts == EXPECTED_PARTS) {
                if (pos < pathlen) {
                    DEBUG_LOG("Path has too many parts: %s\n", path);
                    return 0;
                }
                out[0] = (char)parts;
                return 1 + parts * sizeof(uint32_t);
            }
        }
    }

    DEBUG_LOG("Unexpected code path reached for path: %s\n", path);
    return 0;
}

/**
 * Following portion taken from
 * https://github.com/someone42/hardware-bitcoin-wallet @
 * 102c300d994712484c3c028b215f90a6f99d6155 and adapted for use with
 * the powHSM HAL by RootstockLabs. LICENSE transcribed below.
 */

/*
  Copyright (c) 2011-2012 someone42
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

      Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

      Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#define PRIVATE_KEY_DIGITS (PRIVATE_KEY_LENGTH / sizeof(DIGIT_T))

static void seed_to_node(uint8_t* master_node,
                         const uint8_t* seed,
                         const unsigned int seed_length) {
    hmac_sha512(
        master_node, (const uint8_t*)"Bitcoin seed", 12, seed, seed_length);
}

bool bip32_derive_private(uint8_t* out,
                          const uint8_t* seed,
                          const unsigned int seed_length,
                          const uint32_t* path,
                          const unsigned int path_length) {
    uint8_t current_node[NODE_LENGTH];
    uint8_t temp[NODE_LENGTH];
    DIGIT_T tempbig_a[PRIVATE_KEY_DIGITS + 1],
        tempbig_b[PRIVATE_KEY_DIGITS + 1];
    DIGIT_T tempbig_c[PRIVATE_KEY_DIGITS + 1],
        tempbig_d[PRIVATE_KEY_DIGITS + 1];
    uint8_t hmac_data[1 + 32 + 4]; // prefix + private key + i
    secp256k1_pubkey pubkey;
    size_t pubkey_serialised_size;

    // Init the secp256k1 context
    if (!sp_ctx)
        sp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    // Compute the master node from the seed
    seed_to_node(current_node, seed, seed_length);

    for (unsigned int i = 0; i < path_length; i++) {
        if (path[i] & 0x80000000) {
            // Hardened derivation.
            hmac_data[0] = 0x00;
            memcpy(&hmac_data[1], current_node, 32);
        } else {
            // Non-hardened derivation.
            if (!secp256k1_ec_pubkey_create(sp_ctx, &pubkey, current_node)) {
                DEBUG_LOG("Error deriving public key from private key\n");
                return false;
            }

            pubkey_serialised_size = PUBKEY_CMP_LENGTH;
            secp256k1_ec_pubkey_serialize(sp_ctx,
                                          hmac_data,
                                          &pubkey_serialised_size,
                                          &pubkey,
                                          SECP256K1_EC_COMPRESSED);

            if (pubkey_serialised_size != PUBKEY_CMP_LENGTH) {
                DEBUG_LOG("Unexpected serialised public key size\n");
                return false;
            }
        }
        write_uint32_be(&hmac_data[33], path[i]);

        // Need to write to temp here (instead of current_node) because part of
        // current_node is used as the key.
        hmac_sha512(temp, &current_node[32], 32, hmac_data, sizeof(hmac_data));

        // First 32 bytes of temp = I_L. Compute k_i
        if (!secp256k1_ec_seckey_verify(sp_ctx, temp)) {
            DEBUG_LOG(
                "Overflow during derivation, use a different one (I_L)\n");
            return false;
        }
        parse_bigint_be(temp, 32, tempbig_a, PRIVATE_KEY_DIGITS + 1);

        if (!secp256k1_ec_seckey_verify(sp_ctx, current_node)) {
            DEBUG_LOG("Invalid key during derivation, use a different path "
                      "(invalid k_par)\n");
            return false;
        }
        parse_bigint_be(current_node, 32, tempbig_b, PRIVATE_KEY_DIGITS + 1);

        mpAdd(tempbig_a, tempbig_a, tempbig_b, PRIVATE_KEY_DIGITS + 1);
        parse_bigint_be(secp256k1_order, 32, tempbig_b, PRIVATE_KEY_DIGITS + 1);
        mpDivide(tempbig_d,
                 tempbig_c,
                 tempbig_a,
                 PRIVATE_KEY_DIGITS + 1,
                 tempbig_b,
                 PRIVATE_KEY_DIGITS + 1);
        dump_bigint_be(current_node, tempbig_c, PRIVATE_KEY_DIGITS);
        if (!secp256k1_ec_seckey_verify(sp_ctx, current_node)) {
            DEBUG_LOG(
                "Invalid derived key, use a different path (invalid k_i)\n");
            return false;
        }

        // Last 32 bytes = I_R = c_i
        memcpy(&current_node[32], &temp[32], 32);
    }
    memcpy(out, current_node, 32);
    return true; // success
}
