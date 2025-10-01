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

#include <string.h>

#include "os.h"
#include "cx.h"
#include "hal/constants.h"
#include "hal/seed.h"

bool seed_available() {
    return os_perso_isonboarded() == 1;
}

bool seed_derive_pubkey(uint32_t* path,
                        uint8_t path_length,
                        uint8_t* pubkey_out,
                        uint8_t* pubkey_out_length) {

    volatile unsigned char private_key_data[PRIVATE_KEY_LENGTH];
    volatile cx_ecfp_private_key_t private_key;
    volatile cx_ecfp_public_key_t public_key;

    BEGIN_TRY {
        TRY {
            // Derive and init private key
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       path,
                                       path_length,
                                       (unsigned char*)private_key_data,
                                       NULL);
            cx_ecdsa_init_private_key(CX_CURVE_256K1,
                                      (unsigned char*)private_key_data,
                                      PRIVATE_KEY_LENGTH,
                                      (cx_ecfp_private_key_t*)&private_key);
            // Cleanup private key data
            explicit_bzero((void*)private_key_data, sizeof(private_key_data));
            // Derive public key
            cx_ecfp_generate_pair(CX_CURVE_256K1,
                                  (cx_ecfp_public_key_t*)&public_key,
                                  (cx_ecfp_private_key_t*)&private_key,
                                  1);
            // Cleanup private key
            explicit_bzero((void*)&private_key, sizeof(private_key));
            if (*pubkey_out_length < public_key.W_len) {
                THROW(1);
            }
            // Output the public key
            *pubkey_out_length = public_key.W_len;
            os_memmove(
                (void*)pubkey_out, (const void*)public_key.W, public_key.W_len);
            // Cleanup public key
            explicit_bzero((void*)&public_key, sizeof(public_key));
        }
        CATCH_ALL {
            // Cleanup key data and fail
            explicit_bzero((void*)private_key_data, sizeof(private_key_data));
            explicit_bzero((void*)&private_key, sizeof(private_key));
            explicit_bzero((void*)&public_key, sizeof(public_key));
            return false;
        }
        FINALLY {
        }
    }
    END_TRY;

    return true;
}

bool seed_sign(uint32_t* path,
               uint8_t path_length,
               uint8_t* hash32,
               uint8_t* sig_out,
               uint8_t* sig_out_length) {

    volatile unsigned char private_key_data[PRIVATE_KEY_LENGTH];
    volatile cx_ecfp_private_key_t private_key;

    // Check the destination buffer won't be overflowed by the signature
    if (*sig_out_length < MAX_SIGNATURE_LENGTH) {
        return false;
    }

    BEGIN_TRY {
        TRY {
            // Derive and init private key
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       path,
                                       path_length,
                                       (unsigned char*)private_key_data,
                                       NULL);
            cx_ecdsa_init_private_key(CX_CURVE_256K1,
                                      (unsigned char*)private_key_data,
                                      PRIVATE_KEY_LENGTH,
                                      (cx_ecfp_private_key_t*)&private_key);
            // Cleanup private key data
            explicit_bzero((void*)private_key_data, sizeof(private_key_data));
            *sig_out_length = (uint8_t)cx_ecdsa_sign((void*)&private_key,
                                                     CX_RND_RFC6979 | CX_LAST,
                                                     CX_SHA256,
                                                     hash32,
                                                     HASH_LENGTH,
                                                     sig_out);
            // Cleanup private key
            explicit_bzero((void*)&private_key, sizeof(private_key));
        }
        CATCH_ALL {
            // Cleanup key data and fail
            explicit_bzero((void*)private_key_data, sizeof(private_key_data));
            explicit_bzero((void*)&private_key, sizeof(private_key));
            return false;
        }
        FINALLY {
        }
    }
    END_TRY;

    return true;
}
