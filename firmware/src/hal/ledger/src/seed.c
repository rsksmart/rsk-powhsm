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

#include "sig_utils.h"

bool seed_available() {
    return os_perso_isonboarded() == 1;
}

// Derive and init the private key for the given path.
// Upon failure, the given private key is wiped.
static bool derive_privkey(uint32_t* path,
                           uint8_t path_length,
                           volatile cx_ecfp_private_key_t* private_key) {

    volatile unsigned char private_key_data[PRIVATE_KEY_LENGTH];
    volatile bool success = false;

    BEGIN_TRY {
        TRY {
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       path,
                                       path_length,
                                       (unsigned char*)private_key_data,
                                       NULL);
            cx_ecdsa_init_private_key(CX_CURVE_256K1,
                                      (unsigned char*)private_key_data,
                                      PRIVATE_KEY_LENGTH,
                                      (cx_ecfp_private_key_t*)private_key);
            success = true;
        }
        CATCH_ALL {
            // Cleanup private key
            explicit_bzero((void*)private_key, sizeof(cx_ecfp_private_key_t));
        }
        FINALLY {
            // Cleanup private key data
            explicit_bzero((void*)private_key_data, sizeof(private_key_data));
        }
    }
    END_TRY;

    return success;
}

// Derive the public key for the given path.
// Upon failure, the given public key is wiped.
static bool derive_pubkey(uint32_t* path,
                          uint8_t path_length,
                          volatile cx_ecfp_public_key_t* public_key) {

    volatile cx_ecfp_private_key_t private_key;
    volatile bool success = false;

    BEGIN_TRY {
        TRY {
            if (!derive_privkey(path, path_length, &private_key)) {
                THROW(1);
            }
            cx_ecfp_generate_pair(CX_CURVE_256K1,
                                  (cx_ecfp_public_key_t*)public_key,
                                  (cx_ecfp_private_key_t*)&private_key,
                                  1);
            success = true;
        }
        CATCH_ALL {
            // Cleanup public key
            explicit_bzero((void*)public_key, sizeof(cx_ecfp_public_key_t));
        }
        FINALLY {
            // Cleanup private key
            explicit_bzero((void*)&private_key, sizeof(private_key));
        }
    }
    END_TRY;

    return success;
}

bool seed_derive_pubkey(uint32_t* path,
                        uint8_t path_length,
                        uint8_t* pubkey_out,
                        uint8_t* pubkey_out_length) {

    volatile cx_ecfp_public_key_t public_key;
    volatile bool success = false;

    BEGIN_TRY {
        TRY {
            if (!derive_pubkey(path, path_length, &public_key)) {
                THROW(1);
            }
            if (*pubkey_out_length < public_key.W_len) {
                THROW(1);
            }
            // Output the public key
            *pubkey_out_length = public_key.W_len;
            os_memmove(
                (void*)pubkey_out, (const void*)public_key.W, public_key.W_len);
            success = true;
        }
        CATCH_ALL {
            success = false;
        }
        FINALLY {
            // Cleanup public key
            explicit_bzero((void*)&public_key, sizeof(public_key));
        }
    }
    END_TRY;

    return success;
}

bool seed_sign(uint32_t* path,
               uint8_t path_length,
               uint8_t* hash32,
               uint8_t* sig_out,
               uint8_t* sig_out_length) {

    volatile cx_ecfp_private_key_t private_key;
    volatile cx_ecfp_public_key_t public_key;
    volatile int sig_length;
    volatile bool success = false;

    // Check the destination buffer won't be overflowed by the signature
    if (*sig_out_length < MAX_SIGNATURE_LENGTH) {
        return false;
    }

    BEGIN_TRY {
        TRY {
            if (!derive_privkey(path, path_length, &private_key)) {
                THROW(1);
            }
            sig_length = cx_ecdsa_sign((void*)&private_key,
                                       CX_RND_RFC6979 | CX_LAST,
                                       CX_SHA256,
                                       hash32,
                                       HASH_LENGTH,
                                       sig_out);
            // Cleanup private key
            explicit_bzero((void*)&private_key, sizeof(private_key));
            // Make sure the signature is sound
            if (sig_length < 0 ||
                !sig_der_is_sound(sig_out, (size_t)sig_length)) {
                THROW(1);
            }
            // Verify the signature against the public key of an independent
            // derivation
            if (!derive_pubkey(path, path_length, &public_key)) {
                THROW(1);
            }
            if (cx_ecdsa_verify((cx_ecfp_public_key_t*)&public_key,
                                CX_LAST,
                                CX_SHA256,
                                hash32,
                                HASH_LENGTH,
                                sig_out,
                                (unsigned int)sig_length) != 1) {
                THROW(1);
            }
            *sig_out_length = (uint8_t)sig_length;
            success = true;
        }
        CATCH_ALL {
            // Cleanup signature and mark failure
            explicit_bzero(sig_out, MAX_SIGNATURE_LENGTH);
            *sig_out_length = 0;
            success = false;
        }
        FINALLY {
            // Cleanup key data
            explicit_bzero((void*)&private_key, sizeof(private_key));
            explicit_bzero((void*)&public_key, sizeof(public_key));
        }
    }
    END_TRY;

    return success;
}
