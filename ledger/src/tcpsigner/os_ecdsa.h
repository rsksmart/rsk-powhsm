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

#ifndef __SIMULATOR_OS_ECDSA_H
#define __SIMULATOR_OS_ECDSA_H

#include <stddef.h>
#include <stdbool.h>

// TODO: in the future, actual enum definitions for these
// two types could be copied from the nanos SDK and used
// to e.g. verify calls are made with expected parameters.
// Ignore for now, define as char.
#define CX_CURVE_256K1 0
#define CX_RND_RFC6979 0
#define CX_LAST 0
#define CX_SHA256 0
typedef char cx_md_t;
typedef char cx_curve_t;

typedef struct cx_ecfp_private_key_s {
    unsigned char K[32];
} cx_ecfp_private_key_t;

typedef struct cx_ecfp_public_key_s {
    unsigned int W_len;
    unsigned char W[65];
} cx_ecfp_public_key_t;

void os_ecdsa_initialize();

void os_perso_derive_node_bip32(cx_curve_t curve,
                                unsigned int *path,
                                unsigned int pathLength,
                                unsigned char *privateKey,
                                unsigned char *chain);

int cx_ecdsa_init_private_key(cx_curve_t curve,
                              unsigned char *rawkey,
                              unsigned int key_len,
                              cx_ecfp_private_key_t *key);

int cx_ecfp_generate_pair(cx_curve_t curve,
                          cx_ecfp_public_key_t *pubkey,
                          cx_ecfp_private_key_t *privkey,
                          int keepprivate);

int cx_ecdsa_sign(cx_ecfp_private_key_t *key,
                  int mode,
                  cx_md_t hashID,
                  unsigned char *hash,
                  unsigned int hash_len,
                  unsigned char *sig);

size_t hsmsim_helper_getpubkey(const unsigned char *key,
                               unsigned char *dest,
                               size_t dest_size,
                               bool compressed);

size_t hsmsim_helper_tweak_sign(const unsigned char *key,
                                const unsigned char *tweak,
                                const unsigned char *hash,
                                unsigned char *sig);

#endif // __SIMULATOR_OS_ECDSA_H
