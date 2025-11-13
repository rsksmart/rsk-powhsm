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

#ifndef __MOCK_H
#define __MOCK_H

#include <stdint.h>
#include <stddef.h>

#include "exc.h"

// General definitions
#define CX_RND_RFC6979 (3 << 9)
#define CX_LAST (1 << 0)

void os_memmove(void *dst, const void *src, unsigned int length);

void os_sched_exit(unsigned int exit_code);

// Endorsement functions
unsigned int os_endorsement_key2_derive_sign_data(unsigned char *src,
                                                  unsigned int srcLength,
                                                  unsigned char *signature);

unsigned int os_endorsement_get_code_hash(unsigned char *buffer);

unsigned int os_endorsement_get_public_key(unsigned char index,
                                           unsigned char *buffer);

// Hash type definitions and constants
#define HASH_LENGTH 32

typedef struct cx_hash_s {
    unsigned char hash[HASH_LENGTH];
    int size_in_bytes;
} cx_hash_t;

typedef cx_hash_t cx_sha256_t;
typedef cx_hash_t cx_sha3_t;

// Hash functions
int cx_sha256_init(cx_sha256_t *hash);
int cx_keccak_init(cx_sha3_t *hash, int size);
int cx_hash(cx_hash_t *hash,
            int mode,
            unsigned char *in,
            unsigned int len,
            unsigned char *out);

// NVM functions
void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len);

// Seed type definitions and constants
enum cx_md_e {
    CX_SHA256 = 123,
};
typedef enum cx_md_e cx_md_t;

enum cx_curve_e {
    CX_CURVE_SECP256K1 = 456,
    CX_CURVE_256K1 = CX_CURVE_SECP256K1,
};
typedef enum cx_curve_e cx_curve_t;

struct cx_ecfp_public_key_s {
    cx_curve_t curve;
    unsigned int W_len;
    unsigned char W[65];
};

struct cx_ecfp_private_key_s {
    cx_curve_t curve;
    unsigned int d_len;
    unsigned char d[32];
};

typedef struct cx_ecfp_public_key_s cx_ecfp_public_key_t;
typedef struct cx_ecfp_private_key_s cx_ecfp_private_key_t;

// Seed-related functions
unsigned int os_perso_isonboarded();

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

#endif // __MOCK_H
