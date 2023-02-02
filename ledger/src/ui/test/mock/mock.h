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

#include <assert.h>
#include <stdint.h>
#include <stddef.h>

#include "os_exceptions.h"
#include "apdu_utils.h"
#include "defs.h"

#define PIC(x) (x)

#define PARAM_SIGNERS_FILE testing
#define CX_CURVE_256K1 33

#define CX_NONE 0
#define CX_LAST 1

#define APDU_RETURN(offset) \
    ((uint16_t)(G_io_apdu_buffer[offset] << 8) | (G_io_apdu_buffer[offset + 1]))

// Empty struct used to mock data types
struct mock_struct {
    void *mock_data;
};

typedef char cx_md_t;
typedef uint8_t cx_curve_t;

typedef struct cx_hash_s {
    unsigned char hash[HASH_LENGTH];
    int size_in_bytes;
} cx_hash_t;

typedef cx_hash_t cx_sha3_t;
typedef struct cx_ecfp_public_key_s {
    unsigned int W_len;
    unsigned char W[65];
} cx_ecfp_public_key_t;

typedef struct cx_ecfp_private_key_s {
    unsigned int d_len;
    unsigned char d[32];
} cx_ecfp_private_key_t;

// Mock os calls
unsigned int os_global_pin_retries(void);
void os_global_pin_invalidate(void);
void os_perso_wipe();
void os_perso_derive_and_set_seed(unsigned char identity,
                                  const char *prefix,
                                  unsigned int prefix_length,
                                  const char *passphrase,
                                  unsigned int passphrase_length,
                                  const char *words,
                                  unsigned int words_length);
void os_perso_finalize(void);
unsigned int os_perso_isonboarded(void);
void os_perso_set_pin(unsigned int identity,
                      unsigned char *pin,
                      unsigned int length);
unsigned int os_global_pin_check(unsigned char *pin_buffer,
                                 unsigned char pin_length);
void os_perso_derive_node_bip32(cx_curve_t curve,
                                unsigned int *path,
                                unsigned int pathLength,
                                unsigned char *privateKey,
                                unsigned char *chain);
void os_memmove(void *dst, const void *src, unsigned int length);

int cx_ecdsa_init_private_key(cx_curve_t curve,
                              unsigned char *rawkey,
                              unsigned int key_len,
                              cx_ecfp_private_key_t *key);
int cx_ecfp_generate_pair(cx_curve_t curve,
                          cx_ecfp_public_key_t *pubkey,
                          cx_ecfp_private_key_t *privkey,
                          int keepprivate);
unsigned int os_endorsement_key2_derive_sign_data(unsigned char *src,
                                                  unsigned int srcLength,
                                                  unsigned char *signature);

unsigned int os_endorsement_get_code_hash(unsigned char *buffer);

unsigned int os_endorsement_get_public_key(unsigned char index,
                                           unsigned char *buffer);

// Mock bolos ux calls
unsigned int bolos_ux_mnemonic_from_data(unsigned char *in,
                                         unsigned int inLength,
                                         unsigned char *out,
                                         unsigned int outLength);

// Other mocks
void explicit_bzero(void *s, size_t len);
void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len);
unsigned char *cx_rng(unsigned char *buffer, unsigned int len);
int cx_keccak_init(cx_sha3_t *hash, int size);
int cx_hash(cx_hash_t *hash,
            int mode,
            unsigned char *in,
            unsigned int len,
            unsigned char *out);
int cx_ecfp_init_public_key(cx_curve_t curve,
                            unsigned char *rawkey,
                            unsigned int key_len,
                            cx_ecfp_public_key_t *key);
int cx_ecdsa_verify(cx_ecfp_public_key_t *key,
                    int mode,
                    cx_md_t hashID,
                    unsigned char *hash,
                    unsigned int hash_len,
                    unsigned char *sig,
                    unsigned int sig_len);

unsigned short io_exchange(unsigned char channel_and_flags,
                           unsigned short tx_len);

#endif // __MOCK_H