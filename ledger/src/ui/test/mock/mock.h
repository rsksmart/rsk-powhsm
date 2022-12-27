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

#ifndef _MOCK_H
#define _MOCK_H

#include <assert.h>
#include <stdint.h>
#include <stddef.h>

#include "os_exceptions.h"

#define PIC(x) (x)

#define IO_APDU_BUFFER_SIZE (5 + 255)
extern unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

#define APDU_RETURN(offset) \
    ((uint16_t)(G_io_apdu_buffer[offset] << 8) | (G_io_apdu_buffer[offset + 1]))

// Empty struct used to mock data types
struct mock_struct {
    void *mock_data;
};

typedef uint8_t cx_curve_t;
typedef struct mock_struct cx_sha3_t;
typedef struct mock_struct cx_ecfp_public_key_t;
typedef struct mock_struct cx_ecfp_private_key_t;

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

// Mock bolos ux calls
unsigned int bolos_ux_mnemonic_from_data(unsigned char *in,
                                         unsigned int inLength,
                                         unsigned char *out,
                                         unsigned int outLength);

// Other mocks
void explicit_bzero(void *s, size_t len);
void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len);
unsigned char *cx_rng(unsigned char *buffer, unsigned int len);

#endif