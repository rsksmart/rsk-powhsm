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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cx.h"

/**
 * Utility macros
 */
#define UNUSED(x) (void)x
#define THROW(e) return e
#define PIC(x) (x)

/**
 * Mock APDU buffer
 */
#define IO_APDU_BUFFER_SIZE 85
extern unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

/**
 * Mock context used to assert current state
 */
typedef struct {
    unsigned char global_pin[10];
    unsigned char global_seed[257];
    bool device_unlocked;
    bool device_onboarded;
    unsigned int retries;
} mock_ctx_t;

void init_mock_ctx();
void get_mock_ctx(mock_ctx_t *ctx);

/**
 * Mock calls for os API
 */
unsigned int os_global_pin_check(unsigned char *pin_buffer,
                                 unsigned char pin_length);
void os_perso_set_pin(unsigned int identity,
                      unsigned char *pin,
                      unsigned int length);
void os_global_pin_invalidate(void);
void os_memset(void *dst, unsigned char c, unsigned int length);
void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len);
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
unsigned int os_global_pin_retries(void);

/**
 * Other mocks
 */
void explicit_bzero(void *s, size_t len);
