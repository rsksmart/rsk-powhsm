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

#include <stddef.h>
#include <stdint.h>
#include "cx.h"

/**
 * Utility macros
 */
#define UNUSED(x) (void)x
#define THROW(e) return e
#define PIC(x) (x)

typedef enum {
    MOCK_FUNC_OS_GLOBAL_PIN_CHECK,
    MOCK_FUNC_OS_PERSO_SET_PIN,
    MOCK_FUNC_OS_GLOBAL_PIN_INVALIDATE,
    MOCK_FUNC_OS_MEMSET,
    MOCK_FUNC_NVM_WRITE,
    MOCK_FUNC_OS_PERSO_WIPE,
    MOCK_FUNC_OS_PERSO_DERIVE_AND_SET_SEED,
    MOCK_FUNC_OS_PERSO_FINALIZE,
    MOCK_FUNC_OS_PERSO_ISONBOARDED,
    MOCK_FUNC_BOLOS_UX_MNEMONIC_FROM_DATA,
    MOCK_FUNC_OS_GLOBAL_PIN_RETRIES,
} mock_func_call_t;

/**
 * Mock APDU buffer
 */
#define IO_APDU_BUFFER_SIZE 85
extern unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

/**
 * Helper functions to handle call list
 */
void reset_mock_func_call_list();
void add_mock_func_call(mock_func_call_t func);
mock_func_call_t get_mock_func_call(int order);
int get_mock_func_call_count();

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
void mock_set_pin(unsigned char *pin, size_t n);
