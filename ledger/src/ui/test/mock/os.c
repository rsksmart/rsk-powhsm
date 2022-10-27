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

#include "os.h"
#include "string.h"

/**
 * Mocks pin currently loaded to device
 */
unsigned char current_pin[10];

/**
 * APDU buffer
 */
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

unsigned int os_global_pin_check(unsigned char *pin_buffer,
                                 unsigned char pin_length) {
    return !strncmp(
        (const char *)pin_buffer, (const char *)current_pin, pin_length);
}

void explicit_bzero(void *s, size_t len) {
    memset(s, '\0', len);
    /* Compiler barrier.  */
    asm volatile("" ::: "memory");
}

void os_perso_set_pin(unsigned int identity,
                      unsigned char *pin,
                      unsigned int length) {
    // Do nothing
}

void os_global_pin_invalidate(void) {
    // Do nothing
}

void mock_set_pin(unsigned char *pin, size_t n) {
    memcpy(current_pin, pin, n);
}