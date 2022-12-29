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

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "apdu_utils.h"
#include "assert_utils.h"
#include "defs.h"
#include "mock.h"
#include "communication.h"

static unsigned int G_retries;

// Mock function calls
unsigned int os_global_pin_retries(void) {
    return G_retries;
}

void test_echo() {
    printf("Test echo...\n");
    unsigned int rx = 4;
    assert(4 == echo(rx));
}

void test_get_mode() {
    printf("Test get mode...\n");
    set_apdu("\x80\x43"); // RSK_MODE_CMD
    assert(2 == get_mode());
    ASSERT_APDU("\x80\x02"); // RSK_MODE_BOOTLOADER
}

void test_get_retries() {
    printf("Test get retries...\n");
    G_retries = 123;
    set_apdu("\x80\x45"); // RSK_RETRIES
    assert(3 == get_retries());
    ASSERT_APDU("\x80\x45\x7b");
}

int main() {
    test_echo();
    test_get_mode();
    test_get_retries();

    return 0;
}
