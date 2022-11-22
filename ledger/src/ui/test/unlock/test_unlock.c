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
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "apdu.h"
#include "os.h"
#include "unlock.h"

void test_unlock() {
    printf("Test unlock...\n");

    unsigned char pin_buffer[] = "1234567a";
    unsigned int rx = 4;
    init_mock_ctx();
    for (int i = 0; i < strlen((const char *)pin_buffer); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, pin_buffer[i]);
        assert(3 == update_pin_buffer(rx));
    }

    // assert(3 == set_pin());
    mock_ctx_t mock_ctx;
    get_mock_ctx(&mock_ctx);
    assert(false == mock_ctx.device_unlocked);
    os_perso_set_pin(0, pin_buffer, strlen((const char *)pin_buffer));
    assert(3 == unlock());
    get_mock_ctx(&mock_ctx);
    assert(true == mock_ctx.device_unlocked);
    assert(1 == APDU_AT(2));
}

void test_unlock_wrong_pin() {
    printf("Test unlock (wrong pin)...\n");

    unsigned char pin_buffer[] = "1234567a";
    unsigned char wrong_pin[] = "a7654321";
    unsigned int rx = 4;
    init_mock_ctx();
    for (int i = 0; i < strlen((const char *)wrong_pin); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, wrong_pin[i]);
        assert(3 == update_pin_buffer(rx));
    }

    mock_ctx_t mock_ctx;
    get_mock_ctx(&mock_ctx);
    assert(false == mock_ctx.device_unlocked);
    os_perso_set_pin(0, pin_buffer, strlen((const char *)pin_buffer));
    assert(3 == unlock());
    get_mock_ctx(&mock_ctx);
    assert(false == mock_ctx.device_unlocked);
    assert(0 == APDU_AT(2));
}

int main() {
    test_unlock();
    test_unlock_wrong_pin();

    return 0;
}
