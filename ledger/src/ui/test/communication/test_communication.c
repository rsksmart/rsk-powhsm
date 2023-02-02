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

void test_get_mode_bootloader() {
    printf("Test get mode from bootloader...\n");
    unsigned int rx;
    SET_APDU("\x80\x43", rx); // RSK_MODE_CMD
    assert(2 == get_mode_bootloader());
    ASSERT_APDU("\x80\x02"); // APP_MODE_BOOTLOADER
}

void test_get_mode_heartbeat() {
    printf("Test get mode from heartbeat...\n");
    unsigned int rx;
    SET_APDU("\x80\x43", rx); // RSK_MODE_CMD
    assert(2 == get_mode_heartbeat());
    ASSERT_APDU("\x80\x04"); // APP_MODE_UI_HEARTBEAT
}

void test_get_retries() {
    printf("Test get retries...\n");
    G_retries = 123;
    unsigned int rx;
    SET_APDU("\x80\x45", rx); // RSK_RETRIES
    assert(3 == get_retries());
    ASSERT_APDU("\x80\x45\x7b");
}

bool M_process_exception_callback_called = false;
void _process_exception_callback() {
    M_process_exception_callback_called = true;
}
comm_reset_cb_t process_exception_callback = &_process_exception_callback;

void setup() {
    M_process_exception_callback_called = false;
}

void test_process_exception_ok() {
    printf("Test process exception when APDU_OK...\n");
    setup();

    unsigned int tx;
    SET_APDU("\xaa\xbb\xcc", tx);

    assert(tx + 2 ==
           comm_process_exception(APDU_OK, tx, process_exception_callback));

    ASSERT_APDU("\xaa\xbb\xcc\x90\x00");
    assert(!M_process_exception_callback_called);
}

void test_process_exception_start_6_or_9() {
    unsigned short error[2] = {0x6abc, 0x9def};
    char expected[2][6] = {"\xaa\xbb\xcc\x6a\xbc", "\xaa\xbb\xcc\x9d\xef"};
    for (int i = 0; i < 2; i++) {
        printf("Test process exception when 0x%uXXX...\n",
               ((error[i] & 0xF000) >> 12));
        setup();

        unsigned int tx;
        SET_APDU("\xaa\xbb\xcc", tx);

        assert(tx + 2 == comm_process_exception(
                             error[i], tx, process_exception_callback));

        ASSERT_APDU(expected[i]);
        assert(M_process_exception_callback_called);
    }
}

void test_process_exception_start_somethingelse() {
    printf("Test process exception when not starting with 0x6 or 0x9...\n");
    setup();

    unsigned int tx;
    SET_APDU("\xaa\xbb\xcc", tx);

    assert(tx + 2 ==
           comm_process_exception(0x1234, tx, process_exception_callback));

    ASSERT_APDU("\xaa\xbb\xcc\x6a\x34");
    assert(M_process_exception_callback_called);
}

void test_process_exception_apdu_too_large() {
    printf("Test process exception when APDU too large...\n");
    setup();

    unsigned char apdu[sizeof(G_io_apdu_buffer) + 1];
    for (int i = 0; i < sizeof(apdu); i++)
        apdu[i] = 0x44;

    unsigned int tx;
    SET_APDU(apdu, tx);

    assert(2 == comm_process_exception(0x9000, tx, process_exception_callback));

    ASSERT_APDU("\x69\x83");
    assert(M_process_exception_callback_called);
}

int main() {
    test_echo();
    test_get_mode_bootloader();
    test_get_mode_heartbeat();
    test_get_retries();
    test_process_exception_ok();
    test_process_exception_start_6_or_9();
    test_process_exception_start_somethingelse();
    test_process_exception_apdu_too_large();

    return 0;
}
