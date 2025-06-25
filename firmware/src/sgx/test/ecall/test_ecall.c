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
#include <assert.h>
#include <string.h>

#include "ecall.h"

// Mocks
struct {
    bool sync_try_aqcuire_lock_success;
    bool system_init_success;
    unsigned int system_process_apdu_result;
} G_mocks;

struct {
    bool sync_try_aqcuire_lock;
    bool sync_release_lock;
    bool system_init;
    bool system_finalise;
    bool system_process_apdu;
} G_called;

struct {
    struct {
        unsigned char* msg_buffer;
        size_t msg_buffer_size;
    } system_init;

    struct {
        unsigned int rx;
    } system_process_apdu;
} G_args;

bool sync_try_aqcuire_lock() {
    G_called.sync_try_aqcuire_lock = true;
    return G_mocks.sync_try_aqcuire_lock_success;
}

void sync_release_lock() {
    G_called.sync_release_lock = true;
}

bool system_init(unsigned char* msg_buffer, size_t msg_buffer_size) {
    G_called.system_init = true;
    G_args.system_init.msg_buffer = msg_buffer;
    G_args.system_init.msg_buffer_size = msg_buffer_size;
    return G_mocks.system_init_success;
}

void system_finalise() {
    G_called.system_finalise = true;
}

unsigned int system_process_apdu(unsigned int rx) {
    G_called.system_process_apdu = true;
    G_args.system_process_apdu.rx = rx;
    return G_mocks.system_process_apdu_result;
}

// Unit tests
void setup() {
    explicit_bzero(&G_mocks, sizeof(G_mocks));
    explicit_bzero(&G_called, sizeof(G_called));
    explicit_bzero(&G_args, sizeof(G_args));

    G_mocks.sync_try_aqcuire_lock_success = true;
    G_mocks.system_init_success = true;
}

void test_ecall_system_init_ok() {
    setup();
    printf("Testing ecall_system_init succeeds...\n");

    unsigned char buffer[100];
    size_t buffer_size = sizeof(buffer);
    bool result = ecall_system_init(buffer, buffer_size);

    assert(result == true);
    assert(G_called.sync_try_aqcuire_lock);
    assert(G_called.sync_release_lock);
    assert(G_called.system_init);
    assert(G_args.system_init.msg_buffer == buffer);
    assert(G_args.system_init.msg_buffer_size == buffer_size);
}

void test_ecall_system_init_ecall_fails() {
    setup();
    printf("Testing ecall_system_init when system_init fails...\n");

    unsigned char buffer[100];
    size_t buffer_size = sizeof(buffer);
    G_mocks.system_init_success = false;

    bool result = ecall_system_init(buffer, buffer_size);

    assert(result == false);
    assert(G_called.sync_try_aqcuire_lock);
    assert(G_called.sync_release_lock);
    assert(G_called.system_init);
    assert(G_args.system_init.msg_buffer == buffer);
    assert(G_args.system_init.msg_buffer_size == buffer_size);
}

void test_ecall_system_init_lock_acquisition_fails() {
    setup();
    printf("Testing ecall_system_init when lock acquisition fails...\n");

    unsigned char buffer[100];
    size_t buffer_size = sizeof(buffer);
    G_mocks.sync_try_aqcuire_lock_success = false;

    bool result = ecall_system_init(buffer, buffer_size);

    assert(result == false);
    assert(G_called.sync_try_aqcuire_lock);
    assert(!G_called.sync_release_lock);
    assert(!G_called.system_init);
}

void test_ecall_system_finalise_ok() {
    setup();
    printf("Testing ecall_system_finalise succeeds...\n");

    ecall_system_finalise();

    assert(G_called.sync_try_aqcuire_lock);
    assert(G_called.sync_release_lock);
    assert(G_called.system_finalise);
}

void test_ecall_system_finalise_lock_acquisition_fails() {
    setup();
    printf("Testing ecall_system_finalise when lock acquisition fails...\n");

    G_mocks.sync_try_aqcuire_lock_success = false;

    ecall_system_finalise();

    assert(G_called.sync_try_aqcuire_lock);
    assert(!G_called.sync_release_lock);
    assert(!G_called.system_finalise);
}

void test_ecall_system_process_apdu_ok() {
    setup();
    printf("Test ecall_system_process_apdu succeeds...\n");

    unsigned int rx = 123;
    G_mocks.system_process_apdu_result = 456;

    unsigned int result = ecall_system_process_apdu(rx);

    assert(result == 456);
    assert(G_called.sync_try_aqcuire_lock);
    assert(G_called.sync_release_lock);
    assert(G_called.system_process_apdu);
    assert(G_args.system_process_apdu.rx == 123);
}

void test_ecall_system_process_apdu_lock_acquisition_fails() {
    setup();
    printf("Testing ecall_system_process_apdu lock acquisition failure...\n");

    unsigned int rx = 123;
    G_mocks.system_process_apdu_result = 456;
    G_mocks.sync_try_aqcuire_lock_success = false;

    unsigned int result = ecall_system_process_apdu(rx);

    assert(result == 0);
    assert(G_called.sync_try_aqcuire_lock);
    assert(!G_called.sync_release_lock);
    assert(!G_called.system_process_apdu);
}

int main() {
    test_ecall_system_init_ok();
    test_ecall_system_init_ecall_fails();
    test_ecall_system_init_lock_acquisition_fails();

    test_ecall_system_finalise_ok();
    test_ecall_system_finalise_lock_acquisition_fails();

    test_ecall_system_process_apdu_ok();
    test_ecall_system_process_apdu_lock_acquisition_fails();

    return 0;
}
