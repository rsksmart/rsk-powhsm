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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "hal/communication.h"

void test_communication_init() {
    printf("Testing communication_init...\n");

    unsigned char buffer[512];
    size_t buffer_size = sizeof(buffer);

    bool result = communication_init(buffer, buffer_size);

    assert(result == true);
    assert(communication_get_msg_buffer() == buffer);
    assert(communication_get_msg_buffer_size() == buffer_size);
}

void test_communication_set_msg() {
    printf("Testing communication_set_msg_buffer...\n");

    unsigned char buffer[256];
    size_t buffer_size = sizeof(buffer);

    bool result = communication_set_msg_buffer(buffer, buffer_size);

    assert(result == true);
    assert(communication_get_msg_buffer() == buffer);
    assert(communication_get_msg_buffer_size() == buffer_size);
}

void test_communication_multiple_buffer_changes() {
    printf("Testing multiple buffer changes...\n");

    unsigned char buffer1[100];
    unsigned char buffer2[200];
    unsigned char buffer3[300];

    communication_set_msg_buffer(buffer1, sizeof(buffer1));
    assert(communication_get_msg_buffer() == buffer1);
    assert(communication_get_msg_buffer_size() == sizeof(buffer1));

    communication_set_msg_buffer(buffer2, sizeof(buffer2));
    assert(communication_get_msg_buffer() == buffer2);
    assert(communication_get_msg_buffer_size() == sizeof(buffer2));

    communication_init(buffer3, sizeof(buffer3));
    assert(communication_get_msg_buffer() == buffer3);
    assert(communication_get_msg_buffer_size() == sizeof(buffer3));
}

void test_communication_state_consistency() {
    printf("Testing state consistency across operations...\n");

    unsigned char test_buffer[256];
    size_t test_size = sizeof(test_buffer);

    communication_set_msg_buffer(test_buffer, test_size);

    unsigned char* retrieved_buffer_1 = communication_get_msg_buffer();
    size_t retrieved_size_1 = communication_get_msg_buffer_size();

    unsigned char* retrieved_buffer_2 = communication_get_msg_buffer();
    size_t retrieved_size_2 = communication_get_msg_buffer_size();

    assert(retrieved_buffer_1 == test_buffer);
    assert(retrieved_size_1 == test_size);
    assert(retrieved_buffer_1 == retrieved_buffer_2);
    assert(retrieved_size_1 == retrieved_size_2);
}

int main() {
    test_communication_init();
    test_communication_set_msg();
    test_communication_multiple_buffer_changes();
    test_communication_state_consistency();

    return 0;
}