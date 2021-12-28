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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "srlp.h"

#define MAX_CHUNK_SIZE 10
#define MIN(x, y) (x) <= (y) ? (x) : (y)

static int list_depth = 0;

void handle_bytearray_start(const uint16_t size) {
    printf("Starting bytearray with length = %u\n", size);
}

void handle_bytearray_chunk_as_hex(const uint8_t* bytearray, const size_t len) {
    printf(">");
    for (int i = 0; i < len; i++) {
        printf(" %02x", bytearray[i]);
    }
    putchar('\n');
}

void handle_bytearray_chunk_as_str(const uint8_t* bytearray, const size_t len) {
    unsigned char* buf = malloc(len);
    memcpy(buf, bytearray, len);
    buf[len] = 0;
    printf("Received: %s, len = %zu\n", buf, len);
}

void handle_bytearray_end() {
    printf("Finalizing bytearray\n");
}

void handle_list_start(uint16_t size) {
    ++list_depth;
    printf("Starting list with length = %u\n", size);
}

void handle_list_end() {
    --list_depth;
    printf("Finishing list\n");
}

void do_test(const char* test_name,
             unsigned char rlp[],
             size_t len,
             const rlp_callbacks_t* cbs,
             int expected_end_result) {
    printf("-------- %s --------\n", test_name);

    list_depth = 0;
    rlp_start(cbs);

    int r = 0;
    int limit = (len + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;
    for (int i = 0; i < limit; i++) {
        unsigned char* start = rlp + MAX_CHUNK_SIZE * i;
        size_t chunk_size = MIN(MAX_CHUNK_SIZE, rlp + len - start);
        if ((r = rlp_consume(start, chunk_size)) != RLP_OK) {
            break;
        }
    }

    assert(r == expected_end_result /* rlp parser returned with expected error condition */);
    if (expected_end_result == RLP_OK) {
        assert(list_depth == 0 /* rlp parser is reporting unbalanced lists */);
    } else {
        printf("Parsing finished with expected non-OK result: %d\n",
               expected_end_result);
    }
}

static const rlp_callbacks_t std_cbs = {
    handle_bytearray_start,
    handle_bytearray_chunk_as_str,
    handle_bytearray_end,
    handle_list_start,
    handle_list_end,
};

static const rlp_callbacks_t block_cbs = {
    handle_bytearray_start,
    handle_bytearray_chunk_as_hex,
    handle_bytearray_end,
    handle_list_start,
    handle_list_end,
};

void test_strs() {
    unsigned char rlp[] = {
        0x93, 0x45, 0x73, 0x74, 0x61, 0x6d, 0x6f, 0x73, 0x20, 0x74, 0x6f,
        0x64, 0x6f, 0x73, 0x20, 0x6c, 0x6f, 0x63, 0x6f, 0x73, 0x80, 0x61,
    };

    do_test("mixed strings", rlp, sizeof(rlp), &std_cbs, RLP_OK);
}

void test_long_strs_with_empty() {
    unsigned char rlp[] = {
        0xb8, 0x3d, 0x41, 0x20, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x20, 0x63,
        0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67,
        0x65, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c,
        0x64, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x68, 0x61, 0x70, 0x70, 0x65, 0x6e,
        0x20, 0x75, 0x6e, 0x64, 0x65, 0x72, 0x20, 0x6d, 0x79, 0x20, 0x77, 0x61,
        0x74, 0x63, 0x68, 0x88, 0x48, 0x69, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65,
    };

    do_test("long and short strings", rlp, sizeof(rlp), &std_cbs, RLP_OK);
}

void test_list() {
    unsigned char rlp[] = {
        0xd5, 0xc0, 0x88, 0x48, 0x69, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65,
        0x8a, 0x6d, 0x79, 0x20, 0x66, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x73,
    };

    do_test("list", rlp, sizeof(rlp), &std_cbs, RLP_OK);
}

void test_nested_list() {
    unsigned char rlp[] = {
        0xe0, 0xcb, 0x87, 0x43, 0x6f, 0x61, 0x78, 0x69, 0x61, 0x6c, 0xc2,
        0x41, 0xc0, 0x88, 0x48, 0x69, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65,
        0x8a, 0x6d, 0x79, 0x20, 0x66, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x73,
    };

    do_test(
        "list with deep nesting structure", rlp, sizeof(rlp), &std_cbs, RLP_OK);
}

void test_long_list() {
    unsigned char rlp[] = {
        0xf8, 0x42, 0xb8, 0x40, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67,
        0x20, 0x61, 0x20, 0x6c, 0x69, 0x73, 0x74, 0x20, 0x68, 0x61, 0x76, 0x69,
        0x6e, 0x67, 0x20, 0x6d, 0x6f, 0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6e,
        0x20, 0x66, 0x69, 0x66, 0x74, 0x79, 0x20, 0x66, 0x69, 0x76, 0x65, 0x20,
        0x63, 0x68, 0x61, 0x72, 0x61, 0x63, 0x74, 0x65, 0x72, 0x73, 0x20, 0x69,
        0x6e, 0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68,
    };

    do_test("long list", rlp, sizeof(rlp), &std_cbs, RLP_OK);
}

void test_long_nested_list() {
    unsigned char rlp[] = {
        0xf8, 0x4d, 0xc8, 0x87, 0x43, 0x6f, 0x61, 0x78, 0x69, 0x61, 0x6c, 0x88,
        0x48, 0x69, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x8a, 0x6d, 0x79, 0x20,
        0x66, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x73, 0xaf, 0x61, 0x20, 0x6c, 0x6f,
        0x6e, 0x67, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x20, 0x73, 0x68,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x64, 0x6f, 0x20, 0x69, 0x6e, 0x20, 0x74,
        0x68, 0x69, 0x73, 0x20, 0x70, 0x61, 0x72, 0x74, 0x69, 0x63, 0x75, 0x6c,
        0x61, 0x72, 0x20, 0x63, 0x61, 0x73, 0x65,
    };

    do_test("long list with nesting", rlp, sizeof(rlp), &std_cbs, RLP_OK);
}

void test_empty_list() {
    unsigned char rlp[] = {0xc0};
    do_test("empty list", rlp, sizeof(rlp), &std_cbs, RLP_OK);
}

void test_empty_str() {
    unsigned char rlp[] = {0x80};
    do_test("empty string", rlp, sizeof(rlp), &std_cbs, RLP_OK);
}

int read_block_file(const char* file_name, char** buffer, size_t* len) {
    FILE* f = fopen(file_name, "rb");
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    rewind(f);

    if (ferror(f)) {
        return -1;
    }

    *buffer = malloc(*len);
    fread(*buffer, *len, 1, f);
    fclose(f);

    if (ferror(f)) {
        return -1;
    }

    return 0;
}

void test_block(const char* file_name, int expected_end_result) {
    char* buffer = NULL;
    size_t size = 0;
    int r = read_block_file(file_name, &buffer, &size);
    if (r != 0) {
        printf("Error reading file: %s\n", file_name);
        assert(0);
    }

    do_test(file_name, buffer, size, &block_cbs, expected_end_result);
}

int main() {
    test_strs();
    test_long_strs_with_empty();
    test_list();
    test_nested_list();
    test_long_list();
    test_long_nested_list();
    test_empty_list();
    test_empty_str();

    test_block("resources/block-0900123.rlp", RLP_OK);
    test_block("resources/block-1234000.rlp", RLP_OK);
    test_block("resources/block-1900456.rlp", RLP_OK);
    test_block("resources/block-2221171.rlp", RLP_OK);
    test_block("resources/block-post-wasabi.rlp", RLP_OK);
    test_block("resources/block-pre-wasabi.rlp", RLP_OK);
    test_block("resources/block-fakelen.rlp", RLP_MALFORMED);
}
