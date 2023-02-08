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
#include <stdbool.h>
#include <string.h>

#include "trie.h"
#include "hex_reader.h"

trie_ctx_t context;

void test_init() {
    printf("Testing context initialization...\n");

    trie_init(&context, (trie_cb_t)123, 456);

    assert(context.state == TRIE_ST_FLAGS);
    assert(context.callback == (trie_cb_t)123);
    assert(context.remaining_bytes == 456);
}

void consume_in_chunks(uint8_t* buffer, size_t size, uint8_t chunk_size) {
    for (size_t i = 0; i < size; i += chunk_size) {
        uint8_t this_chunk = i + chunk_size >= size ? size - i : chunk_size;
        uint8_t consumed = trie_consume(buffer + i, this_chunk);
        if (trie_result() >= 0)
            assert(consumed == this_chunk);
    }
}

uint8_t* test_raw_complete_raw;
size_t test_raw_complete_offset;
void callback_test_raw_complete(const trie_cb_event_t event) {
    memcpy(test_raw_complete_raw + test_raw_complete_offset,
           context.raw,
           context.raw_size);
    test_raw_complete_offset += context.raw_size;
}

void test_raw_complete(const char* node_hex) {
    printf("Testing raw callbacks for '%s' should be able to "
           "reconstruct the original node...\n",
           node_hex);

    size_t size = strlen(node_hex) / 2;
    unsigned char* buffer = malloc(size);
    assert(read_hex(node_hex, strlen(node_hex), buffer) == size);

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        test_raw_complete_offset = 0;
        test_raw_complete_raw = malloc(size);
        trie_init(&context, &callback_test_raw_complete, size);
        consume_in_chunks(buffer, size, chunk);
        assert(trie_result() == TRIE_ST_DONE);
        assert(size == test_raw_complete_offset);
        assert(!memcmp(buffer, test_raw_complete_raw, size));
        free(test_raw_complete_raw);
    }

    free(buffer);
}

void test_flag_detection() {
    printf("Testing flag detection...\n");
    assert(TRIE_FG_VERSION(0b00000000) == 0);
    assert(TRIE_FG_VERSION(0b01000000) == 1);
    assert(TRIE_FG_VERSION(0b10000000) == 2);
    assert(TRIE_FG_VERSION(0b11000000) == 3);
    assert(!TRIE_FG_SHARED_PREFIX_PRESENT(0b11101111));
    assert(TRIE_FG_SHARED_PREFIX_PRESENT(0b00010000));
    assert(!TRIE_FG_HAS_LONG_VALUE(0b11011111));
    assert(TRIE_FG_HAS_LONG_VALUE(0b00100000));
    assert(!TRIE_FG_NODE_PRESENT_LEFT(0b11110111));
    assert(TRIE_FG_NODE_PRESENT_LEFT(0b00001000));
    assert(!TRIE_FG_NODE_PRESENT_RIGHT(0b11111011));
    assert(TRIE_FG_NODE_PRESENT_RIGHT(0b00000100));
    assert(!TRIE_FG_NODE_IS_EMBEDDED_LEFT(0b11111101));
    assert(TRIE_FG_NODE_IS_EMBEDDED_LEFT(0b00000010));
    assert(!TRIE_FG_NODE_IS_EMBEDDED_RIGHT(0b11111110));
    assert(TRIE_FG_NODE_IS_EMBEDDED_RIGHT(0b00000001));
}

uint8_t* test_shared_prefix_prefix;
size_t test_shared_prefix_offset;
uint32_t test_shared_prefix_expected_bit_length;
uint8_t test_shared_prefix_ok;
void callback_test_shared_prefix(const trie_cb_event_t event) {
    switch (event) {
    case TRIE_EV_SHARED_PREFIX_LENGTH:
        assert(test_shared_prefix_expected_bit_length == context.length);
        test_shared_prefix_ok++;
        break;
    case TRIE_EV_SHARED_PREFIX:
        memcpy(test_shared_prefix_prefix + test_shared_prefix_offset,
               context.raw,
               context.raw_size);
        test_shared_prefix_offset += context.raw_size;
        break;
    }
}

void test_shared_prefix(const char* node_hex,
                        uint32_t expected_bit_length,
                        const char* expected_prefix_hex) {
    printf("Testing shared prefix for '%s' should be %u bits and '%s'...\n",
           node_hex,
           expected_bit_length,
           expected_prefix_hex);

    size_t size = strlen(node_hex) / 2;
    unsigned char* buffer = malloc(size);
    assert(read_hex(node_hex, strlen(node_hex), buffer) == size);

    size_t expected_prefix_size = strlen(expected_prefix_hex) / 2;
    unsigned char* expected_prefix = malloc(expected_prefix_size);
    assert(read_hex(expected_prefix_hex,
                    strlen(expected_prefix_hex),
                    expected_prefix) == expected_prefix_size);

    test_shared_prefix_expected_bit_length = expected_bit_length;

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        test_shared_prefix_ok = 0;
        test_shared_prefix_offset = 0;
        test_shared_prefix_prefix = malloc(expected_prefix_size);
        trie_init(&context, &callback_test_shared_prefix, size);
        consume_in_chunks(buffer, size, chunk);
        assert(trie_result() == TRIE_ST_DONE);
        assert(test_shared_prefix_ok == 1);
        assert(expected_prefix_size == test_shared_prefix_offset);
        assert(!memcmp(
            expected_prefix, test_shared_prefix_prefix, expected_prefix_size));
        free(test_shared_prefix_prefix);
    }

    free(buffer);
}

uint8_t test_no_shared_prefix_fail;
void callback_test_no_shared_prefix(const trie_cb_event_t event) {
    switch (event) {
    case TRIE_EV_SHARED_PREFIX_LENGTH:
    case TRIE_EV_SHARED_PREFIX:
        test_no_shared_prefix_fail++;
        break;
    }
}

void test_no_shared_prefix(const char* node_hex) {
    printf("Testing no shared prefix for '%s'...\n", node_hex);

    size_t size = strlen(node_hex) / 2;
    unsigned char* buffer = malloc(size);
    assert(read_hex(node_hex, strlen(node_hex), buffer) == size);

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        test_no_shared_prefix_fail = 0;
        trie_init(&context, &callback_test_no_shared_prefix, size);
        consume_in_chunks(buffer, size, chunk);
        assert(trie_result() == TRIE_ST_DONE);
        assert(test_no_shared_prefix_fail == 0);
    }

    free(buffer);
}

uint8_t test_lr_nodes_ok;
size_t test_lr_nodes_left_offset, test_lr_nodes_right_offset;
size_t test_lr_nodes_expected_left_size, test_lr_nodes_expected_right_size;
uint8_t *test_lr_nodes_left, *test_lr_nodes_right;
bool test_lr_nodes_expected_l_emb, test_lr_nodes_expected_r_emb;
uint32_t test_lr_nodes_expected_cs;
void callback_test_lr_nodes(const trie_cb_event_t event) {
    switch (event) {
    case TRIE_EV_LEFT_NODE_START:
    case TRIE_EV_LEFT_NODE_END:
        printf("en el evento %u\n", event);
        assert(!test_lr_nodes_expected_l_emb);
        test_lr_nodes_ok++;
        break;
    case TRIE_EV_RIGHT_NODE_START:
    case TRIE_EV_RIGHT_NODE_END:
        assert(!test_lr_nodes_expected_r_emb);
        test_lr_nodes_ok++;
        break;
    case TRIE_EV_LEFT_NODE_DATA:
        assert(!test_lr_nodes_expected_l_emb);
        memcpy(test_lr_nodes_left + test_lr_nodes_left_offset,
               context.raw,
               context.raw_size);
        test_lr_nodes_left_offset += context.raw_size;
        break;
    case TRIE_EV_RIGHT_NODE_DATA:
        assert(!test_lr_nodes_expected_r_emb);
        memcpy(test_lr_nodes_right + test_lr_nodes_right_offset,
               context.raw,
               context.raw_size);
        test_lr_nodes_right_offset += context.raw_size;
        break;
    case TRIE_EV_LEFT_NODE_EMBEDDED_START:
        assert(test_lr_nodes_expected_l_emb);
        assert(context.length == test_lr_nodes_expected_left_size);
        test_lr_nodes_ok++;
        break;
    case TRIE_EV_LEFT_NODE_EMBEDDED_DATA:
        assert(test_lr_nodes_expected_l_emb);
        memcpy(test_lr_nodes_left + test_lr_nodes_left_offset,
               context.raw,
               context.raw_size);
        test_lr_nodes_left_offset += context.raw_size;
        break;
    case TRIE_EV_RIGHT_NODE_EMBEDDED_START:
        assert(test_lr_nodes_expected_r_emb);
        assert(context.length == test_lr_nodes_expected_right_size);
        test_lr_nodes_ok++;
        break;
    case TRIE_EV_RIGHT_NODE_EMBEDDED_DATA:
        assert(test_lr_nodes_expected_r_emb);
        memcpy(test_lr_nodes_right + test_lr_nodes_right_offset,
               context.raw,
               context.raw_size);
        test_lr_nodes_right_offset += context.raw_size;
        break;
    case TRIE_EV_LEFT_NODE_EMBEDDED_END:
        assert(test_lr_nodes_expected_l_emb);
        test_lr_nodes_ok++;
        break;
    case TRIE_EV_RIGHT_NODE_EMBEDDED_END:
        assert(test_lr_nodes_expected_r_emb);
        test_lr_nodes_ok++;
        break;
    case TRIE_EV_CHILDREN_SIZE:
        assert(test_lr_nodes_expected_cs == context.children_size);
        test_lr_nodes_ok++;
        break;
    }
}

void test_lr_nodes(const char* node_hex,
                   bool l_emb,
                   const char* left_hex,
                   bool r_emb,
                   const char* right_hex,
                   uint32_t cs) {
    printf("Testing L&R nodes, children size for '%s'...\n", node_hex);

    size_t size = strlen(node_hex) / 2;
    unsigned char* buffer = malloc(size);
    assert(read_hex(node_hex, strlen(node_hex), buffer) == size);

    size_t left_size, right_size;
    unsigned char *left, *right;

    if (left_hex) {
        left_size = strlen(left_hex) / 2;
        left = malloc(left_size);
        assert(read_hex(left_hex, strlen(left_hex), left) == left_size);
        test_lr_nodes_expected_left_size = left_size;
    }

    if (right_hex) {
        right_size = strlen(right_hex) / 2;
        right = malloc(right_size);
        assert(read_hex(right_hex, strlen(right_hex), right) == right_size);
        test_lr_nodes_expected_right_size = right_size;
    }

    test_lr_nodes_expected_l_emb = l_emb;
    test_lr_nodes_expected_r_emb = r_emb;
    test_lr_nodes_expected_cs = cs;

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        test_lr_nodes_ok = 0;
        test_lr_nodes_left_offset = 0;
        test_lr_nodes_right_offset = 0;
        test_lr_nodes_left = malloc(left_size);
        test_lr_nodes_right = malloc(right_size);
        trie_init(&context, &callback_test_lr_nodes, size);
        consume_in_chunks(buffer, size, chunk);
        assert(trie_result() == TRIE_ST_DONE);
        assert(test_lr_nodes_ok ==
               ((cs > 0 ? 1 : 0) + (left_hex ? 2 : 0) + (right_hex ? 2 : 0)));
        if (left_hex) {
            assert(left_size == test_lr_nodes_left_offset);
            assert(!memcmp(left, test_lr_nodes_left, left_size));
        }
        if (right_hex) {
            assert(right_size == test_lr_nodes_right_offset);
            assert(!memcmp(right, test_lr_nodes_right, right_size));
        }
        free(test_lr_nodes_left);
        free(test_lr_nodes_right);
    }

    if (left_hex)
        free(left);
    if (right_hex)
        free(right);

    free(buffer);
}

uint8_t test_value_ok;
size_t test_value_offset;
uint8_t* test_value_value;
bool test_value_expected_has_long;
uint32_t test_value_expected_value_length;
void callback_test_value(const trie_cb_event_t event) {
    switch (event) {
    case TRIE_EV_VALUE_HASH_START:
        test_value_ok |= 1;
        break;
    case TRIE_EV_VALUE_HASH_DATA:
        test_value_ok |= 2;
        assert(test_value_expected_has_long);
        memcpy(test_value_value + test_value_offset,
               context.raw,
               context.raw_size);
        test_value_offset += context.raw_size;
        break;
    case TRIE_EV_VALUE_HASH_END:
        test_value_ok |= 4;
        break;
    case TRIE_EV_VALUE_START:
        test_value_ok |= 8;
        assert(!test_value_expected_has_long);
        assert(test_value_expected_value_length == context.length);
        break;
    case TRIE_EV_VALUE_DATA:
        test_value_ok |= 16;
        assert(!test_value_expected_has_long);
        memcpy(test_value_value + test_value_offset,
               context.raw,
               context.raw_size);
        test_value_offset += context.raw_size;
        break;
    case TRIE_EV_VALUE_END:
        assert(!test_value_expected_has_long);
        test_value_ok |= 32;
        break;
    }
}

void test_value(const char* node_hex,
                bool has_long,
                const char* value_hex,
                uint32_t value_length) {
    printf("Testing value for '%s'...\n", node_hex);

    size_t size = strlen(node_hex) / 2;
    unsigned char* buffer = malloc(size);
    assert(read_hex(node_hex, strlen(node_hex), buffer) == size);

    size_t value_size = strlen(value_hex) / 2;
    unsigned char* value = malloc(value_size);
    assert(read_hex(value_hex, strlen(value_hex), value) == value_size);

    test_value_expected_has_long = has_long;
    test_value_expected_value_length = value_length;

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        test_value_value = malloc(value_size);
        test_value_offset = 0;
        test_value_ok = 0;
        trie_init(&context, &callback_test_value, size);
        consume_in_chunks(buffer, size, chunk);
        assert(trie_result() == TRIE_ST_DONE);
        assert(value_size == test_value_offset);
        assert(!memcmp(value, test_value_value, value_size));
        assert(test_value_ok ==
               (has_long ? (1 + 2 + 4) : (value_size > 0 ? (8 + 16 + 32) : 0)));
        free(test_value_value);
    }

    free(value);
    free(buffer);
}

void callback_test_error(const trie_cb_event_t event) {
}
void test_error(const char* node_hex) {
    printf("Testing '%s' should yield an error...", node_hex);

    uint32_t size = strlen(node_hex) / 2;
    unsigned char* node = malloc(size);
    assert(read_hex(node_hex, strlen(node_hex), node) == size);

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        trie_init(&context, &callback_test_error, size);
        consume_in_chunks(node, size, chunk);
        assert(trie_result() < 0);
    }

    free(node);
}

int main() {
    test_init();

    test_raw_complete("70060012ad32877a15a35716ddfa2d1fc51942b3f6edf747a58c39a2"
                      "aebd185b9618f1000203");
    test_raw_complete("4f2670060290077e20feb9ffb4ed5abdcb42dc4e034fe2496cca6b38"
                      "fd479dcd598cfa151b0003882670060012ad32877a15a35716ddfa2d"
                      "1fc51942b3f6edf747a58c39a2aebd185b9618f1000203fdd705");
    test_raw_complete("4daaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddd"
                      "dddddddddd2670060012ad32877a15a35716ddfa2d1fc51942b3f6ed"
                      "f747a58c39a2aebd185b9618f1000203fdd705");
    test_raw_complete("4e2670060290077e20feb9ffb4ed5abdcb42dc4e034fe2496cca6b38"
                      "fd479dcd598cfa151b00038811111111111111112222222222222222"
                      "33333333333333334444444444444444fdd705");
    test_raw_complete("70fffd2101"
                      "88aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                      "aaaaaaaaaaaaaaaa9912ad32877a15a35716ddfa2d1fc51942b3f6ed"
                      "f747a58c39a2aebd185b9618f1000203");
    test_raw_complete("70ff28001122334412ad32877a15a35716ddfa2d1fc51942b3f6edf"
                      "747a58c39a2aebd185b9618f1000203");
    test_raw_complete("4f2870060290077e20feb9ffb4ed5abdcb42dc4e034fe2496cca6b3"
                      "8fd479dcd598cfa151b00038811222670060012ad32877a15a35716"
                      "ddfa2d1fc51942b3f6edf747a58c39a2aebd185b9618f1000203fdd"
                      "705");

    test_flag_detection();

    test_shared_prefix(
        "70060012ad32877a15a35716ddfa2d1fc51942b3f6edf747a58c39a2aebd1"
        "85b9618f1000203",
        7,
        "00");
    test_shared_prefix("703200112233445566778899aabbccddeeff0011223344556612ad3"
                       "2877a15a35716ddfa2d1fc51942b3f6edf747a58c39a2aebd1"
                       "85b9618f1000203",
                       178,
                       "00112233445566778899aabbccddeeff00112233445566");
    test_shared_prefix("70ff28001122334412ad32877a15a35716ddfa2d1fc51942b3f6edf"
                       "747a58c39a2aebd1"
                       "85b9618f1000203",
                       40,
                       "0011223344");
    test_shared_prefix(
        "70fffd2101"
        "88aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaa9912ad32877a15a35716ddfa2d1fc51942b3f6ed"
        "f747a58c39a2aebd185b9618f1000203",
        289,
        "88aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaa99");
    test_shared_prefix(
        "70fffe15000000aabbcc12ad32877a15a35716ddfa2d1fc51942b3f6ed"
        "f747a58c39a2aebd185b9618f1000203",
        21,
        "aabbcc");
    test_shared_prefix(
        "70ffff1900000000000000aabbccdd12ad32877a15a35716ddfa2d1fc5"
        "1942b3f6edf747a58c39a2aebd185b9618f1000203",
        25,
        "aabbccdd");

    test_no_shared_prefix("6012ad32877a15a35716ddfa2d1fc51942b3f6edf747a58c39a2"
                          "aebd185b9618f1000203");
    test_no_shared_prefix(
        "4f2670060290077e20feb9ffb4ed5abdcb42dc4e034fe2496cca6b38fd479dcd598cfa"
        "151b0003882670060012ad32877a15a35716ddfa2d1fc51942b3f6edf747a58c39a2ae"
        "bd185b9618f1000203fdd705");

    test_lr_nodes(
        "4f2870060290077e20feb9ffb4ed5abdcb42dc4e034fe2496cca6b38fd"
        "479dcd598cfa151b00038811222670060012ad32877a15a35716ddfa2d1fc5"
        "1942b3f6edf747a58c39a2aebd185b9618f1000203fdd705",
        true,
        "70060290077e20feb9ffb4ed5abdcb42dc4e034fe2496cca6b38fd479dcd598cfa151b"
        "0003881122",
        true,
        "70060012ad32877a15a35716ddfa2d1fc51942b3f6edf747a58c39a2aebd185b9618f1"
        "000203",
        0x05d7);
    test_lr_nodes(
        "4d11aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa22"
        "2670060012ad32877a15a35716ddfa2d1fc51942b3f6edf747a58c39a2aebd185b"
        "9618f100020316",
        false,
        "11aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa22",
        true,
        "70060012ad32877a15a35716ddfa2d1fc51942b3f6edf747a58c39a2aebd185b9618f1"
        "000203",
        0x16);
    test_lr_nodes(
        "4e2870060290077e20feb9ffb4ed5abdcb42dc4e034fe2496cca6b38fd"
        "479dcd598cfa151b000388112299bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb77feaabbccdd",
        true,
        "70060290077e20feb9ffb4ed5abdcb42dc4e034fe2496cca6b38fd479dcd598cfa151b"
        "0003881122",
        false,
        "99bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb77",
        0xddccbbaa);
    test_lr_nodes(
        "5c05bb66cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc33"
        "99bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb77"
        "ffaabbccdd00000000",
        false,
        "66cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc33",
        false,
        "99bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb77",
        0xddccbbaa);
    test_lr_nodes(
        "5805bb99bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb77"
        "fe77889900",
        false,
        "99bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb77",
        0,
        0,
        0x998877);
    test_lr_nodes(
        "5405bb99bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb77"
        "fe77889900",
        0,
        0,
        false,
        "99bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb77",
        0x998877);
    test_lr_nodes("5005bbaabb", 0, 0, 0, 0, 0);
    test_lr_nodes(
        "7005bb55eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        "eeeeeee44010203",
        0,
        0,
        0,
        0,
        0);

    test_value(
        "70060012ad32877a15a35716ddfa2d1fc51942b3f6edf747a58c39a2aebd185b"
        "9618f1000203",
        true,
        "12ad32877a15a35716ddfa2d1fc51942b3f6edf747a58c39a2aebd185b9618f1",
        0x000203);
    test_value(
        "6044aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa551122"
        "33",
        true,
        "44aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa55",
        0x112233);
    test_value("40112233445566778899", false, "112233445566778899", 0);
    test_value("40eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
               "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
               false,
               "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
               "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
               0);
    test_value(
        "48aabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcc02",
        false,
        "",
        0);
    test_value(
        "44aabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcc02",
        false,
        "",
        0);
    test_value("4a05aabbccddee06", false, "", 0);
    test_value("4505aabbccddee06", false, "", 0);

    test_error("50ffff0000000001");
    test_error("40");
    test_error("4a051122334455ff0000000001");
    test_error("45051122334455ff0000000001");
    test_error("4811ccccccccccccccccccccccccccccccccccccccccccccccccccccc"
               "ccccccc22ff0000000001");
    test_error("4411ccccccccccccccccccccccccccccccccccccccccccccccccccccc"
               "ccccccc22ff0000000001");

    return 0;
}
