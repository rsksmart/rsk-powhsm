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

#include "btctx.h"
#include "hex_reader.h"

btctx_ctx_t context;

int read_hex_file(const char* file_name, unsigned char** buffer, size_t* len) {
    FILE* f = fopen(file_name, "rb");
    if (!f) {
        return -1;
    }
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    rewind(f);

    if (ferror(f) || *len % 2 != 0) {
        return -1;
    }

    *buffer = malloc(*len / 2);
    *len = *len / 2;
    char tmp[2];
    for (size_t off = 0; off < *len; off++) {
        fread(tmp, 2, 1, f);
        read_hex(tmp, 2, *buffer + off);
    }
    fclose(f);

    if (ferror(f)) {
        return -1;
    }

    return 0;
}

bool test_version_ok;
uint32_t test_version_expected_version;
void callback_test_version(const btctx_cb_event_t event) {
    if (event == BTCTX_EV_VERSION) {
        assert(context.parsed.version == test_version_expected_version);
        test_version_ok = true;
    }
}

void test_init() {
    printf("Testing context initialization...\n");

    btctx_init(&context, &callback_test_version);

    assert(context.state == BTCTX_ST_VERSION);
    assert(context.callback == &callback_test_version);
    assert(context.offset == 0);
}

void consume_in_chunks(uint8_t* buffer, size_t size, uint8_t chunk_size) {
    for (size_t i = 0; i < size; i += chunk_size) {
        uint8_t this_chunk = i + chunk_size >= size ? size - i : chunk_size;
        uint8_t consumed = btctx_consume(buffer + i, this_chunk);
        if (btctx_result() >= 0)
            assert(consumed == this_chunk);
    }
}

void test_version(const char* file_name, uint32_t expected_version) {
    printf("Testing version for '%s' should be %d...\n",
           file_name,
           expected_version);
    test_version_expected_version = expected_version;

    unsigned char* buffer = NULL;
    size_t size = 0;
    int r = read_hex_file(file_name, &buffer, &size);
    if (r != 0) {
        printf("Error reading hex file: %s\n", file_name);
        assert(0);
    }

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        test_version_ok = false;
        btctx_init(&context, &callback_test_version);
        consume_in_chunks(buffer, size, chunk);
        assert(btctx_result() == BTCTX_ST_DONE);
        assert(test_version_ok);
    }

    free(buffer);
}

uint8_t test_vin_vout_ok;
uint32_t test_vin_vout_expected_vin_count;
uint32_t test_vin_vout_expected_vout_count;
void callback_test_vin_vout(const btctx_cb_event_t event) {
    if (event == BTCTX_EV_VIN_COUNT) {
        assert(context.parsed.varint.value == test_vin_vout_expected_vin_count);
        test_vin_vout_ok++;
    }

    if (event == BTCTX_EV_VOUT_COUNT) {
        assert(context.parsed.varint.value ==
               test_vin_vout_expected_vout_count);
        test_vin_vout_ok++;
    }
}

void test_vin_vout_counts(const char* file_name,
                          uint32_t expected_vin_count,
                          uint32_t expected_vout_count) {
    printf("Testing vin & vout counts for '%s' should be %d & %d...\n",
           file_name,
           expected_vin_count,
           expected_vout_count);
    test_vin_vout_expected_vin_count = expected_vin_count;
    test_vin_vout_expected_vout_count = expected_vout_count;

    unsigned char* buffer = NULL;
    size_t size = 0;
    int r = read_hex_file(file_name, &buffer, &size);
    if (r != 0) {
        printf("Error reading hex file: %s\n", file_name);
        assert(0);
    }

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        test_vin_vout_ok = 0;
        btctx_init(&context, &callback_test_vin_vout);
        consume_in_chunks(buffer, size, chunk);
        assert(btctx_result() == BTCTX_ST_DONE);
        assert(test_vin_vout_ok == 2);
    }

    free(buffer);
}

uint32_t test_vin_prevtx_vin_index;
uint8_t test_vin_prevtx_ok;
uint8_t* test_vin_prevtx_expected_txhash;
uint32_t test_vin_prevtx_expected_txindex;
uint32_t test_vin_prevtx_expected_seqno;
uint8_t test_vin_prevtx_txhash[32];
uint8_t test_vin_prevtx_txhash_offset;
void callback_test_vin_prevtx(const btctx_cb_event_t event) {
    switch (event) {
    case BTCTX_EV_VIN_TXH_START:
        if (context.inout_current == test_vin_prevtx_vin_index)
            test_vin_prevtx_txhash_offset = 0;
        break;
    case BTCTX_EV_VIN_TXH_DATA:
        if (context.inout_current == test_vin_prevtx_vin_index)
            test_vin_prevtx_txhash[31 - (test_vin_prevtx_txhash_offset++)] =
                context.parsed.value;
        break;
    case BTCTX_EV_VIN_TXH_END:
        if (context.inout_current == test_vin_prevtx_vin_index) {
            assert(test_vin_prevtx_txhash_offset == 32);
            assert(!memcmp(
                test_vin_prevtx_txhash, test_vin_prevtx_expected_txhash, 32));
            test_vin_prevtx_ok++;
        }
        break;
    case BTCTX_EV_VIN_TXIX:
        if (context.inout_current == test_vin_prevtx_vin_index) {
            assert(context.parsed.ptxo_index ==
                   test_vin_prevtx_expected_txindex);
            test_vin_prevtx_ok++;
        }
        break;
    case BTCTX_EV_VIN_SEQNO:
        if (context.inout_current == test_vin_prevtx_vin_index) {
            assert(context.parsed.seqno == test_vin_prevtx_expected_seqno);
            test_vin_prevtx_ok++;
        }
        break;
    }
}

void test_vin_prevtx(const char* file_name,
                     uint32_t vin_index,
                     const char* expected_txhash,
                     uint32_t expected_txindex,
                     uint32_t expected_seqno) {
    printf("Testing vin #%u prev txhash and index for '%s' should be '%s' and "
           "%u...\n",
           vin_index,
           file_name,
           expected_txhash,
           expected_txindex);

    test_vin_prevtx_vin_index = vin_index;

    uint8_t expected_txhash_bytes[32];
    assert(read_hex(expected_txhash, 64, expected_txhash_bytes) == 32);

    test_vin_prevtx_expected_txhash = expected_txhash_bytes;
    test_vin_prevtx_expected_txindex = expected_txindex;
    test_vin_prevtx_expected_seqno = expected_seqno;

    unsigned char* buffer = NULL;
    size_t size = 0;
    int r = read_hex_file(file_name, &buffer, &size);
    if (r != 0) {
        printf("Error reading hex file: %s\n", file_name);
        assert(0);
    }

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        test_vin_prevtx_ok = 0;
        btctx_init(&context, &callback_test_vin_prevtx);
        consume_in_chunks(buffer, size, chunk);
        assert(btctx_result() == BTCTX_ST_DONE);
        assert(test_vin_prevtx_ok == 3);
    }

    free(buffer);
}

uint8_t* test_vin_vout_script_script;
uint32_t test_vin_vout_script_script_offset;
uint32_t test_vin_vout_script_index;
bool test_vin_vout_script_vout;
void callback_test_vin_vout_script(const btctx_cb_event_t event) {
    switch (event) {
    case BTCTX_EV_VIN_SCRIPT_DATA:
        if (!test_vin_vout_script_vout &&
            test_vin_vout_script_index == context.inout_current) {
            memcpy(test_vin_vout_script_script +
                       test_vin_vout_script_script_offset,
                   context.raw,
                   context.raw_size);
            test_vin_vout_script_script_offset += context.raw_size;
        }
        break;
    case BTCTX_EV_VOUT_SCRIPT_DATA:
        if (test_vin_vout_script_vout &&
            test_vin_vout_script_index == context.inout_current) {
            memcpy(test_vin_vout_script_script +
                       test_vin_vout_script_script_offset,
                   context.raw,
                   context.raw_size);
            test_vin_vout_script_script_offset += context.raw_size;
        }
        break;
    }
}

void test_vin_vout_script(const char* file_name,
                          bool vout,
                          uint32_t index,
                          const char* expected_script) {
    printf("Testing %s #%u script for '%s' should be '%s'...\n",
           vout ? "VOUT" : "VIN",
           index,
           file_name,
           expected_script);

    test_vin_vout_script_vout = vout;
    test_vin_vout_script_index = index;

    uint32_t expected_script_length = strlen(expected_script) / 2;
    uint8_t* expected_script_bytes = malloc(expected_script_length);
    assert(read_hex(expected_script,
                    strlen(expected_script),
                    expected_script_bytes) == expected_script_length);

    test_vin_vout_script_script = malloc(expected_script_length);

    unsigned char* buffer = NULL;
    size_t size = 0;
    int r = read_hex_file(file_name, &buffer, &size);
    if (r != 0) {
        printf("Error reading hex file: %s\n", file_name);
        assert(0);
    }

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        test_vin_vout_script_script_offset = 0;
        btctx_init(&context, &callback_test_vin_vout_script);
        consume_in_chunks(buffer, size, chunk);
        assert(btctx_result() == BTCTX_ST_DONE);
        assert(expected_script_length == test_vin_vout_script_script_offset);
        assert(!memcmp(expected_script_bytes,
                       test_vin_vout_script_script,
                       test_vin_vout_script_script_offset));
    }

    free(test_vin_vout_script_script);
    free(expected_script_bytes);
    free(buffer);
}

uint32_t test_vout_value_vout_index;
uint64_t test_vout_value_expected_value;
uint8_t test_vout_value_ok;
void callback_test_vout_value(const btctx_cb_event_t event) {
    switch (event) {
    case BTCTX_EV_VOUT_VALUE:
        if (context.inout_current == test_vout_value_vout_index) {
            assert(test_vout_value_expected_value == context.parsed.vout_value);
            test_vout_value_ok++;
        }
        break;
    }
}

void test_vout_value(const char* file_name,
                     uint32_t vout_index,
                     uint64_t expected_value) {
    printf("Testing vout #%u value '%s' should be %u...\n",
           vout_index,
           file_name,
           expected_value);

    test_vout_value_vout_index = vout_index;
    test_vout_value_expected_value = expected_value;

    unsigned char* buffer = NULL;
    size_t size = 0;
    int r = read_hex_file(file_name, &buffer, &size);
    if (r != 0) {
        printf("Error reading hex file: %s\n", file_name);
        assert(0);
    }

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        test_vout_value_ok = 0;
        btctx_init(&context, &callback_test_vout_value);
        consume_in_chunks(buffer, size, chunk);
        assert(btctx_result() == BTCTX_ST_DONE);
        assert(test_vout_value_ok == 1);
    }

    free(buffer);
}

uint64_t test_locktime_expected_locktime;
uint8_t test_locktime_ok;
void callback_test_locktime(const btctx_cb_event_t event) {
    switch (event) {
    case BTCTX_EV_LOCKTIME:
        assert(test_locktime_expected_locktime == context.parsed.locktime);
        test_locktime_ok++;
        break;
    }
}

void test_locktime(const char* file_name, uint32_t expected_locktime) {
    printf("Testing locktime for '%s' should be %u...\n",
           file_name,
           expected_locktime);

    test_locktime_expected_locktime = expected_locktime;

    unsigned char* buffer = NULL;
    size_t size = 0;
    int r = read_hex_file(file_name, &buffer, &size);
    if (r != 0) {
        printf("Error reading hex file: %s\n", file_name);
        assert(0);
    }

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        test_locktime_ok = 0;
        btctx_init(&context, &callback_test_locktime);
        consume_in_chunks(buffer, size, chunk);
        assert(btctx_result() == BTCTX_ST_DONE);
        assert(test_locktime_ok == 1);
    }

    free(buffer);
}

uint8_t* test_raw_complete_raw;
size_t test_raw_complete_offset;
void callback_test_raw_complete(const btctx_cb_event_t event) {
    memcpy(test_raw_complete_raw + test_raw_complete_offset,
           context.raw,
           context.raw_size);
    test_raw_complete_offset += context.raw_size;
}

void test_raw_complete(const char* file_name) {
    printf("Testing raw callbacks for '%s' should be able to"
           "reconstruct the original tx...\n",
           file_name);

    unsigned char* buffer = NULL;
    size_t size = 0;
    int r = read_hex_file(file_name, &buffer, &size);
    if (r != 0) {
        printf("Error reading hex file: %s\n", file_name);
        assert(0);
    }

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        test_raw_complete_offset = 0;
        test_raw_complete_raw = malloc(size);
        btctx_init(&context, &callback_test_raw_complete);
        consume_in_chunks(buffer, size, chunk);
        assert(btctx_result() == BTCTX_ST_DONE);
        assert(size == test_raw_complete_offset);
        assert(!memcmp(buffer, test_raw_complete_raw, size));
        free(test_raw_complete_raw);
    }

    free(buffer);
}

void callback_test_error(const btctx_cb_event_t event) {
}
void test_error(const char* raw_tx_hex) {
    printf("Testing TX '%s' should yield an error...", raw_tx_hex);

    uint32_t raw_tx_size = strlen(raw_tx_hex) / 2;
    unsigned char* raw_tx = malloc(raw_tx_size);
    assert(read_hex(raw_tx_hex, strlen(raw_tx_hex), raw_tx) == raw_tx_size);

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= raw_tx_size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        btctx_init(&context, &callback_test_error);
        consume_in_chunks(raw_tx, raw_tx_size, chunk);
        assert(btctx_result() < 0);
    }

    free(raw_tx);
}

int main() {
    test_init();
    test_version("resources/tx-001.hex", 1);
    test_version("resources/tx-002.hex", 2);

    test_vin_vout_counts("resources/tx-001.hex", 1, 3);
    test_vin_vout_counts("resources/tx-003.hex", 252, 2);
    test_vin_vout_counts("resources/tx-004.hex", 3, 5);

    test_vin_prevtx(
        "resources/tx-001.hex",
        0,
        "f0e165fa070021a5bf0f533f31cb257ba8833c37146540aac2517ac67ddb250c",
        0,
        0xffffffff);

    test_vin_prevtx(
        "resources/tx-003.hex",
        17,
        "6e56c2ba7072de9984e2b133880d68b1c18b8ddab76de0f94913797eb2fc6d89",
        30,
        0xffffffff);

    test_vin_prevtx(
        "resources/tx-003.hex",
        84,
        "6a8edd13ea51952360a8ade6ec8ff47d1baac8fb9a793c2d55b0af7b5ba0fd34",
        95,
        0xddccbbaa);

    test_vin_prevtx(
        "resources/tx-003.hex",
        137,
        "baefc195e5ece59fc7512b30cdfe1a1151fbf90deaedaa02cfe48d05eb0d4404",
        200,
        0x44332211);

    test_vin_prevtx(
        "resources/tx-004.hex",
        2,
        "b0a268b4b78a91d74daea0d01577b5b1d29b4d7d524fe578c7e053466fd89787",
        2,
        0xffffffff);

    test_vin_vout_script(
        "resources/tx-001.hex",
        false,
        0,
        "0000004c69522102cd53fc53a07f211641a677d250f6de99caf620e8e77071e811a28b"
        "3bcddf0be"
        "1210362634ab57dae9cb373a5d536e66a8c4f67468bbcfb063809bab643072d78a1242"
        "103c5946b"
        "3fbae03a654237da863c9ed534e0878657175b132b8ca630f245df04db53ae");
    test_vin_vout_script("resources/tx-001.hex",
                         true,
                         0,
                         "76a91447a5bfd415108c37e918e8b114b83f8d5ae9834988ac");
    test_vin_vout_script("resources/tx-001.hex",
                         true,
                         1,
                         "a914896ed9f3446d51b5510f7f0b6ef81b2bde55140e87");

    test_vin_vout_script(
        "resources/tx-003.hex",
        false,
        8,
        "0000004c69522102cd53fc53a07f211641a677d250f6de99caf620e8e77071e811a28b"
        "3bcddf0be"
        "1210362634ab57dae9cb373a5d536e66a8c4f67468bbcfb063809bab643072d78a1242"
        "103c5946b"
        "3fbae03a654237da863c9ed534e0878657175b132b8ca630f245df04db53ae");
    test_vin_vout_script("resources/tx-003.hex",
                         true,
                         0,
                         "76a91447a5bfd415108c37e918e8b114b83f8d5ae9834988ac");
    test_vin_vout_script("resources/tx-003.hex",
                         true,
                         1,
                         "a914896ed9f3446d51b5510f7f0b6ef81b2bde55140e87");

    test_vout_value("resources/tx-001.hex", 0, 0x0000000011e111b0L);
    test_vout_value("resources/tx-001.hex", 2, 0x00000000b4efcd11L);
    test_vout_value("resources/tx-002.hex", 0, 0x0000000011e111b0L);
    test_vout_value("resources/tx-002.hex", 1, 0x00000000a0eebb00L);

    test_locktime("resources/tx-001.hex", 0x00000000);
    test_locktime("resources/tx-002.hex", 0x11223344);
    test_locktime("resources/tx-003.hex", 0x55667788);

    test_raw_complete("resources/tx-001.hex");
    test_raw_complete("resources/tx-002.hex");
    test_raw_complete("resources/tx-003.hex");
    test_raw_complete("resources/tx-004.hex");

    test_error("01000000ff1122334401");
    test_error("01000000010c25db7dc67a51c2aa406514373c83a87b25cb313f530fbfa5"
               "210007fa65e1f000000000ff1122334401");
    test_error("01000000010c25db7dc67a51c2aa406514373c83a87b25cb313f530fbfa5"
               "210007fa65e1f00000000001aa00000000ff5555555511");
    test_error(
        "01000000010c25db7dc67a51c2aa406514373c83a87b25cb313f530fbfa5"
        "210007fa65e1f00000000001aaffffffff011122334455667788ff1122334401");

    return 0;
}
