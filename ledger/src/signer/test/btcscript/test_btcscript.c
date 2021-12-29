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

#include "btcscript.h"
#include "hex_reader.h"

btcscript_ctx_t context;

void test_init() {
    printf("Testing context initialization...\n");

    btcscript_init(&context, (btcscript_cb_t)1234, 5678);

    assert(context.state == BTCSCRIPT_ST_OPCODE);
    assert(context.opcode == 0);
    assert(context.size_offset == 0);
    assert(context.operand_size == 0);
    assert((size_t)context.callback == 1234);
    assert(context.bytes_remaining == 5678);
    assert(!btcscript_result());
}

void consume_in_chunks(uint8_t* buffer, size_t size, uint8_t chunk_size) {
    for (size_t i = 0; i < size; i += chunk_size) {
        uint8_t this_chunk = i + chunk_size >= size ? size - i : chunk_size;
        uint8_t consumed = btcscript_consume(buffer + i, this_chunk);
        if (btcscript_result() >= 0)
            assert(consumed == this_chunk);
    }
}

uint8_t test_opcode_no_operand_expected_opcode;
int test_opcode_no_operand_ok;
void test_opcode_no_operand_callback(btcscript_cb_event_t event) {
    if (event == BTCSCRIPT_EV_OPCODE &&
        context.opcode == test_opcode_no_operand_expected_opcode) {
        test_opcode_no_operand_ok++;
    }
}

void test_opcode_no_operand(const char* script_hex, uint8_t expected_opcode) {
    printf("Testing no operand opcode for script '%s'...\n", script_hex);

    size_t script_size = (size_t)(strlen(script_hex) / 2);
    uint8_t* script = malloc(script_size);
    assert(read_hex(script_hex, script_size * 2, script) == script_size);

    test_opcode_no_operand_expected_opcode = expected_opcode;
    test_opcode_no_operand_ok = 0;
    btcscript_init(&context, &test_opcode_no_operand_callback, script_size);
    btcscript_consume(script, script_size);
    assert(btcscript_result() == BTCSCRIPT_ST_DONE);
    assert(test_opcode_no_operand_ok == 1);

    free(script);
}

uint8_t test_opcode_n_operand_expected_opcode;
uint32_t test_opcode_n_operand_expected_operand_size;
uint8_t* test_opcode_n_operand_expected_operand;
int test_opcode_n_operand_ok;
uint8_t* test_opcode_n_operand_operand;
uint32_t operand_offset;
void test_opcode_n_operand_callback(btcscript_cb_event_t event) {
    switch (event) {
    case BTCSCRIPT_EV_OPCODE:
        if (context.opcode == test_opcode_n_operand_expected_opcode) {
            assert(context.operand_size ==
                   test_opcode_n_operand_expected_operand_size);
            test_opcode_n_operand_operand = malloc(context.operand_size);
            operand_offset = 0;
            test_opcode_n_operand_ok++;
        }
        break;
    case BTCSCRIPT_EV_OPERAND:
        if (context.opcode == test_opcode_n_operand_expected_opcode) {
            assert(test_opcode_n_operand_ok == 1);
            test_opcode_n_operand_operand[operand_offset++] =
                context.operand_byte;
        }
        break;
    case BTCSCRIPT_EV_OPERAND_END:
        if (context.opcode == test_opcode_n_operand_expected_opcode) {
            assert(operand_offset ==
                   test_opcode_n_operand_expected_operand_size);
            assert(test_opcode_n_operand_ok == 1);
            assert(!memcmp(test_opcode_n_operand_expected_operand,
                           test_opcode_n_operand_operand,
                           test_opcode_n_operand_expected_operand_size));
            free(test_opcode_n_operand_operand);
            test_opcode_n_operand_ok++;
        }
        break;
    }
}

void test_opcode_n_operand(const char* script_hex,
                           uint8_t expected_opcode,
                           const char* expected_operand_hex) {
    printf("Testing opcode and operand for script '%s'...\n", script_hex);

    size_t script_size = (size_t)(strlen(script_hex) / 2);
    uint8_t* script = malloc(script_size);
    assert(read_hex(script_hex, script_size * 2, script) == script_size);

    size_t operand_size = (size_t)(strlen(expected_operand_hex) / 2);
    uint8_t* expected_operand = malloc(operand_size);
    assert(read_hex(expected_operand_hex, operand_size * 2, expected_operand) ==
           operand_size);

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= script_size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        test_opcode_n_operand_expected_opcode = expected_opcode;
        test_opcode_n_operand_expected_operand_size = operand_size;
        test_opcode_n_operand_expected_operand = expected_operand;
        test_opcode_n_operand_ok = 0;
        btcscript_init(&context, &test_opcode_n_operand_callback, script_size);
        consume_in_chunks(script, script_size, chunk);
        assert(btcscript_result() == BTCSCRIPT_ST_DONE);
        assert(test_opcode_n_operand_ok == 2);
    }

    free(script);
}

void test_empty_callback(btcscript_cb_event_t event) {
}

void test_result(const char* script_hex,
                 int8_t expected_result,
                 const char* description) {
    printf("Testing script '%s' should be deemed %s...\n",
           script_hex,
           description);

    size_t script_size = (size_t)(strlen(script_hex) / 2);
    uint8_t* script = malloc(script_size);
    assert(read_hex(script_hex, script_size * 2, script) == script_size);

    // Test sending different chunk sizes
    for (uint8_t chunk = 1; chunk <= 101 && chunk <= script_size; chunk += 10) {
        printf("- with chunk size %u\n", chunk);

        btcscript_init(&context, &test_empty_callback, script_size);
        consume_in_chunks(script, script_size, chunk);
        assert(btcscript_result() == expected_result);
    }

    free(script);
}

void test_valid(const char* script_hex) {
    test_result(script_hex, BTCSCRIPT_ST_DONE, "valid");
}

void test_invalid(const char* script_hex) {
    test_result(script_hex, BTCSCRIPT_ERR_INVALID, "invalid");
}

int main() {
    test_init();

    test_opcode_no_operand("00", BTCSCRIPT_OP_0);
    test_opcode_no_operand("4f", BTCSCRIPT_OP_1NEGATE);
    test_opcode_no_operand("50", BTCSCRIPT_OP_RESERVED);
    test_opcode_no_operand("51", BTCSCRIPT_OP_1);
    test_opcode_no_operand("52", BTCSCRIPT_OP_2);
    test_opcode_no_operand("53", BTCSCRIPT_OP_3);
    test_opcode_no_operand("54", BTCSCRIPT_OP_4);
    test_opcode_no_operand("55", BTCSCRIPT_OP_5);
    test_opcode_no_operand("56", BTCSCRIPT_OP_6);
    test_opcode_no_operand("57", BTCSCRIPT_OP_7);
    test_opcode_no_operand("58", BTCSCRIPT_OP_8);
    test_opcode_no_operand("59", BTCSCRIPT_OP_9);
    test_opcode_no_operand("5a", BTCSCRIPT_OP_10);
    test_opcode_no_operand("5b", BTCSCRIPT_OP_11);
    test_opcode_no_operand("5c", BTCSCRIPT_OP_12);
    test_opcode_no_operand("5d", BTCSCRIPT_OP_13);
    test_opcode_no_operand("5e", BTCSCRIPT_OP_14);
    test_opcode_no_operand("5f", BTCSCRIPT_OP_15);
    test_opcode_no_operand("60", BTCSCRIPT_OP_16);

    test_opcode_n_operand("01aa", 0x01, "aa");
    test_opcode_n_operand("02aabb", 0x02, "aabb");
    test_opcode_n_operand(
        "0a0102030405060708090a", 0x0a, "0102030405060708090a");
    test_opcode_n_operand("4b11111111111111111111222222222222222222223333333333"
                          "3333333333444444444444444444445555555555555555555566"
                          "666666666666666666777777777777777777778888888888",
                          0x4b,
                          "1111111111111111111122222222222222222222333333333333"
                          "3333333344444444444444444444555555555555555555556666"
                          "6666666666666666777777777777777777778888888888");
    test_opcode_n_operand("4c051122334455", 0x4c, "1122334455");
    test_opcode_n_operand(
        "4d020156d2f3a9cda97ac22b0d23f5d082b9269c2880f513b42dee69e7ab1580d15b06"
        "ca006205eed0a890c9e526dba3fd7628be994785d8a3f0cec83136c7114c94eba0ae00"
        "934773c669880b106ae298953a27d19f581a25589b301e49a64791e36895673636b95a"
        "5fd05e87b45ddee9754e4338e22776d08f869bc2b26e63f73b4745a1b89f0f22a826b6"
        "27a0d6248713b357833fdf6cd76ca4e2ee8442169cd5e7289546e7511f8bce3dffd5af"
        "c66516bc9348cb491fec435899c740783aa8567a75935967beb194b8baea97df841a68"
        "192ba41e96ccc309c11aaa4e03c545cbfa74d5de6f146bbdcdcc84e61e30e7cdde3388"
        "eb156affe18870052a19f92580f329ed",
        0x4d,
        "56d2f3a9cda97ac22b0d23f5d082b9269c2880f513b42dee69e7ab1580d15b06ca0062"
        "05eed0a890c9e526dba3fd7628be994785d8a3f0cec83136c7114c94eba0ae00934773"
        "c669880b106ae298953a27d19f581a25589b301e49a64791e36895673636b95a5fd05e"
        "87b45ddee9754e4338e22776d08f869bc2b26e63f73b4745a1b89f0f22a826b627a0d6"
        "248713b357833fdf6cd76ca4e2ee8442169cd5e7289546e7511f8bce3dffd5afc66516"
        "bc9348cb491fec435899c740783aa8567a75935967beb194b8baea97df841a68192ba4"
        "1e96ccc309c11aaa4e03c545cbfa74d5de6f146bbdcdcc84e61e30e7cdde3388eb156a"
        "ffe18870052a19f92580f329ed");
    test_opcode_n_operand(
        "4eaa00000063e081551583516962082588bb01b85b3674a2f78c23783a686b27ce302d"
        "f87876ce1f6762bdd6b1be1a292dc09d4bd09b515909812c6dc1dfb49f2f0c3f84a953"
        "80a29e85f744d0aaf28408844a848a866c15c97dcdb5109842acbb0b1fbd4b8a53b986"
        "39d8a8d9cd413e6e746741c862a5a72055e3bbaa52c7cc97f0441b81bd75049c01daa7"
        "952ce18194192850ff3f07e01af94266824459dc7bcc7451692ec12ccc6b4ac138cb7"
        "a",
        0x4e,
        "63e081551583516962082588bb01b85b3674a2f78c23783a686b27ce302df87876ce1f"
        "6762bdd6b1be1a292dc09d4bd09b515909812c6dc1dfb49f2f0c3f84a95380a29e85f7"
        "44d0aaf28408844a848a866c15c97dcdb5109842acbb0b1fbd4b8a53b98639d8a8d9cd"
        "413e6e746741c862a5a72055e3bbaa52c7cc97f0441b81bd75049c01daa7952ce18194"
        "192850ff3f07e01af94266824459dc7bcc7451692ec12ccc6b4ac138cb7a");

    test_valid("01aa02bbbb03cccccc4c04dddddddd");
    test_valid(
        "0a0102030405060708090a4d020156d2f3a9cda97ac22b0d23f5d082b9269c2880f513"
        "b42dee69e7ab1580d15b06ca006205eed0a890c9e526dba3fd7628be994785d8a3f0ce"
        "c83136c7114c94eba0ae00934773c669880b106ae298953a27d19f581a25589b301e49"
        "a64791e36895673636b95a5fd05e87b45ddee9754e4338e22776d08f869bc2b26e63f7"
        "3b4745a1b89f0f22a826b627a0d6248713b357833fdf6cd76ca4e2ee8442169cd5e728"
        "9546e7511f8bce3dffd5afc66516bc9348cb491fec435899c740783aa8567a75935967"
        "beb194b8baea97df841a68192ba41e96ccc309c11aaa4e03c545cbfa74d5de6f146bbd"
        "cdcc84e61e30e7cdde3388eb156affe18870052a19f92580f329ed");
    test_valid(
        "000000004cd8645221024c759affafc5589872d218ca30377e6d97211c039c375672c1"
        "69ba76ce7fad6a21031f4aa4943fa2b731cd99c551d6992021555877b3b32c12538560"
        "0fbc1b89c2a92103767a0994daa8babee7215b2371916d09fc1158de3c23feeefaae2d"
        "fe5baf483053670132b275522102132685d71b0109fecef0160f1efcab0187eff916f4"
        "d472289741bff2666d0e1c2102ed498022f9d618a96f272b1990a640d9f24fb97d2648"
        "f8716f9ee22dc008eba721036f66639295ca8e4294c24d63e3fbc11247f6ba6a27b6b4"
        "de9a3492f414152d9b5368ae");
    test_valid("0000004c69522102cd53fc53a07f211641a677d250f6de99caf620e8e77071e"
               "811a28b3bcddf0be1210362634ab57dae9cb373a5d536e66a8c4f67468bbcfb"
               "063809bab643072d78a1242103c5946b3fbae03a654237da863c9ed534e0878"
               "657175b132b8ca630f245df04db53ae");
    test_valid(
        "00000000000000004dbd0157210231a395e332dde8688800a0025cccc5771ea1aa874a"
        "633b8ab6e5c89d300c7c3621026b472f7d59d201ff1f540f111b6eb329e071c30a9d23"
        "e3d2bcd128fe73dc254c21027319afb15481dbeb3c426bcc37f9a30e7f51ceff586936"
        "d85548d9395bcc2344210294c817150f78607566e961b3c71df53a22022a80acbb982f"
        "83c0c8baac040adc2103250c11be0561b1d7ae168b1f59e39cbc1fd1ba3cf4d2140c1a"
        "365b2723a2bf9321033ada6ef3b1d93a1978b595c7a9e2aa613860b26d4f5a7abb8857"
        "6aa42b3432ad210357f7ed4c118e581f49cd3b4d9dd1edb4295f4def49d6dcf2faaaaa"
        "c87a1a0a42210372cd46831f3b6afd4c044d160b7667e8ebf659d6cb51a825a3104df6"
        "ee0638c62103ae72827d25030818c4947a800187b1fbcc33ae751e248ae60094cc989f"
        "b880f62103b3a7aa25702000c5c1faa300600e8e2bd89cde2be7fb1ec898a39c50d9de"
        "90d12103b53899c390573471ba30e5054f78376c5f797fda26dde7a760789f02908cba"
        "d22103e05bf6002b62651378b1954820539c36ca405cbb778c225395dd9ebff6780299"
        "2103ecd8af1e93c57a1b8c7f917bd9980af798adeb0205e9687865673353eb041e8d5d"
        "ae");

    test_invalid("61");
    test_invalid("01aa02bbcc03ddeeff041122334461");
    test_invalid("4eaa00000063e081551583516962082588bb01b85b3674a2f78c23783a686"
                 "b27ce302df87876ce1f6762bdd6b1be1a292dc09d4bd09b515909812c6dc1"
                 "dfb49f2f0c3f84a95380a29e85f744d0aaf28408844a848a866c15c97dcdb"
                 "5109842acbb0b1fbd4b8a53b98639d8a8d9cd413e6e746741c862a5a72055"
                 "e3bbaa52c7cc97f0441b81bd75049c01daa7952ce18194192850ff3f07e01"
                 "af94266824459dc7bcc7451692ec12ccc6b4ac138cb7aaa");

    return 0;
}
