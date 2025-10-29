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

#include "attestation.h"
#include "bc_state.h"
#include "apdu.h"
#include "hal/exceptions.h"
#include "assert_utils.h"

// Global mock variables
#define IO_APDU_BUFFER_SIZE (5 + 32)
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];
#include "apdu_utils.h"

bc_state_t N_bc_state_var;
static att_t G_att_ctx;

struct {
    bool endorsement_sign_fail;
    bool seed_derive_pubkey_fail;
    bool endorsement_get_code_hash_fail;
    bool endorsement_get_envelope_empty;
} G_mocks;

// Mocked constant values
#define MOCK_CLA_INS "\xAA\xBB"
#define MOCK_UD_VALUE                          \
    "\x11\x22\x22\x22\x22\x22\x22\x22\x22\x33" \
    "\x11\x22\x22\x22\x22\x22\x22\x22\x22\x33" \
    "\x11\x22\x22\x22\x22\x22\x22\x22\x22\x33" \
    "\x44\x55"
#define ENDORSEMENT_SIGNATURE "\xaa\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xcc"
#define CODE_HASH                              \
    "\x11\x22\x11\x22\x11\x22\x11\x22\x11\x22" \
    "\x11\x22\x11\x22\x11\x22\x11\x22\x11\x22"
#define MOCK_PUBKEYS_HASH                      \
    "\x88\x73\x10\x56\x39\xd3\x9c\x1e\xca\x6d" \
    "\xf2\x9c\x1a\xfa\x7f\x8f\x5e\xf2\x5d\xf8" \
    "\x61\x28\x62\x92\x69\x99\xa5\x57\x21\xd0" \
    "\x78\x3d"
#define MOCK_BEST_BLOCK                        \
    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb" \
    "\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc" \
    "\xdd\xdd"
#define MOCK_TX_HASH                           \
    "\x33\x33\x33\x33\x33\x33\x33\x33\x44\x44" \
    "\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44" \
    "\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44" \
    "\x44\x44"
#define MOCK_ENVELOPE                          \
    "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11" \
    "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11" \
    "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11" \
    "\x11"                                     \
    "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22" \
    "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22" \
    "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22" \
    "\x22"                                     \
    "\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33" \
    "\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33" \
    "\x33\x33\x33\x33\x33\x33\x33\x33"
#define MOCK_MESSAGE                           \
    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
    "\xaa"                                     \
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb" \
    "\xbb\xbb\xbb\xbb\xbb"

// Mock functions
void platform_memmove(void* dst, const void* src, unsigned int length) {
    memmove(dst, src, length);
}

unsigned char* communication_get_msg_buffer() {
    return G_io_apdu_buffer;
}

size_t communication_get_msg_buffer_size() {
    return sizeof(G_io_apdu_buffer);
}

const char* platform_get_id() {
    return "tst";
}

uint64_t platform_get_timestamp() {
    return 0x1122334455667788;
}

char G_ordered_path[21];

const char* get_ordered_path(unsigned int index) {
    memcpy(
        G_ordered_path, "Xi-am-ordered-path::", strlen("Xi-am-ordered-path::"));
    G_ordered_path[sizeof(G_ordered_path) - 1] = 0x30 + index + 1;
    return G_ordered_path;
}

bool seed_derive_pubkey(uint32_t* path,
                        uint8_t path_length,
                        uint8_t* pubkey_out,
                        uint8_t* pubkey_out_length) {
    assert(path_length == 5);
    uint8_t* raw_path = (uint8_t*)raw_path;
    size_t raw_path_size = path_length * sizeof(path[0]);
    assert(!memcmp(path, "i-am-ordered-path::", raw_path_size - 1));
    assert(raw_path[raw_path_size - 1] >= 0x31 &&
           raw_path[raw_path_size - 1] <= 0x36);

    if (G_mocks.seed_derive_pubkey_fail)
        return false;

    memcpy(pubkey_out, "derived-", strlen("derived-"));
    memcpy(pubkey_out + strlen("derived-"), raw_path, raw_path_size);
    *pubkey_out_length = raw_path_size + strlen("derived-");
    return true;
}

bool endorsement_sign(uint8_t* msg,
                      size_t msg_size,
                      uint8_t* signature_out,
                      uint8_t* signature_out_length) {
    if (G_mocks.endorsement_sign_fail)
        return false;

    assert(msg == G_att_ctx.msg);
    assert(msg_size == G_att_ctx.msg_length);
    memcpy(signature_out, ENDORSEMENT_SIGNATURE, strlen(ENDORSEMENT_SIGNATURE));
    *signature_out_length = strlen(ENDORSEMENT_SIGNATURE);
    return true;
}

uint8_t* endorsement_get_envelope() {
    if (G_mocks.endorsement_get_envelope_empty)
        return NULL;

    return MOCK_ENVELOPE;
}

size_t endorsement_get_envelope_length() {
    if (G_mocks.endorsement_get_envelope_empty)
        return 0;

    return strlen(MOCK_ENVELOPE);
}

bool endorsement_get_code_hash(uint8_t* code_hash_out,
                               uint8_t* code_hash_out_length) {
    assert(*code_hash_out_length >= strlen(CODE_HASH));

    if (G_mocks.endorsement_get_code_hash_fail)
        return false;

    memcpy(code_hash_out, CODE_HASH, strlen(CODE_HASH));
    *code_hash_out_length = strlen(CODE_HASH);
    return true;
}

// Unit tests

void setup() {
    memset(&G_mocks, 0, sizeof(G_mocks));
    memset(N_bc_state_var.best_block, 0, sizeof(N_bc_state_var.best_block));
    memset(N_bc_state_var.last_auth_signed_btc_tx_hash,
           0,
           sizeof(N_bc_state_var.last_auth_signed_btc_tx_hash));
}

void test_get_attestation_get_ok() {
    printf("Test OP_ATT_GET success...\n");

    unsigned int rx;
    setup();
    memcpy(N_bc_state_var.best_block, MOCK_BEST_BLOCK, strlen(MOCK_BEST_BLOCK));
    memcpy(N_bc_state_var.last_auth_signed_btc_tx_hash,
           MOCK_TX_HASH,
           strlen(MOCK_TX_HASH));

    BEGIN_TRY {
        TRY {
            SET_APDU(MOCK_CLA_INS "\x01" MOCK_UD_VALUE, rx);
            assert(TX_FOR_DATA_SIZE(strlen(ENDORSEMENT_SIGNATURE)) ==
                   get_attestation(rx, &G_att_ctx));

            ASSERT_APDU(MOCK_CLA_INS "\x01" ENDORSEMENT_SIGNATURE);
            assert(G_att_ctx.state == STATE_ATTESTATION_READY);

            size_t offset = 0;
            assert(!memcmp(G_att_ctx.msg + offset,
                           "POWHSM:5.6::",
                           strlen("POWHSM:5.6::")));
            offset += strlen("POWHSM:5.6::");
            assert(!memcmp(G_att_ctx.msg + offset, "tst", 3));
            offset += 3;
            assert(!memcmp(
                G_att_ctx.msg + offset, MOCK_UD_VALUE, strlen(MOCK_UD_VALUE)));
            offset += strlen(MOCK_UD_VALUE);
            assert(!memcmp(G_att_ctx.msg + offset,
                           MOCK_PUBKEYS_HASH,
                           strlen(MOCK_PUBKEYS_HASH)));
            offset += strlen(MOCK_PUBKEYS_HASH);
            assert(!memcmp(G_att_ctx.msg + offset,
                           MOCK_BEST_BLOCK,
                           strlen(MOCK_BEST_BLOCK)));
            offset += strlen(MOCK_BEST_BLOCK);
            assert(!memcmp(G_att_ctx.msg + offset,
                           "\x33\x33\x33\x33\x33\x33\x33\x33",
                           ATT_LAST_SIGNED_TX_BYTES));
            offset += ATT_LAST_SIGNED_TX_BYTES;
            assert(!memcmp(G_att_ctx.msg + offset,
                           "\x11\x22\x33\x44\x55\x66\x77\x88",
                           sizeof(uint64_t)));
            offset += sizeof(uint64_t);
            assert(offset == G_att_ctx.msg_length);
        }
        CATCH_ALL {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_get_ud_value_too_short() {
    printf("Test OP_ATT_GET UD value too short...\n");

    unsigned int rx;
    setup();

    BEGIN_TRY {
        TRY {
            SET_APDU(MOCK_CLA_INS "\x01"
                                  "\x11\x22",
                     rx);
            get_attestation(rx, &G_att_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(ERR_ATT_PROT_INVALID == e);
            assert(G_att_ctx.state == STATE_ATTESTATION_WAIT_SIGN);
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_get_pubkey_derivation_fail() {
    printf("Test OP_ATT_GET public key derivation fails...\n");

    unsigned int rx;
    setup();
    G_mocks.seed_derive_pubkey_fail = true;

    BEGIN_TRY {
        TRY {
            SET_APDU(MOCK_CLA_INS "\x01" MOCK_UD_VALUE, rx);
            get_attestation(rx, &G_att_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(ERR_ATT_INTERNAL == e);
            assert(G_att_ctx.state == STATE_ATTESTATION_WAIT_SIGN);
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_get_endorsement_sign_fail() {
    printf("Test OP_ATT_GET endorsement signing fails...\n");

    unsigned int rx;
    setup();
    G_mocks.endorsement_sign_fail = true;

    BEGIN_TRY {
        TRY {
            SET_APDU(MOCK_CLA_INS "\x01" MOCK_UD_VALUE, rx);
            get_attestation(rx, &G_att_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(ERR_ATT_INTERNAL == e);
            assert(G_att_ctx.state == STATE_ATTESTATION_WAIT_SIGN);
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_get_envelope_ok() {
    printf("Test OP_ATT_GET_ENVELOPE success...\n");

    unsigned int rx;
    setup();
    G_att_ctx.state = STATE_ATTESTATION_READY;

    BEGIN_TRY {
        TRY {
            // Page 0
            SET_APDU(MOCK_CLA_INS "\x04\x00", rx);
            assert(TX_FOR_DATA_SIZE(IO_APDU_BUFFER_SIZE - 5) ==
                   get_attestation(rx, &G_att_ctx));

            ASSERT_APDU(MOCK_CLA_INS "\x04\x01"
                                     "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
                                     "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
                                     "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
                                     "\x11");
            assert(G_att_ctx.state == STATE_ATTESTATION_READY);

            // Page 1
            SET_APDU(MOCK_CLA_INS "\x04\x01", rx);
            assert(TX_FOR_DATA_SIZE(IO_APDU_BUFFER_SIZE - 5) ==
                   get_attestation(rx, &G_att_ctx));

            ASSERT_APDU(MOCK_CLA_INS "\x04\x01"
                                     "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
                                     "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
                                     "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
                                     "\x22");
            assert(G_att_ctx.state == STATE_ATTESTATION_READY);

            // Page 1 again
            SET_APDU(MOCK_CLA_INS "\x04\x01", rx);
            assert(TX_FOR_DATA_SIZE(IO_APDU_BUFFER_SIZE - 5) ==
                   get_attestation(rx, &G_att_ctx));

            ASSERT_APDU(MOCK_CLA_INS "\x04\x01"
                                     "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
                                     "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
                                     "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
                                     "\x22");
            assert(G_att_ctx.state == STATE_ATTESTATION_READY);

            // Page 2
            SET_APDU(MOCK_CLA_INS "\x04\x02", rx);
            assert(TX_FOR_DATA_SIZE(28 + 1) == get_attestation(rx, &G_att_ctx));

            ASSERT_APDU(MOCK_CLA_INS "\x04\x00"
                                     "\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33"
                                     "\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33"
                                     "\x33\x33\x33\x33\x33\x33\x33\x33");
            assert(G_att_ctx.state == STATE_ATTESTATION_READY);
        }
        CATCH_ALL {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_get_envelope_no_envelope_ok() {
    printf("Test OP_ATT_GET_ENVELOPE with no envelope (defaults to message) "
           "success...\n");

    unsigned int rx;
    setup();
    G_att_ctx.state = STATE_ATTESTATION_READY;
    G_mocks.endorsement_get_envelope_empty = true;
    memcpy(G_att_ctx.msg, MOCK_MESSAGE, strlen(MOCK_MESSAGE));
    G_att_ctx.msg_length = strlen(MOCK_MESSAGE);

    BEGIN_TRY {
        TRY {
            // Page 0
            SET_APDU(MOCK_CLA_INS "\x04\x00", rx);
            assert(TX_FOR_DATA_SIZE(IO_APDU_BUFFER_SIZE - 5) ==
                   get_attestation(rx, &G_att_ctx));

            ASSERT_APDU(MOCK_CLA_INS "\x04\x01"
                                     "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                                     "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                                     "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                                     "\xaa");
            assert(G_att_ctx.state == STATE_ATTESTATION_READY);

            // Page 1
            SET_APDU(MOCK_CLA_INS "\x04\x01", rx);
            assert(TX_FOR_DATA_SIZE(15 + 1) == get_attestation(rx, &G_att_ctx));

            ASSERT_APDU(MOCK_CLA_INS "\x04\x00"
                                     "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
                                     "\xbb\xbb\xbb\xbb\xbb");
            assert(G_att_ctx.state == STATE_ATTESTATION_READY);

            // Page 1 again
            SET_APDU(MOCK_CLA_INS "\x04\x01", rx);
            assert(TX_FOR_DATA_SIZE(15 + 1) == get_attestation(rx, &G_att_ctx));

            ASSERT_APDU(MOCK_CLA_INS "\x04\x00"
                                     "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
                                     "\xbb\xbb\xbb\xbb\xbb");
            assert(G_att_ctx.state == STATE_ATTESTATION_READY);
        }
        CATCH_ALL {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_get_envelope_page_out_of_range() {
    printf("Test OP_ATT_GET_ENVELOPE with page out of range fails...\n");

    unsigned int rx;
    setup();
    G_att_ctx.state = STATE_ATTESTATION_READY;

    BEGIN_TRY {
        TRY {
            SET_APDU(MOCK_CLA_INS "\x04\x03", rx);
            get_attestation(rx, &G_att_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(ERR_ATT_PROT_INVALID == e);
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_get_envelope_no_envelope_page_out_of_range() {
    printf("Test OP_ATT_GET_ENVELOPE with no envelope (defaults to message) "
           "and page out of range fails...\n");

    unsigned int rx;
    setup();
    G_att_ctx.state = STATE_ATTESTATION_READY;
    G_mocks.endorsement_get_envelope_empty = true;
    memcpy(G_att_ctx.msg, MOCK_MESSAGE, strlen(MOCK_MESSAGE));
    G_att_ctx.msg_length = strlen(MOCK_MESSAGE);

    BEGIN_TRY {
        TRY {
            SET_APDU(MOCK_CLA_INS "\x02\x02", rx);
            get_attestation(rx, &G_att_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(ERR_ATT_PROT_INVALID == e);
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_get_message_ok() {
    printf("Test OP_ATT_GET_MESSAGE success...\n");

    unsigned int rx;
    setup();
    G_att_ctx.state = STATE_ATTESTATION_READY;
    memcpy(G_att_ctx.msg, MOCK_MESSAGE, strlen(MOCK_MESSAGE));
    G_att_ctx.msg_length = strlen(MOCK_MESSAGE);

    BEGIN_TRY {
        TRY {
            // Page 0
            SET_APDU(MOCK_CLA_INS "\x02\x00", rx);
            assert(TX_FOR_DATA_SIZE(IO_APDU_BUFFER_SIZE - 5) ==
                   get_attestation(rx, &G_att_ctx));

            ASSERT_APDU(MOCK_CLA_INS "\x02\x01"
                                     "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                                     "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                                     "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                                     "\xaa");
            assert(G_att_ctx.state == STATE_ATTESTATION_READY);

            // Page 1
            SET_APDU(MOCK_CLA_INS "\x02\x01", rx);
            assert(TX_FOR_DATA_SIZE(15 + 1) == get_attestation(rx, &G_att_ctx));

            ASSERT_APDU(MOCK_CLA_INS "\x02\x00"
                                     "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
                                     "\xbb\xbb\xbb\xbb\xbb");
            assert(G_att_ctx.state == STATE_ATTESTATION_READY);

            // Page 1 again
            SET_APDU(MOCK_CLA_INS "\x02\x01", rx);
            assert(TX_FOR_DATA_SIZE(15 + 1) == get_attestation(rx, &G_att_ctx));

            ASSERT_APDU(MOCK_CLA_INS "\x02\x00"
                                     "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
                                     "\xbb\xbb\xbb\xbb\xbb");
            assert(G_att_ctx.state == STATE_ATTESTATION_READY);
        }
        CATCH_ALL {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_get_envelope_n_message_invalid_state() {
    printf("Test OP_ATT_GET_ENVELOPE and OP_ATT_GET_MESSAGE with invalid state "
           "fail...\n");

    unsigned int rx;
    setup();
    G_att_ctx.state = STATE_ATTESTATION_WAIT_SIGN;

    for (int i = 0; i < 2; i++) {
        BEGIN_TRY {
            TRY {
                SET_APDU(MOCK_CLA_INS "\x04\x00", rx);
                if (i)
                    SET_APDU_OP(2);
                get_attestation(rx, &G_att_ctx);
                ASSERT_FAIL();
            }
            CATCH_OTHER(e) {
                assert(ERR_ATT_PROT_INVALID == e);
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}

void test_get_attestation_get_envelope_n_message_no_page_index() {
    printf("Test OP_ATT_GET_ENVELOPE and OP_ATT_GET_MESSAGE with no page index "
           "fail...\n");

    unsigned int rx;
    setup();
    G_att_ctx.state = STATE_ATTESTATION_READY;

    for (int i = 0; i < 2; i++) {
        BEGIN_TRY {
            TRY {
                SET_APDU(MOCK_CLA_INS "\x04", rx);
                if (i)
                    SET_APDU_OP(2);
                get_attestation(rx, &G_att_ctx);
                ASSERT_FAIL();
            }
            CATCH_OTHER(e) {
                assert(ERR_ATT_PROT_INVALID == e);
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}

void test_get_attestation_app_hash_ok() {
    printf("Test OP_ATT_APP_HASH success...\n");

    unsigned int rx;
    setup();
    G_att_ctx.state = STATE_ATTESTATION_READY;

    BEGIN_TRY {
        TRY {
            SET_APDU(MOCK_CLA_INS "\x03", rx);
            assert(TX_FOR_DATA_SIZE(strlen(CODE_HASH)) ==
                   get_attestation(rx, &G_att_ctx));

            ASSERT_APDU(MOCK_CLA_INS "\x03" CODE_HASH);
            assert(G_att_ctx.state == STATE_ATTESTATION_READY);
        }
        CATCH_ALL {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_app_hash_invalid_state() {
    printf("Test OP_ATT_APP_HASH with invalid state fails...\n");

    unsigned int rx;
    setup();
    G_att_ctx.state = STATE_ATTESTATION_WAIT_SIGN;

    BEGIN_TRY {
        TRY {
            SET_APDU(MOCK_CLA_INS "\x03", rx);
            get_attestation(rx, &G_att_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(ERR_ATT_PROT_INVALID == e);
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_app_hash_get_code_hash_fail() {
    printf("Test OP_ATT_APP_HASH get code hash fails...\n");

    unsigned int rx;
    setup();
    G_att_ctx.state = STATE_ATTESTATION_READY;
    G_mocks.endorsement_get_code_hash_fail = true;

    BEGIN_TRY {
        TRY {
            SET_APDU(MOCK_CLA_INS "\x03", rx);
            get_attestation(rx, &G_att_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(ERR_ATT_INTERNAL == e);
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_invalid_op() {
    printf("Test invalid op...\n");

    unsigned int rx;
    setup();

    BEGIN_TRY {
        TRY {
            SET_APDU(MOCK_CLA_INS "\x99", rx);
            get_attestation(rx, &G_att_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(ERR_ATT_PROT_INVALID == e);
        }
        FINALLY {
        }
    }
    END_TRY;
}

int main() {
    test_get_attestation_get_ok();
    test_get_attestation_get_ud_value_too_short();
    test_get_attestation_get_pubkey_derivation_fail();
    test_get_attestation_get_endorsement_sign_fail();

    test_get_attestation_get_envelope_ok();
    test_get_attestation_get_envelope_no_envelope_ok();
    test_get_attestation_get_envelope_page_out_of_range();
    test_get_attestation_get_envelope_no_envelope_page_out_of_range();

    test_get_attestation_get_message_ok();

    test_get_attestation_get_envelope_n_message_invalid_state();
    test_get_attestation_get_envelope_n_message_no_page_index();

    test_get_attestation_app_hash_ok();
    test_get_attestation_app_hash_invalid_state();
    test_get_attestation_app_hash_get_code_hash_fail();

    test_get_attestation_invalid_op();
    return 0;
}
