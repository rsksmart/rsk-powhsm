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
#include "os.h"
#include "bolos_ux.h"
#include "ui_heartbeat.h"
#include "signer_authorization.h"
#include "communication.h"
#include "apdu_utils.h"
#include "assert_utils.h"
#include "ui_err.h"

// ******************************
// ***** Mocks and helpers ******
// ******************************

typedef union {
    struct {
        int something;
        int additional;
    };

    ui_heartbeat_t ui_heartbeat;
} wider_context_t;

wider_context_t M_wider_context;

static const unsigned char MOCK_CODE_HASH[] = {
    0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xcc};

static const unsigned char MOCK_PUBLIC_KEY[] = {
    0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x66};

static const unsigned char MOCK_SIGNER_HASH[] = {
    0x66, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x88};

static sigaut_signer_t M_signer_info;

unsigned int M_io_exchange_call_number;
unsigned char M_apdu[sizeof(G_io_apdu_buffer)];
unsigned short M_apdu_size;
unsigned int M_txd;
unsigned short M_last_exception;

void setup() {
    memcpy(M_signer_info.hash, MOCK_SIGNER_HASH, sizeof(MOCK_SIGNER_HASH));
    M_signer_info.iteration = 0x99aa;
    M_io_exchange_call_number = 0;
    M_apdu_size = 0;
    M_txd = 0;
    M_last_exception = 0;
    ui_heartbeat_init(&M_wider_context.ui_heartbeat);
}

void set_public_key(cx_ecfp_public_key_t *pubkey, char *rawkey) {
    pubkey->W_len = PUBKEY_UNCMP_LENGTH;
    memcpy(pubkey->W, rawkey, pubkey->W_len);
}

unsigned int os_endorsement_get_code_hash(unsigned char *buffer) {
    memcpy(buffer, MOCK_CODE_HASH, sizeof(MOCK_CODE_HASH));
    return sizeof(MOCK_CODE_HASH);
}

unsigned int os_endorsement_get_public_key(unsigned char index,
                                           unsigned char *buffer) {
    assert(2 == index);
    memcpy(buffer, MOCK_PUBLIC_KEY, sizeof(MOCK_PUBLIC_KEY));
    return sizeof(MOCK_PUBLIC_KEY);
}

unsigned int os_endorsement_key2_derive_sign_data(unsigned char *src,
                                                  unsigned int srcLength,
                                                  unsigned char *signature) {
    size_t offset = 0;

    memcpy(signature + offset, "\xaa\xbb\xcc", 3);
    offset += 3;

    memcpy(signature + offset, src, srcLength);
    offset += srcLength;

    memcpy(signature + offset, "\xdd\xee\xff", 3);
    offset += 3;

    return offset;
}

sigaut_signer_t *get_authorized_signer_info() {
    return &M_signer_info;
}

unsigned int get_mode_heartbeat() {
    unsigned int foo;
    SET_APDU("\x12\x34\x56\x78\x9a\xbc\xde", foo);
    return 7;
}

void _set_mock_apdu(unsigned char *buffer, unsigned short buffer_size) {
    memcpy(M_apdu, buffer, buffer_size);
    M_apdu_size = buffer_size;
}

#define set_mock_apdu(apdu_literal) \
    _set_mock_apdu(apdu_literal, sizeof(apdu_literal) - 1)

unsigned short io_exchange(unsigned char channel_and_flags,
                           unsigned short tx_len) {
    M_txd = tx_len;

    if (M_io_exchange_call_number++) {
        THROW(EX_BOOTLOADER_RSK_END);
        assert(false);
    };

    assert(0 == channel_and_flags);
    assert(0 == tx_len);

    memcpy(G_io_apdu_buffer, M_apdu, M_apdu_size);
    return M_apdu_size;
}

unsigned int comm_process_exception(unsigned short ex,
                                    unsigned int tx,
                                    comm_reset_cb_t comm_reset_cb) {
    M_last_exception = ex;
    return tx;
}

// ************************
// ****** Unit tests ******
// ************************

void assert_hb_context_cleared() {
    ASSERT_STRUCT_CLEARED(uint8_t[80], M_wider_context.ui_heartbeat.msg);
    assert(0 == M_wider_context.ui_heartbeat.msg_offset);
    assert(STATE_UI_HEARTBEAT_WAIT_UD_VALUE ==
           M_wider_context.ui_heartbeat.state);
}

#define assert_ok(expected_apdu)                \
    ASSERT_APDU(expected_apdu);                 \
    assert(M_txd == sizeof(expected_apdu) - 1); \
    assert(M_last_exception == APDU_OK)

#define assert_error(expected_error_code) \
    assert(M_txd == 0);                   \
    assert(M_last_exception == expected_error_code)

void test_heartbeat_init() {
    printf("Test heartbeat init...\n");

    setup();
    M_wider_context.something = 0x66778899;
    M_wider_context.additional = 0xaabbccdd;

    ui_heartbeat_init(&M_wider_context.ui_heartbeat);

    assert_hb_context_cleared();
}

void test_get_mode() {
    printf("Test get mode...\n");

    setup();

    set_mock_apdu("\x80\x43");
    ui_heartbeat_main(&M_wider_context.ui_heartbeat);

    assert_ok("\x12\x34\x56\x78\x9a\xbc\xde");
}

void test_end_cmd() {
    printf("Test end command...\n");

    setup();

    set_mock_apdu("\x80\xff");
    ui_heartbeat_main(&M_wider_context.ui_heartbeat);

    ASSERT_APDU("\x80\xff");
    assert(M_io_exchange_call_number == 1);
    assert(M_txd == 0);
    assert(M_last_exception == 0);
}

void test_op_ud_value() {
    printf("Test op UD value...\n");

    setup();

    set_mock_apdu("\x80\x60\x01"
                  "\x11"
                  "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
                  "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
                  "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
                  "\x33");
    ui_heartbeat_main(&M_wider_context.ui_heartbeat);

    assert_ok("\x80\x60\x01");

    const char expected_msg[] = "HSM:UI:HB:4.0:" // Prefix
                                "\x11"           // UD
                                "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22" // .
                                "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22" // .
                                "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22" // .
                                "\x33"                                     // .
                                "\x66" // Auth signer hash
                                "\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77" // .
                                "\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77" // .
                                "\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77" // .
                                "\x88"                                     // .
                                "\x99\xaa"; // Auth signer iteration
    assert(!memcmp(M_wider_context.ui_heartbeat.msg,
                   expected_msg,
                   sizeof(expected_msg) - 1));
    assert(M_wider_context.ui_heartbeat.msg_offset == sizeof(expected_msg) - 1);
    assert(M_wider_context.ui_heartbeat.state == STATE_UI_HEARTBEAT_READY);
}

void test_op_ud_value_invalid_size() {
    printf("Test op UD value with invalid size...\n");

    setup();
    M_wider_context.ui_heartbeat.msg_offset = 5;

    set_mock_apdu("\x80\x60\x01"
                  "\x11\x22\x33\x44\x55");
    ui_heartbeat_main(&M_wider_context.ui_heartbeat);

    assert_error(0x6b10);
    assert_hb_context_cleared();
}

void test_op_get_signature() {
    printf("Test op get signature...\n");

    setup();

    const char message[] = "\x00\x99\x88\x77\x66\x55\x44\x33\x22\x11";
    memcpy(M_wider_context.ui_heartbeat.msg, message, sizeof(message) - 1);
    M_wider_context.ui_heartbeat.msg_offset = sizeof(message) - 1;
    M_wider_context.ui_heartbeat.state = STATE_UI_HEARTBEAT_READY;

    set_mock_apdu("\x80\x60\x02");
    ui_heartbeat_main(&M_wider_context.ui_heartbeat);

    assert_ok("\x80\x60\x02"
              "\xaa\xbb\xcc"
              "\x00\x99\x88\x77\x66\x55\x44\x33\x22\x11"
              "\xdd\xee\xff");

    assert(!memcmp(
        M_wider_context.ui_heartbeat.msg, message, sizeof(message) - 1));
    assert(M_wider_context.ui_heartbeat.msg_offset == sizeof(message) - 1);
    assert(M_wider_context.ui_heartbeat.state == STATE_UI_HEARTBEAT_READY);
}

void test_op_get_signature_invalid_state() {
    printf("Test op get signature with invalid state...\n");

    setup();
    M_wider_context.ui_heartbeat.state = STATE_UI_HEARTBEAT_WAIT_UD_VALUE;

    set_mock_apdu("\x80\x60\x02");
    ui_heartbeat_main(&M_wider_context.ui_heartbeat);

    assert_error(0x6b10);
    assert_hb_context_cleared();
}

void test_op_get_msg() {
    printf("Test op get message...\n");

    setup();

    const char message[] = "\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44";
    memcpy(M_wider_context.ui_heartbeat.msg, message, sizeof(message) - 1);
    M_wider_context.ui_heartbeat.msg_offset = sizeof(message) - 1;
    M_wider_context.ui_heartbeat.state = STATE_UI_HEARTBEAT_READY;

    set_mock_apdu("\x80\x60\x03");
    ui_heartbeat_main(&M_wider_context.ui_heartbeat);

    assert_ok("\x80\x60\x03"
              "\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44");

    assert(!memcmp(
        M_wider_context.ui_heartbeat.msg, message, sizeof(message) - 1));
    assert(M_wider_context.ui_heartbeat.msg_offset == sizeof(message) - 1);
    assert(M_wider_context.ui_heartbeat.state == STATE_UI_HEARTBEAT_READY);
}

void test_op_get_msg_invalid_state() {
    printf("Test op get message with invalid state...\n");

    setup();
    M_wider_context.ui_heartbeat.state = STATE_UI_HEARTBEAT_WAIT_UD_VALUE;

    set_mock_apdu("\x80\x60\x03");
    ui_heartbeat_main(&M_wider_context.ui_heartbeat);

    assert_error(0x6b10);
    assert_hb_context_cleared();
}

void test_op_app_hash() {
    printf("Test op app hash...\n");

    setup();

    set_mock_apdu("\x80\x60\x04");
    ui_heartbeat_main(&M_wider_context.ui_heartbeat);

    assert_ok("\x80\x60\x04"
              "\xaa\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
              "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
              "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
              "\xbb\xcc");
}

void test_op_pubkey() {
    printf("Test op pubkey...\n");

    setup();

    set_mock_apdu("\x80\x60\x05");
    ui_heartbeat_main(&M_wider_context.ui_heartbeat);

    assert_ok("\x80\x60\x05"
              "\x44\x55\x55\x55\x55\x55\x55\x55\x55\x55"
              "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
              "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
              "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
              "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
              "\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55"
              "\x55\x55\x55\x55\x66");
}

void test_op_invalid_op() {
    printf("Test invalid hb op...\n");

    setup();
    M_wider_context.ui_heartbeat.msg_offset = 123;

    set_mock_apdu("\x80\x60\xff");
    ui_heartbeat_main(&M_wider_context.ui_heartbeat);

    assert_error(0x6b10);
    assert_hb_context_cleared();
}

void test_empty_apdu() {
    printf("Test empty APDU...\n");

    setup();

    set_mock_apdu("");
    ui_heartbeat_main(&M_wider_context.ui_heartbeat);

    assert_error(0x6982);
}

void test_invalid_cla() {
    printf("Test invalid CLA...\n");

    setup();

    set_mock_apdu("\x77");
    ui_heartbeat_main(&M_wider_context.ui_heartbeat);

    assert_error(0x6e22);
}

int main() {
    test_heartbeat_init();
    test_get_mode();
    test_end_cmd();
    test_op_ud_value();
    test_op_ud_value_invalid_size();
    test_op_get_signature();
    test_op_get_signature_invalid_state();
    test_op_get_msg();
    test_op_get_msg_invalid_state();
    test_op_app_hash();
    test_op_pubkey();
    test_op_invalid_op();
    test_empty_apdu();
    test_invalid_cla();
    return 0;
}
