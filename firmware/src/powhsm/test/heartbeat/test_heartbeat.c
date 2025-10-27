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

#include "assert_utils.h"
#include "apdu.h"
#include "hal/exceptions.h"
#include "hal/communication.h"
#include "bc_state.h"
#include "heartbeat.h"

// Test global variables
static uint8_t G_comm_buffer[260];
static size_t G_comm_buffer_size = sizeof(G_comm_buffer);
static heartbeat_t G_hbt_ctx;

// Mock app hash
static uint8_t G_mock_app_hash[HASH_SIZE];

// Mock public key
static uint8_t G_mock_pubkey[PUBKEY_UNCMP_LENGTH];

// Mock configuration
struct {
    bool endorsement_sign;
    bool endorsement_get_code_hash;
    bool endorsement_get_public_key;
} G_mocks;

// Mock call tracking
struct {
    int endorsement_sign_calls;
    int endorsement_get_code_hash_calls;
    int endorsement_get_public_key_calls;
} G_called;

// Mock blockchain state
bc_state_t N_bc_state_var;

// Mock implementations
bool endorsement_sign(uint8_t *msg,
                      size_t msg_size,
                      uint8_t *signature_out,
                      uint8_t *signature_out_length) {
    G_called.endorsement_sign_calls++;

    if (!G_mocks.endorsement_sign) {
        return false;
    }

    assert(*signature_out_length >= MAX_SIGNATURE_LENGTH);

    memset(signature_out, 0xAA, MAX_SIGNATURE_LENGTH);
    *signature_out_length = MAX_SIGNATURE_LENGTH;

    return true;
}

bool endorsement_get_code_hash(uint8_t *code_hash_out,
                               uint8_t *code_hash_out_length) {
    G_called.endorsement_get_code_hash_calls++;

    if (!G_mocks.endorsement_get_code_hash) {
        return false;
    }

    assert(*code_hash_out_length >= HASH_SIZE);

    memcpy(code_hash_out, G_mock_app_hash, HASH_SIZE);
    *code_hash_out_length = HASH_SIZE;

    return true;
}

bool endorsement_get_public_key(uint8_t *public_key_out,
                                uint8_t *public_key_out_length) {
    G_called.endorsement_get_public_key_calls++;

    if (!G_mocks.endorsement_get_public_key) {
        return false;
    }

    assert(*public_key_out_length >= PUBKEY_UNCMP_LENGTH);

    memcpy(public_key_out, G_mock_pubkey, PUBKEY_UNCMP_LENGTH);
    *public_key_out_length = PUBKEY_UNCMP_LENGTH;

    return true;
}

// Helper functions
void setup(state_heartbeat_t initial_state, op_code_heartbeat_t op) {
    memset(&G_mocks, 0, sizeof(G_mocks));
    memset(&G_called, 0, sizeof(G_called));
    memset(&N_bc_state_var, 0, sizeof(N_bc_state_var));
    memset(G_comm_buffer, 0, sizeof(G_comm_buffer));
    memset(G_mock_app_hash, 0, sizeof(G_mock_app_hash));
    memset(G_mock_pubkey, 0, sizeof(G_mock_pubkey));
    memset(&G_hbt_ctx, 0, sizeof(G_hbt_ctx));

    // Set default mock return values to success
    G_mocks.endorsement_sign = true;
    G_mocks.endorsement_get_code_hash = true;
    G_mocks.endorsement_get_public_key = true;

    bool result = communication_init(G_comm_buffer, G_comm_buffer_size);
    assert(result);

    G_hbt_ctx.state = initial_state;
    SET_APDU_OP(op);
}

// Test cases
void test_ud_value_success() {
    printf("Testing OP_HBT_UD_VALUE success...\n");
    setup(STATE_HEARTBEAT_WAIT_UD_VALUE, OP_HBT_UD_VALUE);

    uint8_t best_block[HASH_SIZE];
    uint8_t last_auth_signed_btc_tx_hash[HASH_SIZE];
    memset(best_block, 0xAA, HASH_SIZE);
    memset(last_auth_signed_btc_tx_hash, 0xBB, HASH_SIZE);
    memcpy(N_bc_state_var.best_block, best_block, HASH_SIZE);
    memcpy(N_bc_state_var.last_auth_signed_btc_tx_hash,
           last_auth_signed_btc_tx_hash,
           HASH_SIZE);

    uint8_t ud_value[UD_VALUE_SIZE];
    memset(ud_value, 0x11, UD_VALUE_SIZE);
    memcpy(APDU_DATA_PTR, ud_value, UD_VALUE_SIZE);

    ASSERT_DOESNT_THROW({
        unsigned int tx = TX_FOR_DATA_SIZE(UD_VALUE_SIZE);
        tx = get_heartbeat(tx, &G_hbt_ctx);
        assert(tx == TX_FOR_DATA_SIZE(0));
    });

    assert(G_hbt_ctx.state == STATE_HEARTBEAT_READY);
    assert(G_hbt_ctx.msg_offset == HEARTBEAT_MSG_PREFIX_LENGTH + HASH_SIZE +
                                       LAST_SIGNED_TX_BYTES + UD_VALUE_SIZE);

    unsigned int offset = 0;
    ASSERT_MEMCMP(G_hbt_ctx.msg + offset,
                  HEARTBEAT_MSG_PREFIX,
                  HEARTBEAT_MSG_PREFIX_LENGTH);

    offset += HEARTBEAT_MSG_PREFIX_LENGTH;
    ASSERT_MEMCMP(G_hbt_ctx.msg + offset, N_bc_state_var.best_block, HASH_SIZE);

    offset += HASH_SIZE;
    ASSERT_MEMCMP(G_hbt_ctx.msg + offset,
                  N_bc_state_var.last_auth_signed_btc_tx_hash,
                  LAST_SIGNED_TX_BYTES);

    offset += LAST_SIGNED_TX_BYTES;
    ASSERT_MEMCMP(G_hbt_ctx.msg + offset, ud_value, UD_VALUE_SIZE);
}

void test_ud_value_ud_size_too_small() {
    printf("Testing OP_HBT_UD_VALUE with UD size too small...\n");
    setup(STATE_HEARTBEAT_WAIT_UD_VALUE, OP_HBT_UD_VALUE);

    // Test with less than UD_VALUE_SIZE bytes
    memset(APDU_DATA_PTR, 0x22, UD_VALUE_SIZE - 1);

    ASSERT_THROWS(
        {
            unsigned int tx = TX_FOR_DATA_SIZE(UD_VALUE_SIZE + 1);
            get_heartbeat(tx, &G_hbt_ctx);
        },
        ERR_HBT_PROT_INVALID);

    assert(G_hbt_ctx.state == STATE_HEARTBEAT_WAIT_UD_VALUE);
    assert(G_hbt_ctx.msg_offset == 0);
}

void test_ud_value_ud_size_too_large() {
    printf("Testing OP_HBT_UD_VALUE with UD size too large...\n");
    setup(STATE_HEARTBEAT_WAIT_UD_VALUE, OP_HBT_UD_VALUE);

    // Test with more than UD_VALUE_SIZE bytes
    memset(APDU_DATA_PTR, 0x33, UD_VALUE_SIZE + 1);

    ASSERT_THROWS(
        {
            unsigned int tx = TX_FOR_DATA_SIZE(UD_VALUE_SIZE + 1);
            get_heartbeat(tx, &G_hbt_ctx);
        },
        ERR_HBT_PROT_INVALID);

    assert(G_hbt_ctx.state == STATE_HEARTBEAT_WAIT_UD_VALUE);
    assert(G_hbt_ctx.msg_offset == 0);
}

void test_get_success() {
    printf("Testing OP_HBT_GET success...\n");
    setup(STATE_HEARTBEAT_READY, OP_HBT_GET);

    ASSERT_DOESNT_THROW({
        unsigned int tx = TX_FOR_DATA_SIZE(0);
        tx = get_heartbeat(tx, &G_hbt_ctx);
        assert(tx == TX_FOR_DATA_SIZE(MAX_SIGNATURE_LENGTH));
    });
    assert(G_called.endorsement_sign_calls == 1);

    uint8_t expected_signature[MAX_SIGNATURE_LENGTH];
    memset(expected_signature, 0xAA, MAX_SIGNATURE_LENGTH);
    ASSERT_MEMCMP(APDU_DATA_PTR, expected_signature, MAX_SIGNATURE_LENGTH);
}

void test_get_invalid_state() {
    printf("Testing OP_HBT_GET with invalid state...\n");

    // Set state to WAIT_UD_VALUE instead of READY
    setup(STATE_HEARTBEAT_WAIT_UD_VALUE, OP_HBT_GET);

    ASSERT_THROWS(
        {
            unsigned int tx = TX_FOR_DATA_SIZE(0);
            get_heartbeat(tx, &G_hbt_ctx);
        },
        ERR_HBT_PROT_INVALID);

    assert(G_called.endorsement_sign_calls == 0);
    assert(G_hbt_ctx.state == STATE_HEARTBEAT_WAIT_UD_VALUE);
}

void test_get_endorsement_sign_fails() {
    printf("Testing OP_HBT_GET when endorsement_sign fails...\n");
    setup(STATE_HEARTBEAT_READY, OP_HBT_GET);
    G_mocks.endorsement_sign = false;

    ASSERT_THROWS(
        {
            unsigned int tx = TX_FOR_DATA_SIZE(0);
            get_heartbeat(tx, &G_hbt_ctx);
        },
        ERR_HBT_INTERNAL);

    assert(G_called.endorsement_sign_calls == 1);
    assert(G_hbt_ctx.state == STATE_HEARTBEAT_READY);
}

void test_get_message_success() {
    printf("Testing OP_HBT_GET_MESSAGE success...\n");
    setup(STATE_HEARTBEAT_READY, OP_HBT_GET_MESSAGE);

    const uint8_t *expected_msg = "the-expected-message";
    unsigned int expected_msg_size = strlen(expected_msg);
    memcpy(G_hbt_ctx.msg, expected_msg, expected_msg_size);
    G_hbt_ctx.msg_offset = expected_msg_size;

    ASSERT_DOESNT_THROW({
        unsigned int tx = TX_FOR_DATA_SIZE(0);
        tx = get_heartbeat(tx, &G_hbt_ctx);
        assert(tx == TX_FOR_DATA_SIZE(expected_msg_size));
    });

    assert(G_hbt_ctx.msg_offset == expected_msg_size);
    ASSERT_MEMCMP(APDU_DATA_PTR, expected_msg, expected_msg_size);
    assert(G_hbt_ctx.state == STATE_HEARTBEAT_READY);
}

void test_get_message_invalid_state() {
    printf("Testing OP_HBT_GET_MESSAGE with invalid state...\n");
    setup(STATE_HEARTBEAT_WAIT_UD_VALUE, OP_HBT_GET_MESSAGE);

    ASSERT_THROWS(
        {
            unsigned int tx = TX_FOR_DATA_SIZE(0);
            get_heartbeat(tx, &G_hbt_ctx);
        },
        ERR_HBT_PROT_INVALID);

    assert(G_hbt_ctx.msg_offset == 0);
    assert(G_hbt_ctx.state == STATE_HEARTBEAT_WAIT_UD_VALUE);
}

void test_get_message_large_message_success() {
    printf("Testing OP_HBT_GET_MESSAGE maximum message size succeeds...\n");
    setup(STATE_HEARTBEAT_READY, OP_HBT_GET_MESSAGE);

    uint8_t large_msg[MAX_HEARTBEAT_MESSAGE_SIZE];
    memset(large_msg, 0xDD, sizeof(large_msg));
    memcpy(G_hbt_ctx.msg, large_msg, sizeof(large_msg));
    G_hbt_ctx.msg_offset = sizeof(large_msg);

    ASSERT_DOESNT_THROW({
        unsigned int tx = TX_FOR_DATA_SIZE(0);
        tx = get_heartbeat(tx, &G_hbt_ctx);
        assert(tx == TX_FOR_DATA_SIZE(sizeof(large_msg)));
    });

    assert(G_hbt_ctx.msg_offset == sizeof(large_msg));
    ASSERT_MEMCMP(APDU_DATA_PTR, large_msg, sizeof(large_msg));
    assert(G_hbt_ctx.state == STATE_HEARTBEAT_READY);
}

void test_get_message_offset_too_large_fails() {
    printf("Testing OP_HBT_GET_MESSAGE with offset too large fails...\n");
    setup(STATE_HEARTBEAT_READY, OP_HBT_GET_MESSAGE);

    // Set the offset to be too large
    memset(G_hbt_ctx.msg, 0xEE, sizeof(G_hbt_ctx.msg));
    G_hbt_ctx.msg_offset = sizeof(G_hbt_ctx.msg) + 1;

    ASSERT_THROWS(
        {
            unsigned int tx = TX_FOR_DATA_SIZE(0);
            get_heartbeat(tx, &G_hbt_ctx);
        },
        ERR_HBT_INTERNAL);

    assert(G_hbt_ctx.state == STATE_HEARTBEAT_READY);
}

void test_app_hash_success() {
    printf("Testing OP_HBT_APP_HASH success...\n");
    setup(STATE_HEARTBEAT_READY, OP_HBT_APP_HASH);

    const uint8_t *app_hash = "1234567890abcdef1234567890abcdef";
    memcpy(G_mock_app_hash, app_hash, HASH_SIZE);

    ASSERT_DOESNT_THROW({
        unsigned int tx = TX_FOR_DATA_SIZE(0);
        tx = get_heartbeat(tx, &G_hbt_ctx);
        assert(tx == TX_FOR_DATA_SIZE(HASH_SIZE));
    });

    assert(G_called.endorsement_get_code_hash_calls == 1);
    ASSERT_MEMCMP(APDU_DATA_PTR, app_hash, HASH_SIZE);
    assert(G_hbt_ctx.state == STATE_HEARTBEAT_READY);
}

void test_app_hash_endorsement_get_code_hash_fails() {
    printf("Testing OP_HBT_APP_HASH when endorsement_get_code_hash fails...\n");
    setup(STATE_HEARTBEAT_READY, OP_HBT_APP_HASH);

    const uint8_t *app_hash = "1234567890abcdef1234567890abcdef";
    memcpy(G_mock_app_hash, app_hash, HASH_SIZE);
    G_mocks.endorsement_get_code_hash = false;

    ASSERT_THROWS(
        {
            unsigned int tx = TX_FOR_DATA_SIZE(0);
            get_heartbeat(tx, &G_hbt_ctx);
        },
        ERR_HBT_INTERNAL);

    assert(G_called.endorsement_get_code_hash_calls == 1);
    assert(G_hbt_ctx.msg_offset == 0);
    assert(G_hbt_ctx.state == STATE_HEARTBEAT_READY);
}

void test_pubkey_success() {
    printf("Testing OP_HBT_PUBKEY success...\n");
    setup(STATE_HEARTBEAT_READY, OP_HBT_PUBKEY);

    const uint8_t *pubkey =
        "01234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    memcpy(G_mock_pubkey, pubkey, PUBKEY_UNCMP_LENGTH);

    ASSERT_DOESNT_THROW({
        unsigned int tx = TX_FOR_DATA_SIZE(0);
        tx = get_heartbeat(tx, &G_hbt_ctx);
        assert(tx == TX_FOR_DATA_SIZE(PUBKEY_UNCMP_LENGTH));
    });

    assert(G_called.endorsement_get_public_key_calls == 1);
    ASSERT_MEMCMP(APDU_DATA_PTR, pubkey, PUBKEY_UNCMP_LENGTH);
    assert(G_hbt_ctx.state == STATE_HEARTBEAT_READY);
}

void test_pubkey_endorsement_get_public_key_fails() {
    printf("Testing OP_HBT_PUBKEY when endorsement_get_public_key fails...\n");
    setup(STATE_HEARTBEAT_READY, OP_HBT_PUBKEY);

    const uint8_t *pubkey =
        "01234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    memcpy(G_mock_pubkey, pubkey, PUBKEY_UNCMP_LENGTH);
    G_mocks.endorsement_get_public_key = false;

    ASSERT_THROWS(
        {
            unsigned int tx = TX_FOR_DATA_SIZE(0);
            get_heartbeat(tx, &G_hbt_ctx);
        },
        ERR_HBT_INTERNAL);

    assert(G_called.endorsement_get_public_key_calls == 1);
    assert(G_hbt_ctx.state == STATE_HEARTBEAT_READY);
}

void test_invalid_operation() {
    printf("Testing invalid heartbeat operation...\n");
    setup(STATE_HEARTBEAT_READY, 0xFF);

    ASSERT_THROWS({ get_heartbeat(0, &G_hbt_ctx); }, ERR_HBT_PROT_INVALID);

    assert(G_hbt_ctx.state == STATE_HEARTBEAT_WAIT_UD_VALUE);
}

int main() {
    test_ud_value_success();
    test_ud_value_ud_size_too_small();
    test_ud_value_ud_size_too_large();

    test_get_success();
    test_get_invalid_state();
    test_get_endorsement_sign_fails();

    test_get_message_success();
    test_get_message_invalid_state();
    test_get_message_large_message_success();
    test_get_message_offset_too_large_fails();

    test_app_hash_success();
    test_app_hash_endorsement_get_code_hash_fails();

    test_pubkey_success();
    test_pubkey_endorsement_get_public_key_fails();

    test_invalid_operation();

    return 0;
}
