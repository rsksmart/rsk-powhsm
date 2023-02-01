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
#include <stdlib.h>
#include "ui_err.h"
#include "mock.h"
#include "assert_utils.h"
#include "signer_authorization.h"
#include "testing.h"

sigaut_t G_sigaut_ctx;

#define TEST_SIGAUT_SIGNATURE_LEN 75
static const unsigned char G_valid_signatures[][TEST_SIGAUT_SIGNATURE_LEN] = {
    "\xd1\x98\x62\x0e\x60\x25\x5a\xd0\xb3\xc4\x1f\x0b\x0c\x7f\x7e\xd4\x94\xa9"
    "\xfe\x45\x29\xe8\x9b\xe0\x77\xb3\x95\x87\x53\xd7\xad\x93\xed\xa2\x7e\x02"
    "\x8a\x9f\x3e\x7d\x9a\x07\xd5\x29\xe3\x8b\xf5\xb2\xb1\x26\x86\x0a\x02\xed"
    "\x8f\xda\x83\xb6\xe2\x1d\xd3\xac\x65\x56\xe0\x53\x8f\x2e\xa8\x05\x4a\x8c"
    "\x43\x26\x8a",

    "\xf9\x6f\x6b\x3e\x3c\xe5\x08\x8b\x46\x83\xbe\x87\x3c\x07\x5a\x61\x4a\x8c"
    "\x65\x64\x9a\x4c\xa8\x6a\x78\xa0\xc6\x6c\x9e\x47\x7e\x20\x5f\x32\x2e\xc9"
    "\x89\x9e\x0f\x4d\x00\x60\xab\x30\x69\x28\xcd\x69\x43\x01\x30\x36\x01\x33"
    "\xf1\x32\x26\xcd\x1c\x62\x3b\x12\xf7\xf4\xef\x69\x87\x8b\xe8\x7d\xbe\x60"
    "\x86\x4d\xa2",

    "\x4b\xf1\xc6\x36\xef\x35\x06\x39\x42\x9e\x3e\xf4\x02\xd3\xd1\x63\xa0\x59"
    "\x73\x8d\x39\x3d\xd9\x38\xa0\x34\xa3\x2e\xf7\xf8\xe2\xbe\xe7\x2d\xbd\x07"
    "\xf0\x8c\x00\xc0\x5c\x62\xee\x1a\x5a\xf4\x24\xe1\x9d\x03\x83\x36\x1b\xbf"
    "\x3e\x7f\x55\x61\xf0\x52\x42\x21\x1d\xea\xe8\xfc\x26\x5d\xa1\x83\x04\xc7"
    "\xe0\xca\x4e",
};

static const uint8_t G_authorizers_pubkeys[][AUTHORIZED_SIGNER_PUBKEY_LENGTH] =
    AUTHORIZERS_PUBKEYS;
static const int G_num_pubkeys =
    sizeof(G_authorizers_pubkeys) / sizeof(G_authorizers_pubkeys[0]);

static const unsigned char G_authorized_signer_hash[] =
    "AUTHORIZED HASH 123456789abcdef";

// Helper functions
static bool is_key_authorized(cx_ecfp_public_key_t *key) {
    for (int i = 0; i < G_num_pubkeys; i++) {
        if (0 ==
            memcmp(G_authorizers_pubkeys[i], key->W, PUBKEY_UNCMP_LENGTH)) {
            return true;
        }
    }
    return false;
}

static unsigned char *get_signature(cx_ecfp_public_key_t *key) {
    for (int i = 0; i < G_num_pubkeys; i++) {
        if (0 ==
            memcmp(G_authorizers_pubkeys[i], key->W, PUBKEY_UNCMP_LENGTH)) {
            return (unsigned char *)G_valid_signatures[i];
        }
    }
    ASSERT_FAIL();
}

int cx_keccak_init(cx_sha3_t *hash, int size) {
    // Size is passed in bits for this call
    int size_in_bytes = size / 8;
    assert(size_in_bytes <= sizeof(hash->hash));

    hash->size_in_bytes = size_in_bytes;
    memset(hash->hash, 0xff, sizeof(hash->hash));
    return 0;
}

int cx_hash(cx_hash_t *hash,
            int mode,
            unsigned char *in,
            unsigned int len,
            unsigned char *out) {
    // We don't need an actual hash algorithm for the purpose of this test,
    // so we just XOR the input with the current hash to make sure the correct
    // data was passed
    assert(len <= hash->size_in_bytes);
    for (int i = 0; i < len; i++) {
        hash->hash[i] ^= in[i];
    }

    if (mode & CX_LAST) {
        memcpy(out, hash->hash, hash->size_in_bytes);
    }
    return 0;
}

int cx_ecfp_init_public_key(cx_curve_t curve,
                            unsigned char *rawkey,
                            unsigned int key_len,
                            cx_ecfp_public_key_t *key) {
    assert(NULL != rawkey);
    assert(NULL != key);
    assert(CX_CURVE_256K1 == curve);
    assert(65 == key_len);

    memcpy(key->W, rawkey, key_len);
    key->W_len = key_len;

    return 0;
}

int cx_ecdsa_verify(cx_ecfp_public_key_t *key,
                    int mode,
                    cx_md_t hashID,
                    unsigned char *hash,
                    unsigned int hash_len,
                    unsigned char *sig,
                    unsigned int sig_len) {
    // We don't need to perform an actual verification for this test, we just
    // assert that this was called with the correct parameters and verify wheter
    // or not one of the authorized keys and the corresponding mock signature
    // were provided
    assert(key == &G_sigaut_ctx.pubkey);
    assert(hash == G_sigaut_ctx.auth_hash);
    if (is_key_authorized(key)) {
        return (0 ==
                memcmp(sig, get_signature(key), TEST_SIGAUT_SIGNATURE_LEN));
    }
    return 0;
}

void assert_sigaut_ctx_reset(sigaut_t *sigaut_ctx) {
    assert(sigaut_state_wait_signer_version == sigaut_ctx->state);
    ASSERT_STRUCT_CLEARED(sigaut_signer_t, sigaut_ctx->signer);
    ASSERT_ARRAY_CLEARED(sigaut_ctx->authorized_signer_verified);
    ASSERT_STRUCT_CLEARED(cx_sha3_t, sigaut_ctx->auth_hash_ctx);
    ASSERT_STRUCT_CLEARED(cx_ecfp_public_key_t, sigaut_ctx->pubkey);
    ASSERT_ARRAY_CLEARED(sigaut_ctx->buf);
    ASSERT_ARRAY_CLEARED(sigaut_ctx->auth_hash);
}

void test_reset_signer_authorization() {
    printf("Test reset signer authorization...\n");

    reset_signer_authorization(&G_sigaut_ctx);
    assert_sigaut_ctx_reset(&G_sigaut_ctx);
}

void test_init_signer_authorization() {
    printf("Test init signer authorization...\n");

    init_signer_authorization();
    sigaut_signer_t *signer = get_authorized_signer_info();
    assert(NULL != signer);
    ASSERT_MEMCMP(PARAM_INITIAL_SIGNER_HASH, signer->hash, HASH_LENGTH);
    assert(PARAM_INITIAL_SIGNER_ITERATION == signer->iteration);
}

void test_op_sigaut_get_current() {
    printf("Test OP_SIGAUT_GET_CURRENT...\n");

    unsigned int rx;
    reset_signer_authorization(&G_sigaut_ctx);
    // OP_SIGAUT_GET_CURRENT
    SET_APDU("\x80\x81\x00", rx);
    assert((3 + sizeof(sigaut_signer_t)) ==
           do_authorize_signer(rx, &G_sigaut_ctx));

    ASSERT_APDU("\x80\x81\x00" PARAM_INITIAL_SIGNER_HASH "\x00\x01");
}

void test_op_sigaut_sigver() {
    printf("Test OP_SIGAUT_SIGVER...\n");

#define TEST_OP_SIGAUT_SIGNER_HASH                                             \
    "\xe8\xe8\xa8\xe8\x1a\x2d\x4d\x22\xfa\xbb\xa2\xa1\x3d\x8d\x04\x1f\x89\xdd" \
    "\x65\xa4\x73\xc5\xc6\x7c\x1f\x24\xe9\x94\x08\x0b\xf1\x34"

    unsigned int rx;
    reset_signer_authorization(&G_sigaut_ctx);
    G_sigaut_ctx.state = sigaut_state_wait_signer_version;

    // OP_SIGAUT_SIGVER + hash + iteration
    SET_APDU("\x80\x81\x01" TEST_OP_SIGAUT_SIGNER_HASH "\x00\x02", rx);
    assert(3 == do_authorize_signer(rx, &G_sigaut_ctx));

    assert(sigaut_state_wait_signature == G_sigaut_ctx.state);
    ASSERT_MEMCMP(TEST_OP_SIGAUT_SIGNER_HASH,
                  G_sigaut_ctx.signer.hash,
                  sizeof(G_sigaut_ctx.signer.hash));
    assert(2 == G_sigaut_ctx.signer.iteration);

    ASSERT_MEMCMP(
        "\xee\xba\xb4\xad\x98\x83\x99\xab\xae\xfc\xac\xe5\xf1\xf6\xf4\xfe\xad"
        "\xed\x9a\x8c\x8c\x9e\x98\x9a\xc5\xf5\xff\xff\xff\xff\xff\xff",
        G_sigaut_ctx.auth_hash,
        HASH_LENGTH);
}

void test_op_sigaut_sigver_invalid_iteration() {
    printf("Test OP_SIGAUT_SIGVER (invalid iteration)...\n");

    unsigned int rx;
    reset_signer_authorization(&G_sigaut_ctx);
    G_sigaut_ctx.state = sigaut_state_wait_signer_version;

    // OP_SIGAUT_SIGVER + hash + iteration
    SET_APDU("\x80\x81\x01" PARAM_INITIAL_SIGNER_HASH "\x00\x01", rx);

    BEGIN_TRY {
        TRY {
            do_authorize_signer(rx, &G_sigaut_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(ERR_SIGAUT_INVALID_ITERATION == e);
        }
        FINALLY {
        }
    }
    END_TRY;

    assert_sigaut_ctx_reset(&G_sigaut_ctx);
}

void test_op_sigaut_sigver_invalid_input() {
    printf("Test OP_SIGAUT_SIGVER (invalid input)...\n");

    unsigned int rx;
    reset_signer_authorization(&G_sigaut_ctx);
    G_sigaut_ctx.state = sigaut_state_wait_signer_version;

    // OP_SIGAUT_SIGVER + hash + iteration
    SET_APDU("\x80\x81\x01" PARAM_INITIAL_SIGNER_HASH, rx);

    BEGIN_TRY {
        TRY {
            do_authorize_signer(rx, &G_sigaut_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(ERR_UI_PROT_INVALID == e);
        }
        FINALLY {
        }
    }
    END_TRY;

    assert_sigaut_ctx_reset(&G_sigaut_ctx);
}

void test_op_sigaut_sign() {
    printf("Test OP_SIGAUT_SIGN...\n");

    unsigned int rx;
    reset_signer_authorization(&G_sigaut_ctx);
    G_sigaut_ctx.state = sigaut_state_wait_signature;

    memcpy(G_sigaut_ctx.signer.hash, G_authorized_signer_hash, HASH_LENGTH);
    G_sigaut_ctx.signer.iteration = 2;

    // Perform 2 of 3 authorization

    G_sigaut_ctx.pubkey.W_len = PUBKEY_UNCMP_LENGTH;
    memcpy(
        G_sigaut_ctx.pubkey.W, G_authorizers_pubkeys[0], PUBKEY_UNCMP_LENGTH);
    // OP_SIGAUT_SIGN + G_valid_signature[0]
    SET_APDU("\x80\x81\x02\xd1\x98\x62\x0e\x60\x25\x5a\xd0\xb3\xc4\x1f\x0b\x0c"
             "\x7f\x7e\xd4\x94\xa9\xfe\x45\x29\xe8\x9b\xe0\x77\xb3\x95\x87\x53"
             "\xd7\xad\x93\xed\xa2\x7e\x02\x8a\x9f\x3e\x7d\x9a\x07\xd5\x29\xe3"
             "\x8b\xf5\xb2\xb1\x26\x86\x0a\x02\xed\x8f\xda\x83\xb6\xe2\x1d\xd3"
             "\xac\x65\x56\xe0\x53\x8f\x2e\xa8\x05\x4a\x8c\x43\x26\x8a",
             rx);
    assert(4 == do_authorize_signer(rx, &G_sigaut_ctx));
    assert(RES_SIGAUT_MORE == APDU_DATA_PTR[0]);
    ASSERT_STRUCT_CLEARED(cx_ecfp_public_key_t, G_sigaut_ctx.pubkey);

    G_sigaut_ctx.pubkey.W_len = PUBKEY_UNCMP_LENGTH;
    memcpy(
        G_sigaut_ctx.pubkey.W, G_authorizers_pubkeys[1], PUBKEY_UNCMP_LENGTH);
    // OP_SIGAUT_SIGN + G_valid_signature[1]
    SET_APDU("\x80\x81\x02\xf9\x6f\x6b\x3e\x3c\xe5\x08\x8b\x46\x83\xbe\x87\x3c"
             "\x07\x5a\x61\x4a\x8c\x65\x64\x9a\x4c\xa8\x6a\x78\xa0\xc6\x6c\x9e"
             "\x47\x7e\x20\x5f\x32\x2e\xc9\x89\x9e\x0f\x4d\x00\x60\xab\x30\x69"
             "\x28\xcd\x69\x43\x01\x30\x36\x01\x33\xf1\x32\x26\xcd\x1c\x62\x3b"
             "\x12\xf7\xf4\xef\x69\x87\x8b\xe8\x7d\xbe\x60\x86\x4d\xa2",
             rx);
    assert(4 == do_authorize_signer(rx, &G_sigaut_ctx));
    assert(RES_SIGAUT_SUCCESS == APDU_DATA_PTR[0]);
    ASSERT_MEMCMP(G_authorized_signer_hash,
                  N_current_signer_status_var.signer.hash,
                  HASH_LENGTH);
    assert(2 == N_current_signer_status_var.signer.iteration);
    assert_sigaut_ctx_reset(&G_sigaut_ctx);
}

void test_op_sigaut_sign_not_enough_signatures() {
    printf("Test OP_SIGAUT_SIGN (not enough signatures)...\n");

    unsigned int rx;
    reset_signer_authorization(&G_sigaut_ctx);
    G_sigaut_ctx.state = sigaut_state_wait_signature;

    G_sigaut_ctx.pubkey.W_len = PUBKEY_UNCMP_LENGTH;
    memcpy(
        G_sigaut_ctx.pubkey.W, G_authorizers_pubkeys[0], PUBKEY_UNCMP_LENGTH);
    // OP_SIGAUT_SIGN + G_valid_signature[0]
    SET_APDU("\x80\x81\x02\xd1\x98\x62\x0e\x60\x25\x5a\xd0\xb3\xc4\x1f\x0b\x0c"
             "\x7f\x7e\xd4\x94\xa9\xfe\x45\x29\xe8\x9b\xe0\x77\xb3\x95\x87\x53"
             "\xd7\xad\x93\xed\xa2\x7e\x02\x8a\x9f\x3e\x7d\x9a\x07\xd5\x29\xe3"
             "\x8b\xf5\xb2\xb1\x26\x86\x0a\x02\xed\x8f\xda\x83\xb6\xe2\x1d\xd3"
             "\xac\x65\x56\xe0\x53\x8f\x2e\xa8\x05\x4a\x8c\x43\x26\x8a",
             rx);
    assert(4 == do_authorize_signer(rx, &G_sigaut_ctx));
    assert(RES_SIGAUT_MORE == APDU_DATA_PTR[0]);
    ASSERT_STRUCT_CLEARED(cx_ecfp_public_key_t, G_sigaut_ctx.pubkey);

    // Send same valid signature with same pubkey
    G_sigaut_ctx.pubkey.W_len = PUBKEY_UNCMP_LENGTH;
    memcpy(
        G_sigaut_ctx.pubkey.W, G_authorizers_pubkeys[0], PUBKEY_UNCMP_LENGTH);
    // OP_SIGAUT_SIGN + G_valid_signature[0]
    SET_APDU("\x80\x81\x02\xd1\x98\x62\x0e\x60\x25\x5a\xd0\xb3\xc4\x1f\x0b\x0c"
             "\x7f\x7e\xd4\x94\xa9\xfe\x45\x29\xe8\x9b\xe0\x77\xb3\x95\x87\x53"
             "\xd7\xad\x93\xed\xa2\x7e\x02\x8a\x9f\x3e\x7d\x9a\x07\xd5\x29\xe3"
             "\x8b\xf5\xb2\xb1\x26\x86\x0a\x02\xed\x8f\xda\x83\xb6\xe2\x1d\xd3"
             "\xac\x65\x56\xe0\x53\x8f\x2e\xa8\x05\x4a\x8c\x43\x26\x8a",
             rx);
    assert(4 == do_authorize_signer(rx, &G_sigaut_ctx));
    assert(RES_SIGAUT_MORE == APDU_DATA_PTR[0]);

    // Send same valid signature with another pubkey
    G_sigaut_ctx.pubkey.W_len = PUBKEY_UNCMP_LENGTH;
    memcpy(
        G_sigaut_ctx.pubkey.W, G_authorizers_pubkeys[1], PUBKEY_UNCMP_LENGTH);
    // OP_SIGAUT_SIGN + G_valid_signature[0]
    SET_APDU("\x80\x81\x02\xd1\x98\x62\x0e\x60\x25\x5a\xd0\xb3\xc4\x1f\x0b\x0c"
             "\x7f\x7e\xd4\x94\xa9\xfe\x45\x29\xe8\x9b\xe0\x77\xb3\x95\x87\x53"
             "\xd7\xad\x93\xed\xa2\x7e\x02\x8a\x9f\x3e\x7d\x9a\x07\xd5\x29\xe3"
             "\x8b\xf5\xb2\xb1\x26\x86\x0a\x02\xed\x8f\xda\x83\xb6\xe2\x1d\xd3"
             "\xac\x65\x56\xe0\x53\x8f\x2e\xa8\x05\x4a\x8c\x43\x26\x8a",
             rx);
    assert(4 == do_authorize_signer(rx, &G_sigaut_ctx));
    assert(RES_SIGAUT_MORE == APDU_DATA_PTR[0]);

    // Send invalid signature with valid pubkey
    G_sigaut_ctx.pubkey.W_len = PUBKEY_UNCMP_LENGTH;
    memcpy(
        G_sigaut_ctx.pubkey.W, G_authorizers_pubkeys[0], PUBKEY_UNCMP_LENGTH);
    // OP_SIGAUT_SIGN + invalid signature
    SET_APDU("\x80\x81\x02\x01\x02\x03\x04\x60\x25\x5a\xd0\xb3\xc4\x1f\x0b\x0c"
             "\x7f\x7e\xd4\x94\xa9\xfe\x45\x29\xe8\x9b\xe0\x77\xb3\x95\x87\x53"
             "\xd7\xad\x93\xed\xa2\x7e\x02\x8a\x9f\x3e\x7d\x9a\x07\xd5\x29\xe3"
             "\x8b\xf5\xb2\xb1\x26\x86\x0a\x02\xed\x8f\xda\x83\xb6\xe2\x1d\xd3"
             "\xac\x65\x56\xe0\x53\x8f\x2e\xa8\x05\x4a\x8c\x43\x26\x8a",
             rx);
    assert(4 == do_authorize_signer(rx, &G_sigaut_ctx));
    assert(RES_SIGAUT_MORE == APDU_DATA_PTR[0]);
}

void test_op_sigaut_get_auth_count() {
    printf("Test OP_SIGAUT_GET_AUTH_COUNT...\n");

    unsigned int rx;
    reset_signer_authorization(&G_sigaut_ctx);
    // OP_SIGAUT_GET_AUTH_COUNT
    SET_APDU("\x80\x81\x03", rx);
    assert(4 == do_authorize_signer(rx, &G_sigaut_ctx));
    assert(3 == APDU_DATA_PTR[0]);
}

void test_op_sigaut_get_auth_at() {
    printf("Test OP_SIGAUT_GET_AUTH_AT...\n");

    unsigned int rx;
    reset_signer_authorization(&G_sigaut_ctx);

    // OP_SIGAUT_GET_AUTH_AT[0]
    SET_APDU("\x80\x81\x04\x00", rx);
    assert(TX_FOR_DATA_SIZE(sizeof(G_authorizers_pubkeys[0])) ==
           do_authorize_signer(rx, &G_sigaut_ctx));
    ASSERT_MEMCMP(APDU_DATA_PTR,
                  G_authorizers_pubkeys[0],
                  sizeof(G_authorizers_pubkeys[0]));

    // OP_SIGAUT_GET_AUTH_AT[1]
    SET_APDU("\x80\x81\x04\x01", rx);
    assert(TX_FOR_DATA_SIZE(sizeof(G_authorizers_pubkeys[1])) ==
           do_authorize_signer(rx, &G_sigaut_ctx));
    ASSERT_MEMCMP(APDU_DATA_PTR,
                  G_authorizers_pubkeys[1],
                  sizeof(G_authorizers_pubkeys[1]));

    // OP_SIGAUT_GET_AUTH_AT[2]
    SET_APDU("\x80\x81\x04\x02", rx);
    assert(TX_FOR_DATA_SIZE(sizeof(G_authorizers_pubkeys[2])) ==
           do_authorize_signer(rx, &G_sigaut_ctx));
    ASSERT_MEMCMP(APDU_DATA_PTR,
                  G_authorizers_pubkeys[2],
                  sizeof(G_authorizers_pubkeys[2]));
}

void test_is_authorized_signer() {
    printf("Test is signer authorized...\n");
    reset_signer_authorization(&G_sigaut_ctx);

    memcpy(N_current_signer_status_var.signer.hash,
           G_authorized_signer_hash,
           HASH_LENGTH);
    assert(is_authorized_signer((unsigned char *)G_authorized_signer_hash));

    unsigned char wrong_hash[] = "A WRONG HASH - 123456789abcdef0";
    assert(!is_authorized_signer(wrong_hash));
}

void test_get_authorized_signer_info() {
    printf("Test get signer authorization\n");

    memcpy(N_current_signer_status_var.signer.hash,
           G_authorized_signer_hash,
           HASH_LENGTH);
    N_current_signer_status_var.signer.iteration = 9;

    sigaut_signer_t *signer = get_authorized_signer_info();
    assert(NULL != signer);
    ASSERT_MEMCMP(G_authorized_signer_hash, signer->hash, HASH_LENGTH);
    assert(9 == signer->iteration);
}

int main() {
    test_reset_signer_authorization();
    test_init_signer_authorization();
    test_op_sigaut_get_current();
    test_op_sigaut_sigver();
    test_op_sigaut_sigver_invalid_iteration();
    test_op_sigaut_sigver_invalid_input();
    test_op_sigaut_sign();
    test_op_sigaut_sign_not_enough_signatures();
    test_op_sigaut_get_auth_count();
    test_op_sigaut_get_auth_at();
    test_is_authorized_signer();
    test_get_authorized_signer_info();

    return 0;
}