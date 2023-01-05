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
#include "apdu_utils.h"
#include "assert_utils.h"
#include "err.h"

#define PUBLIC_KEY                                                             \
    "\x0b\xe6\xd7\x1d\x5c\x2b\x06\x36\x03\x53\xfb\xd8\x22\x7a\xb3\xab\xfc\x3d" \
    "\x46\x6a\x5f\x74\xdc\x28\xc2\xb7\x3e\xb0\x95\x2b\xec\x20\x87\x89\x35\xa7" \
    "\xe5\x6c\x84\xd0\xb2\xad\xae\x28\x58\x40\xd0\x24\xd5\x12\x6c\x7a\x3b\x6c" \
    "\x34\xc5\x22\x89\x42\x0b\x32\x08\xf2\x4d"
#define PRIVATE_KEY                                                            \
    "\xce\x1c\xa0\xf8\xf6\x40\x4b\xfd\x7a\x0a\x33\x80\xd3\x8c\x21\x5c\x89\x31" \
    "\x61\x91\xb5\x45\x62\xd8\x32\x68\xca\x57\x01\x73\x30\xfc"
#define SIGNER_HASH                                                            \
    "\xdd\xa7\x70\x05\x55\xa3\x7b\x75\x34\x29\x1b\x96\x2d\x9f\x41\x41\xb9\x64" \
    "\x48\xda\xd7\x12\x81\xef\x7c\x2d\x61\x49\x4c\xcb\xb8\x59"
#define MSG_SIGNATURE                                                          \
    "\xc0\xc5\xf8\x75\xdc\xdb\x74\x64\x68\x2a\x30\xd5\x44\xc8\x23\xed\xb8\x8e" \
    "\x73\x31\xc4\xac\x72\x34\xcb\xae\xb0\x56\x07\x13\x6b\x57"

// Global mock variables
static att_t G_att_ctx;
static sigaut_signer_t G_signer_info;
static cx_ecfp_private_key_t G_priv_key;
static unsigned char G_path[PUBKEY_PATH_LENGTH];

// Global onboarding flag
const unsigned char N_onboarded_ui[1];

// Helper functions
void set_public_key(cx_ecfp_public_key_t *pubkey, char *rawkey) {
    pubkey->W_len = strlen(rawkey);
    memcpy(pubkey->W, rawkey, pubkey->W_len);
}

void set_private_key(cx_ecfp_private_key_t *privkey, unsigned char *rawkey) {
    privkey->d_len = strlen((const char *)rawkey);
    memcpy(privkey->d, rawkey, privkey->d_len);
}

// cx mocks
int cx_ecdsa_init_private_key(cx_curve_t curve,
                              unsigned char *rawkey,
                              unsigned int key_len,
                              cx_ecfp_private_key_t *key) {
    assert(CX_CURVE_256K1 == curve);
    ASSERT_STR_N_EQUALS(rawkey, PRIVATE_KEY, KEYLEN);
    assert(rawkey == (unsigned char *)G_att_ctx.priv_key_data);
    assert(key == &G_att_ctx.priv_key);
    assert(KEYLEN == key_len);
    set_private_key(key, rawkey);
    return 0;
}

int cx_ecfp_generate_pair(cx_curve_t curve,
                          cx_ecfp_public_key_t *pubkey,
                          cx_ecfp_private_key_t *privkey,
                          int keepprivate) {
    assert(CX_CURVE_256K1 == curve);
    assert(pubkey == &G_att_ctx.pub_key);
    assert(privkey == &G_att_ctx.priv_key);
    ASSERT_STR_N_EQUALS(PRIVATE_KEY, privkey->d, KEYLEN);
    assert(1 == keepprivate);
    set_public_key(pubkey, PUBLIC_KEY);
    return 0;
}

// os mocks
unsigned int os_endorsement_get_code_hash(unsigned char *buffer) {
    // Should not be called for the current implementation
    ASSERT_FAIL();
}

unsigned int os_endorsement_key2_derive_sign_data(unsigned char *src,
                                                  unsigned int srcLength,
                                                  unsigned char *signature) {
    assert(src == (unsigned char *)G_att_ctx.msg);
    assert(srcLength == G_att_ctx.msg_offset);
    assert(signature == APDU_DATA_PTR);
    memcpy(signature, MSG_SIGNATURE, sizeof(MSG_SIGNATURE));

    return strlen(MSG_SIGNATURE);
}

void os_perso_derive_node_bip32(cx_curve_t curve,
                                unsigned int *path,
                                unsigned int pathLength,
                                unsigned char *privateKey,
                                unsigned char *chain) {
    assert(CX_CURVE_256K1 == curve);
    assert(path == (unsigned int *)G_att_ctx.path);
    assert(privateKey == (unsigned char *)G_att_ctx.priv_key_data);
    ASSERT_STR_N_EQUALS(path, PUBKEY_PATH, PUBKEY_PATH_LENGTH);
    ASSERT_STR_N_EQUALS(privateKey, PRIVATE_KEY, KEYLEN);
    assert(NULL == chain);
}

void os_memmove(void *dst, const void *src, unsigned int length) {
    memmove(dst, src, length);
}

// signer_authorization mocks
sigaut_signer_t *get_authorized_signer_info() {
    memcpy(G_signer_info.hash, SIGNER_HASH, sizeof(SIGNER_HASH));
    G_signer_info.iteration = 9;
    return &G_signer_info;
}

// Unit tests
void test_reset_attestation() {
    printf("Test reset attestation...\n");
    memcpy(G_att_ctx.msg, "a-msg", strlen("a-msg"));
    G_att_ctx.msg_offset = strlen("a-msg");
    memcpy(G_att_ctx.path, "a-path", strlen("a-path"));
    set_private_key(&G_att_ctx.priv_key, (unsigned char *)PRIVATE_KEY);
    set_public_key(&G_att_ctx.pub_key, PUBLIC_KEY);

    reset_attestation(&G_att_ctx);
    ASSERT_STRUCT_CLEARED(att_t, G_att_ctx);
    assert(att_stage_wait_ud_value == G_att_ctx.stage);
}

void test_get_attestation_ud_value() {
    printf("Test ATT_OP_UD_VALUE...\n");
    reset_attestation(&G_att_ctx);
    *(unsigned char *)N_onboarded_ui = 1;
    memcpy(G_att_ctx.priv_key_data, PRIVATE_KEY, sizeof(PRIVATE_KEY));
    G_att_ctx.stage = att_stage_wait_ud_value;
    // CLA + INS_ATTESTATION + ATT_OP_UD_VALUE + UD_VALUE
    unsigned int rx = set_apdu(
        "\x80\x50\x01\x46\x8d\xa8\x7f\x6a\x85\xe6\x40\x93\x27\xe1\x17\xe8"
        "\xc7\xd2\x11\x0c\x73\x60\x22\x26\xbb\xb5\xed\xf2\x7d\x98\xc8\xa3"
        "\x1b\xcc\xf0");

    assert(3 == get_attestation(rx, &G_att_ctx));
    // PREFIX + UD_VALUE + Compressed pubkey + Signer hash + Iteration
    ASSERT_STR_EQUALS(
        "HSM:UI:3.0"
        "\x46\x8d\xa8\x7f\x6a\x85\xe6\x40\x93\x27\xe1\x17\xe8\xc7\xd2\x11\x0c"
        "\x73\x60\x22\x26\xbb\xb5\xed\xf2\x7d\x98\xc8\xa3\x1b\xcc\xf0"
        "\x03\xe6\xd7\x1d\x5c\x2b\x06\x36\x03\x53\xfb\xd8\x22\x7a\xb3\xab\xfc"
        "\x3d\x46\x6a\x5f\x74\xdc\x28\xc2\xb7\x3e\xb0\x95\x2b\xec\x20\x87"
        "\xdd\xa7\x70\x05\x55\xa3\x7b\x75\x34\x29\x1b\x96\x2d\x9f\x41\x41\xb9"
        "\x64\x48\xda\xd7\x12\x81\xef\x7c\x2d\x61\x49\x4c\xcb\xb8\x59"
        "\x00\x09",
        G_att_ctx.msg);
    assert(att_stage_ready == G_att_ctx.stage);
}

void test_get_attestation_ud_value_wrong_stage() {
    printf("Test ATT_OP_UD_VALUE (wrong stage)...\n");
    reset_attestation(&G_att_ctx);
    *(unsigned char *)N_onboarded_ui = 1;
    memcpy(G_att_ctx.priv_key_data, PRIVATE_KEY, sizeof(PRIVATE_KEY));
    G_att_ctx.stage = att_stage_ready;
    // CLA + INS_ATTESTATION + ATT_OP_UD_VALUE + UD_VALUE
    set_apdu("\x80\x50\x01\x46\x8d\xa8\x7f\x6a\x85\xe6\x40\x93\x27\xe1\x17\xe8"
             "\xc7\xd2\x11\x0c\x73\x60\x22\x26\xbb\xb5\xed\xf2\x7d\x98\xc8\xa3"
             "\x1b\xcc\xf0");

    BEGIN_TRY {
        TRY {
            get_attestation(35, &G_att_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(PROT_INVALID == e);
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_get_msg() {
    printf("Test ATT_OP_GET_MSG...\n");
    reset_attestation(&G_att_ctx);
    *(unsigned char *)N_onboarded_ui = 1;
    memcpy(
        G_att_ctx.msg,
        "HSM:UI:3.0"
        "\x46\x8d\xa8\x7f\x6a\x85\xe6\x40\x93\x27\xe1\x17\xe8\xc7\xd2\x11\x0c"
        "\x73\x60\x22\x26\xbb\xb5\xed\xf2\x7d\x98\xc8\xa3\x1b\xcc\xf0"
        "\x03\xe6\xd7\x1d\x5c\x2b\x06\x36\x03\x53\xfb\xd8\x22\x7a\xb3\xab\xfc"
        "\x3d\x46\x6a\x5f\x74\xdc\x28\xc2\xb7\x3e\xb0\x95\x2b\xec\x20\x87"
        "\xdd\xa7\x70\x05\x55\xa3\x7b\x75\x34\x29\x1b\x96\x2d\x9f\x41\x41\xb9"
        "\x64\x48\xda\xd7\x12\x81\xef\x7c\x2d\x61\x49\x4c\xcb\xb8\x59"
        "\x00\x09",
        ATT_MESSAGE_SIZE);
    G_att_ctx.msg_offset = ATT_MESSAGE_SIZE;
    G_att_ctx.stage = att_stage_ready;

    // CLA + INS_ATTESTATION + ATT_OP_GET_MSG + PAGE_NUM (0)
    set_apdu("\x80\x50\x02\x00");
    assert((APDU_TOTAL_DATA_SIZE_OUT + 3) == get_attestation(4, &G_att_ctx));
    ASSERT_APDU(
        "\x80\x50\x02\x00"
        "HSM:UI:3.0"
        "\x46\x8d\xa8\x7f\x6a\x85\xe6\x40\x93\x27\xe1\x17\xe8\xc7\xd2\x11\x0c"
        "\x73\x60\x22\x26\xbb\xb5\xed\xf2\x7d\x98\xc8\xa3\x1b\xcc\xf0"
        "\x03\xe6\xd7\x1d\x5c\x2b\x06\x36\x03\x53\xfb\xd8\x22\x7a\xb3\xab\xfc"
        "\x3d\x46\x6a\x5f\x74\xdc\x28\xc2\xb7\x3e\xb0\x95\x2b\xec\x20\x87"
        "\xdd\xa7\x70\x05");

    // CLA + INS_ATTESTATION + ATT_OP_GET_MSG + PAGE_NUM (1)
    set_apdu("\x80\x50\x02\x01");
    assert(34 == get_attestation(4, &G_att_ctx));
    ASSERT_APDU("\x80\x50\x02\x00"
                "\x55\xa3\x7b\x75\x34\x29\x1b\x96\x2d\x9f\x41\x41\xb9"
                "\x64\x48\xda\xd7\x12\x81\xef\x7c\x2d\x61\x49\x4c\xcb\xb8\x59"
                "\x00\x09");
}

void test_get_attestation_get_msg_wrong_stage() {
    printf("Test ATT_OP_GET_MSG (wrong stage)...\n");
    reset_attestation(&G_att_ctx);
    *(unsigned char *)N_onboarded_ui = 1;
    memcpy(
        &G_att_ctx.msg,
        "HSM:UI:3.0"
        "\x46\x8d\xa8\x7f\x6a\x85\xe6\x40\x93\x27\xe1\x17\xe8\xc7\xd2\x11\x0c"
        "\x73\x60\x22\x26\xbb\xb5\xed\xf2\x7d\x98\xc8\xa3\x1b\xcc\xf0"
        "\x03\xe6\xd7\x1d\x5c\x2b\x06\x36\x03\x53\xfb\xd8\x22\x7a\xb3\xab\xfc"
        "\x3d\x46\x6a\x5f\x74\xdc\x28\xc2\xb7\x3e\xb0\x95\x2b\xec\x20\x87"
        "\xdd\xa7\x70\x05\x55\xa3\x7b\x75\x34\x29\x1b\x96\x2d\x9f\x41\x41\xb9"
        "\x64\x48\xda\xd7\x12\x81\xef\x7c\x2d\x61\x49\x4c\xcb\xb8\x59"
        "\x00\x09",
        ATT_MESSAGE_SIZE);
    G_att_ctx.msg_offset = ATT_MESSAGE_SIZE;
    G_att_ctx.stage = att_stage_wait_ud_value;

    // CLA + INS_ATTESTATION + ATT_OP_GET_MSG + PAGE_NUM (0)
    set_apdu("\x80\x50\x02\x00");

    BEGIN_TRY {
        TRY {
            get_attestation(4, &G_att_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(PROT_INVALID == e);
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_get() {
    printf("Test ATT_OP_GET...\n");
    reset_attestation(&G_att_ctx);
    *(unsigned char *)N_onboarded_ui = 1;
    G_att_ctx.stage = att_stage_ready;

    // CLA + INS_ATTESTATION + ATT_OP_GET
    set_apdu("\x80\x50\x03");

    assert(TX_FOR_DATA_SIZE(strlen(MSG_SIGNATURE)) ==
           get_attestation(3, &G_att_ctx));

    ASSERT_APDU("\x80\x50\x03" MSG_SIGNATURE);
}

void test_get_attestation_get_wrong_stage() {
    printf("Test ATT_OP_GET (wrong stage)...\n");
    reset_attestation(&G_att_ctx);
    *(unsigned char *)N_onboarded_ui = 1;
    G_att_ctx.stage = att_stage_wait_ud_value;

    // CLA + INS_ATTESTATION + ATT_OP_GET
    set_apdu("\x80\x50\x03");

    BEGIN_TRY {
        TRY {
            get_attestation(3, &G_att_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(PROT_INVALID == e);
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_invalid() {
    printf("Test invalid command...\n");
    reset_attestation(&G_att_ctx);
    *(unsigned char *)N_onboarded_ui = 1;
    G_att_ctx.stage = att_stage_ready;
    // CLA + INS_ATTESTATION + Invalid command
    set_apdu("\x80\x50\x99");

    BEGIN_TRY {
        TRY {
            get_attestation(4, &G_att_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(PROT_INVALID == e);
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_get_attestation_not_onboarded() {
    printf("Test get attestation (device not onboarded)...\n");
    reset_attestation(&G_att_ctx);
    *(unsigned char *)N_onboarded_ui = 0;
    G_att_ctx.stage = att_stage_ready;
    // CLA + INS_ATTESTATION + ATT_OP_GET
    set_apdu("\x80\x50\x03");

    BEGIN_TRY {
        TRY {
            get_attestation(4, &G_att_ctx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(ATT_NO_ONBOARD == e);
        }
        FINALLY {
        }
    }
    END_TRY;
}

int main() {
    test_reset_attestation();
    test_get_attestation_ud_value();
    test_get_attestation_ud_value_wrong_stage();
    test_get_attestation_get_msg();
    test_get_attestation_get_msg_wrong_stage();
    test_get_attestation_get();
    test_get_attestation_get_wrong_stage();
    test_get_attestation_invalid();
    test_get_attestation_not_onboarded();
    return 0;
}
