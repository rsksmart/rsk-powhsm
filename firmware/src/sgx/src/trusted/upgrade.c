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

#include "upgrade.h"

#include <string.h>
#include <secp256k1.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/attestation/custom_claims.h>

#include "hal/exceptions.h"
#include "hal/log.h"
#include "hal/seed.h"
#include "hal/hash.h"

#include "defs.h"
#include "apdu.h"
#include "hsm.h"
#include "migrate.h"
#include "eth.h"
#include "ints.h"
#include "compiletime.h"
#include "evidence.h"

// Authorizers' public keys length (uncompressed format)
#define AUTHORIZED_SIGNER_PUBKEY_LENGTH 65

// Maximum number of authorizers (increase this if using a greater number)
#define MAX_AUTHORIZERS 10

// Authorized signers
#include "upgrade_signers.h"
static const uint8_t authorizers_pubkeys[][AUTHORIZED_SIGNER_PUBKEY_LENGTH] =
    AUTHORIZERS_PUBKEYS;

// Total number of authorizers
#define TOTAL_AUTHORIZERS \
    (sizeof(authorizers_pubkeys) / sizeof(authorizers_pubkeys[0]))

// Minimum number of authorizers required to authorize a signer
#define THRESHOLD_AUTHORIZERS (TOTAL_AUTHORIZERS / 2 + 1)

// SGX upgrade spec message parts
#define SGX_UPG_SPEC_MSG_P1 "RSK_powHSM_SGX_upgrade_from_"
#define SGX_UPG_SPEC_MSG_P1_LENGTH (sizeof(SGX_UPG_SPEC_MSG_P1) - sizeof(""))

#define SGX_UPG_SPEC_MSG_P2 "_to_"
#define SGX_UPG_SPEC_MSG_P2_LENGTH (sizeof(SGX_UPG_SPEC_MSG_P2) - sizeof(""))

#define EVIDENCE_FORMAT EVIDENCE_FORMAT_SGX_LOCAL

// Operation selectors
typedef enum {
    OP_UPGRADE_START = 0x01,
    OP_UPGRADE_SPEC_SIG = 0x02,
    OP_UPGRADE_IDENTIFY_PEER = 0x03,
    OP_UPGRADE_PROCESS_DATA = 0x04,
} op_code_upgrade_t;

// Error codes
typedef enum {
    ERR_UPGRADE_PROTOCOL = 0x6A00,
    ERR_UPGRADE_SPEC = 0x6A01,
    ERR_UPGRADE_SIGNATURE = 0x6A02,
    ERR_UPGRADE_AUTH = 0x6A03,
    ERR_UPGRADE_DATA_PROCESSING = 0x6A04,
    ERR_UPGRADE_INTERNAL = 0x6A99,
} err_code_upgrade_t;

// MRENCLAVE size
#define UPGRADE_MRENCLAVE_SIZE HASH_LENGTH

// SGX upgrade spec
typedef struct {
    uint8_t mrenclave_from[UPGRADE_MRENCLAVE_SIZE];
    uint8_t mrenclave_to[UPGRADE_MRENCLAVE_SIZE];
} upgrade_spec_t;

// SGX upgrade operations
typedef enum {
    upgrade_operation_none = 0,
    upgrade_operation_export = 1,
    upgrade_operation_import = 2,
} upgrade_operation_t;

// SGX upgrade SM states
typedef enum {
    upgrade_state_await_spec = 0,
    upgrade_state_await_spec_sigs = 1,
    upgrade_state_await_peer_id = 2,
    upgrade_state_ready_for_xchg = 3,
} upgrade_state_t;

// SGX upgrade context
typedef struct {
    upgrade_operation_t operation;
    upgrade_state_t state;
    upgrade_spec_t spec;
    uint8_t* my_mrenclave;
    uint8_t* their_mrenclave;

    uint8_t expected_message_hash[HASH_LENGTH];
    bool authorized_signer_verified[MAX_AUTHORIZERS];
} upgrade_ctx_t;

// SGX upgrade ctx
static upgrade_ctx_t upgrade_ctx;

/*
 * Reset the upgrade context
 */
static void reset_upgrade() {
    explicit_bzero(&upgrade_ctx, sizeof(upgrade_ctx));
}

/*
 * Check that the context for the SGX upgrade
 * matches the expected state and is in a
 * consistent state.
 *
 * Reset the state and throw a protocol error
 * otherwise.
 */
static void check_state(upgrade_state_t expected) {
    // Consistency check
    if (upgrade_ctx.state == upgrade_state_await_spec &&
        upgrade_ctx.operation != upgrade_operation_none) {
        reset_upgrade();
        THROW(ERR_UPGRADE_PROTOCOL);
    } else if (upgrade_ctx.state != upgrade_state_await_spec &&
               upgrade_ctx.operation == upgrade_operation_none) {
        reset_upgrade();
        THROW(ERR_UPGRADE_PROTOCOL);
    }
    // Expectation check
    if (upgrade_ctx.state != expected) {
        reset_upgrade();
        THROW(ERR_UPGRADE_PROTOCOL);
    }
}

static bool generate_message_to_verify() {
    uint8_t message_size;
    uint8_t aux_buf[4]; // Hold at most three digits plus a null terminator
    hash_sha256_ctx_t hash_ctx;

    if (!hash_sha256_init(&hash_ctx))
        goto generate_message_to_verify_error;

    // Hash eth prefix
    if (!hash_sha256_update(&hash_ctx,
                            (const uint8_t*)ETHEREUM_MSG_PREFIX,
                            ETHEREUM_MSG_PREFIX_LENGTH))
        goto generate_message_to_verify_error;

    // Compute total message size
    message_size = SGX_UPG_SPEC_MSG_P1_LENGTH +
                   sizeof(upgrade_ctx.spec.mrenclave_from) * 2 + // Hexa
                   SGX_UPG_SPEC_MSG_P2_LENGTH +
                   sizeof(upgrade_ctx.spec.mrenclave_to) * 2; // Hexa

    // Hash message size
    UINT_TO_DECSTR(aux_buf, message_size);
    if (!hash_sha256_update(&hash_ctx, aux_buf, strlen((char*)aux_buf)))
        goto generate_message_to_verify_error;

    // Hash message
    if (!hash_sha256_update(&hash_ctx,
                            (uint8_t*)SGX_UPG_SPEC_MSG_P1,
                            SGX_UPG_SPEC_MSG_P1_LENGTH))
        goto generate_message_to_verify_error;

    for (unsigned int i = 0; i < sizeof(upgrade_ctx.spec.mrenclave_from); i++) {
        BYTE_TO_HEXSTR(aux_buf, upgrade_ctx.spec.mrenclave_from[i]);
        if (!hash_sha256_update(&hash_ctx, aux_buf, 2))
            goto generate_message_to_verify_error;
    }

    if (!hash_sha256_update(&hash_ctx,
                            (uint8_t*)SGX_UPG_SPEC_MSG_P2,
                            SGX_UPG_SPEC_MSG_P2_LENGTH))
        goto generate_message_to_verify_error;

    for (unsigned int i = 0; i < sizeof(upgrade_ctx.spec.mrenclave_to); i++) {
        BYTE_TO_HEXSTR(aux_buf, upgrade_ctx.spec.mrenclave_to[i]);
        if (!hash_sha256_update(&hash_ctx, aux_buf, 2))
            goto generate_message_to_verify_error;
    }

    // Output hash
    if (!hash_sha256_final(&hash_ctx, upgrade_ctx.expected_message_hash))
        goto generate_message_to_verify_error;
    return true;

generate_message_to_verify_error:
    LOG("Error generating message to verify\n");
    return false;
}

// -----------------------------------------------------------------------
// Protocol implementation
// -----------------------------------------------------------------------

void upgrade_init() {
    // Build should fail when more authorizers than supported are provided
    COMPILE_TIME_ASSERT(TOTAL_AUTHORIZERS <= MAX_AUTHORIZERS);

    reset_upgrade();
    LOG("Upgrade module initialized\n");
}

#define DUMMY_PEER_ID "peer-id:"
#define DUMMY_PEER_ID_LEN (sizeof(DUMMY_PEER_ID) - 1)

#define DUMMY_KEY                                                             \
    {                                                                         \
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22,     \
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x33, 0x33, \
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44,       \
    }

unsigned int do_upgrade(volatile unsigned int rx) {
    uint8_t key[] = DUMMY_KEY;
    size_t sz = 0;
    int signature_valid;
    long unsigned valid_count;
    secp256k1_context* secp_ctx;
    secp256k1_ecdsa_signature signature;
    secp256k1_pubkey pubkey;
    uint8_t* evidence = NULL;
    size_t evidence_size;
    oe_claim_t* claims = NULL;
    size_t claims_size;
    oe_claim_t* claim;

    switch (APDU_OP()) {
    case OP_UPGRADE_START:
        check_state(upgrade_state_await_spec);
        // We expect a from/to upgrade spec plus an operation type byte
        if (APDU_DATA_SIZE(rx) != UPGRADE_MRENCLAVE_SIZE * 2 + 1) {
            reset_upgrade();
            THROW(ERR_UPGRADE_PROTOCOL);
        }
        // Operation validations
        switch (APDU_DATA_PTR[0]) {
        case upgrade_operation_export:
            REQUIRE_ONBOARDED();
            REQUIRE_UNLOCKED();
            break;
        case upgrade_operation_import:
            REQUIRE_NOT_ONBOARDED();
            break;
        default:
            reset_upgrade();
            THROW(ERR_UPGRADE_PROTOCOL);
        }
        upgrade_ctx.operation = APDU_DATA_PTR[0];
        // Spec
        memcpy(upgrade_ctx.spec.mrenclave_from,
               APDU_DATA_PTR + 1,
               UPGRADE_MRENCLAVE_SIZE);
        memcpy(upgrade_ctx.spec.mrenclave_to,
               APDU_DATA_PTR + 1 + UPGRADE_MRENCLAVE_SIZE,
               UPGRADE_MRENCLAVE_SIZE);
        upgrade_ctx.my_mrenclave =
            upgrade_ctx.operation == upgrade_operation_export
                ? upgrade_ctx.spec.mrenclave_from
                : upgrade_ctx.spec.mrenclave_to;
        upgrade_ctx.their_mrenclave =
            upgrade_ctx.operation == upgrade_operation_export
                ? upgrade_ctx.spec.mrenclave_to
                : upgrade_ctx.spec.mrenclave_from;
        LOG("Spec received\n");
        LOG_HEX(
            "From:", upgrade_ctx.spec.mrenclave_from, UPGRADE_MRENCLAVE_SIZE);
        LOG_HEX("To:", upgrade_ctx.spec.mrenclave_to, UPGRADE_MRENCLAVE_SIZE);
        LOG("Role: %s\n",
            upgrade_ctx.operation == upgrade_operation_export ? "exporter"
                                                              : "importer");
        // Check this enclave's mrenclave matches the corresponding
        // value in the spec according to the specified role
        if (!evidence_generate(
                EVIDENCE_FORMAT, NULL, 0, &evidence, &evidence_size)) {
            LOG("Unable to generate enclave evidence\n");
            goto do_upgrade_start_error;
        }
        if (!evidence_verify_and_extract_claims(EVIDENCE_FORMAT,
                                                evidence,
                                                evidence_size,
                                                &claims,
                                                &claims_size)) {
            LOG("Error verifying this enclave's evidence\n");
            goto do_upgrade_start_error;
        }
        if (!(claim = evidence_get_claim(
                  claims, claims_size, OE_CLAIM_UNIQUE_ID))) {
            LOG("Error extracting this enclave's mrenclave\n");
            goto do_upgrade_start_error;
        }
        LOG_HEX("This enclave's mrenclave:", claim->value, claim->value_size);
        if (claim->value_size != UPGRADE_MRENCLAVE_SIZE ||
            memcmp(claim->value,
                   upgrade_ctx.my_mrenclave,
                   UPGRADE_MRENCLAVE_SIZE) != 0) {
            LOG("This enclave's mrenclave does not match the spec's "
                "mrenclave\n");
            goto do_upgrade_start_error;
        }
        generate_message_to_verify();
        LOG_HEX("Message to verify: ",
                upgrade_ctx.expected_message_hash,
                sizeof(upgrade_ctx.expected_message_hash));
        upgrade_ctx.state = upgrade_state_await_spec_sigs;
        return TX_NO_DATA();
    do_upgrade_start_error:
        if (evidence)
            evidence_free(evidence);
        if (claims)
            oe_free(claims);
        reset_upgrade();
        THROW(ERR_UPGRADE_SPEC);
    case OP_UPGRADE_SPEC_SIG:
        check_state(upgrade_state_await_spec_sigs);
        if (APDU_DATA_SIZE(rx) < 1) {
            reset_upgrade();
            THROW(ERR_UPGRADE_PROTOCOL);
        }
        // Check to see whether we find a matching authorized signer
        secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        if (!secp256k1_ecdsa_signature_parse_der(
                secp_ctx, &signature, APDU_DATA_PTR, APDU_DATA_SIZE(rx))) {
            secp256k1_context_destroy(secp_ctx);
            reset_upgrade();
            THROW(ERR_UPGRADE_SIGNATURE);
        }
        signature_valid = 0;
        for (unsigned int i = 0; i < TOTAL_AUTHORIZERS && !signature_valid;
             i++) {
            // Clear public key memory region first just in case initialization
            // fails
            explicit_bzero(&pubkey, sizeof(pubkey));
            // Attempt to verify against this public key
            if (!secp256k1_ec_pubkey_parse(
                    secp_ctx,
                    &pubkey,
                    (const unsigned char*)authorizers_pubkeys[i],
                    sizeof(authorizers_pubkeys[i]))) {
                secp256k1_context_destroy(secp_ctx);
                reset_upgrade();
                THROW(ERR_UPGRADE_SIGNATURE);
            }
            signature_valid =
                secp256k1_ecdsa_verify(secp_ctx,
                                       &signature,
                                       upgrade_ctx.expected_message_hash,
                                       &pubkey);
            // Cleanup
            explicit_bzero(&pubkey, sizeof(pubkey));

            // Found a valid signature?
            if (signature_valid) {
                LOG("Valid signature received!\n");
                upgrade_ctx.authorized_signer_verified[i] = true;
            }
        }
        secp256k1_context_destroy(secp_ctx);

        // Reached the threshold?
        valid_count = 0;
        for (unsigned int i = 0; i < TOTAL_AUTHORIZERS; i++)
            if (upgrade_ctx.authorized_signer_verified[i])
                valid_count++;

        LOG("Valid signatures so far: %lu\n", valid_count);

        if (valid_count >= THRESHOLD_AUTHORIZERS) {
            SET_APDU_OP(0); // No need for more
            upgrade_ctx.state = upgrade_state_await_peer_id;
            LOG("Threshold reached!\n");
        } else {
            SET_APDU_OP(1); // We need more
        }
        return TX_NO_DATA();
    case OP_UPGRADE_IDENTIFY_PEER:
        check_state(upgrade_state_await_peer_id);
        if (APDU_DATA_SIZE(rx) != DUMMY_PEER_ID_LEN + UPGRADE_MRENCLAVE_SIZE ||
            memcmp(APDU_DATA_PTR, DUMMY_PEER_ID, DUMMY_PEER_ID_LEN) ||
            memcmp(APDU_DATA_PTR + DUMMY_PEER_ID_LEN,
                   upgrade_ctx.their_mrenclave,
                   UPGRADE_MRENCLAVE_SIZE)) {
            reset_upgrade();
            THROW(ERR_UPGRADE_AUTH);
        }
        upgrade_ctx.state = upgrade_state_ready_for_xchg;
        return TX_NO_DATA();
    case OP_UPGRADE_PROCESS_DATA:
        check_state(upgrade_state_ready_for_xchg);
        switch (upgrade_ctx.operation) {
        case upgrade_operation_export:
            LOG("Exporting data...\n");
            sz = APDU_TOTAL_DATA_SIZE_OUT;
            if (!migrate_export(key, sizeof(key), APDU_DATA_PTR, &sz) ||
                sz != (sz & 0xFF)) {
                reset_upgrade();
                THROW(ERR_UPGRADE_DATA_PROCESSING);
            }
            LOG("Data export complete\n");
            reset_upgrade();
            return TX_FOR_DATA_SIZE((uint8_t)sz);
        case upgrade_operation_import:
            LOG("Importing data...\n");
            if (APDU_DATA_SIZE(rx) == 0) {
                reset_upgrade();
                THROW(ERR_UPGRADE_PROTOCOL);
            }
            if (!migrate_import(
                    key, sizeof(key), APDU_DATA_PTR, APDU_DATA_SIZE(rx))) {
                reset_upgrade();
                THROW(ERR_UPGRADE_DATA_PROCESSING);
            }
            LOG("Data import complete\n");
            reset_upgrade();
            return TX_NO_DATA();
        default:
            // We should never reach this point
            THROW(ERR_UPGRADE_INTERNAL);
        }
    default:
        reset_upgrade();
        THROW(ERR_UPGRADE_PROTOCOL);
        break;
    }
}
