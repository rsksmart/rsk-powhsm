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
#include <secp256k1_ecdh.h>
#include <openenclave/corelibc/stdlib.h>

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
#include "util.h"
#include "random.h"
#include "aes_gcm.h"

// Authorizers' public keys length (uncompressed format)
#define AUTHORIZED_SIGNER_PUBKEY_LENGTH 65

// Maximum number of authorizers (increase this if using a greater number)
#define MAX_AUTHORIZERS 10

// Maximum size for a peer data packet
#define MAX_RECV_DATA_SIZE (8 * 1024) // 8Kbytes

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
    OP_UPGRADE_IDENTIFY_SELF = 0x03,
    OP_UPGRADE_IDENTIFY_PEER = 0x04,
    OP_UPGRADE_PROCESS_DATA = 0x05,
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
    upgrade_state_await_spec,
    upgrade_state_await_spec_sigs,
    upgrade_state_send_self_id,
    upgrade_state_await_peer_id,
    upgrade_state_ready_for_xchg,
} upgrade_state_t;

// SGX upgrade context
typedef struct {
    upgrade_state_t state;

    upgrade_spec_t spec;
    upgrade_operation_t operation;
    uint8_t* my_mrenclave;
    uint8_t* their_mrenclave;

    uint8_t expected_message_hash[HASH_LENGTH];
    bool authorized_signer_verified[MAX_AUTHORIZERS];

    uint8_t* evidence;
    size_t evidence_size;
    bool evidence_external;

    uint8_t my_privkey[PRIVATE_KEY_LENGTH];
    uint8_t my_pubkey[PUBKEY_CMP_LENGTH];
    size_t my_pubkey_len;
    uint8_t their_pubkey[PUBKEY_CMP_LENGTH];

    size_t trx_offset;
} upgrade_ctx_t;

// SGX upgrade ctx
static upgrade_ctx_t upgrade_ctx;

/*
 * Free current evidence buffer, if any
 */
static void free_evidence() {
    if (upgrade_ctx.evidence) {
        if (!upgrade_ctx.evidence_external)
            evidence_free(upgrade_ctx.evidence);
        else
            oe_free(upgrade_ctx.evidence);
    }
    upgrade_ctx.evidence = NULL;
    upgrade_ctx.evidence_size = 0;
}

/*
 * Reset the upgrade context
 */
static void reset_upgrade() {
    free_evidence();
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
    hash_keccak256_ctx_t hash_ctx;

    if (!hash_keccak256_init(&hash_ctx))
        goto generate_message_to_verify_error;

    // Hash eth prefix
    if (!hash_keccak256_update(&hash_ctx,
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
    if (!hash_keccak256_update(&hash_ctx, aux_buf, strlen((char*)aux_buf)))
        goto generate_message_to_verify_error;

    // Hash message
    if (!hash_keccak256_update(&hash_ctx,
                               (uint8_t*)SGX_UPG_SPEC_MSG_P1,
                               SGX_UPG_SPEC_MSG_P1_LENGTH))
        goto generate_message_to_verify_error;

    for (unsigned int i = 0; i < sizeof(upgrade_ctx.spec.mrenclave_from); i++) {
        BYTE_TO_HEXSTR(aux_buf, upgrade_ctx.spec.mrenclave_from[i]);
        if (!hash_keccak256_update(&hash_ctx, aux_buf, 2))
            goto generate_message_to_verify_error;
    }

    if (!hash_keccak256_update(&hash_ctx,
                               (uint8_t*)SGX_UPG_SPEC_MSG_P2,
                               SGX_UPG_SPEC_MSG_P2_LENGTH))
        goto generate_message_to_verify_error;

    for (unsigned int i = 0; i < sizeof(upgrade_ctx.spec.mrenclave_to); i++) {
        BYTE_TO_HEXSTR(aux_buf, upgrade_ctx.spec.mrenclave_to[i]);
        if (!hash_keccak256_update(&hash_ctx, aux_buf, 2))
            goto generate_message_to_verify_error;
    }

    // Output hash
    if (!hash_keccak256_final(&hash_ctx, upgrade_ctx.expected_message_hash))
        goto generate_message_to_verify_error;
    return true;

generate_message_to_verify_error:
    LOG("Error generating message to verify\n");
    return false;
}

static uint8_t send_data(uint8_t* src,
                         size_t src_size,
                         size_t* src_offset,
                         bool* more) {
    size_t tx = MIN(APDU_TOTAL_DATA_SIZE_OUT, src_size - *src_offset);
    memcpy(APDU_DATA_PTR, src + *src_offset, tx);
    *src_offset += tx;
    *more = *src_offset < src_size;
    LOG("Sending %lu bytes of data\n", tx);
    return (uint8_t)tx;
}

static bool receive_data(volatile unsigned int rx,
                         uint8_t** dest,
                         size_t* dest_size,
                         size_t* dest_offset) {
    size_t pl = !*dest ? 2 : 0; // Two bytes for payload length
    if (APDU_DATA_SIZE(rx) <= pl) {
        reset_upgrade();
        THROW(ERR_UPGRADE_PROTOCOL);
    }
    if (!*dest) {
        VAR_BIGENDIAN_FROM(APDU_DATA_PTR, *dest_size, pl);
        // We allow a maximum data size due to the nature of data
        // we need to process
        if (*dest_size > MAX_RECV_DATA_SIZE) {
            LOG("Data bigger than allowed max\n");
            reset_upgrade();
            THROW(ERR_UPGRADE_PROTOCOL);
        }
        *dest = oe_malloc(*dest_size);
        *dest_offset = 0;
        LOG("Expecting %lu bytes of data\n", *dest_size);
    }
    if (APDU_DATA_SIZE(rx) - pl > *dest_size - *dest_offset) {
        LOG("Data buffer overflow\n");
        reset_upgrade();
        THROW(ERR_UPGRADE_PROTOCOL);
    }
    memcpy(*dest + *dest_offset, APDU_DATA_PTR + pl, APDU_DATA_SIZE(rx) - pl);
    *dest_offset += APDU_DATA_SIZE(rx) - pl;
    LOG("Received %lu bytes of data\n", APDU_DATA_SIZE(rx) - pl);
    return *dest_offset < *dest_size; // More?
}

// -----------------------------------------------------------------------
// Protocol implementation
// -----------------------------------------------------------------------

void upgrade_init() {
    // Build should fail when more authorizers than supported are provided
    COMPILE_TIME_ASSERT(TOTAL_AUTHORIZERS <= MAX_AUTHORIZERS);
    // Build should fail if hash size size differs from expected key size
    COMPILE_TIME_ASSERT(HASH_LENGTH == AES_GCM_KEY_SIZE);

    reset_upgrade();
    LOG("Upgrade module initialized\n");
}

unsigned int do_upgrade(volatile unsigned int rx) {
    uint8_t key[AES_GCM_KEY_SIZE];
    size_t sz = 0;
    uint8_t tx;
    bool baux;
    int signature_valid;
    long unsigned valid_count;
    secp256k1_context* secp_ctx;
    secp256k1_ecdsa_signature signature;
    secp256k1_pubkey pubkey;
    oe_claim_t* claims = NULL;
    size_t claims_size;
    oe_claim_t* claim;
    evidence_format_t format;
    uint16_t error;

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
        explicit_bzero(&format, sizeof(format));
        format.id = EVIDENCE_FORMAT;
        upgrade_ctx.evidence_external = false;
        if (!evidence_generate(&format,
                               NULL,
                               0,
                               &upgrade_ctx.evidence,
                               &upgrade_ctx.evidence_size)) {
            LOG("Unable to generate enclave evidence for self\n");
            error = ERR_UPGRADE_INTERNAL;
            goto do_upgrade_start_error;
        }
        if (!evidence_verify_and_extract_claims(EVIDENCE_FORMAT,
                                                upgrade_ctx.evidence,
                                                upgrade_ctx.evidence_size,
                                                &claims,
                                                &claims_size)) {
            LOG("Error verifying this enclave's evidence\n");
            error = ERR_UPGRADE_INTERNAL;
            goto do_upgrade_start_error;
        }
        if (!(claim = evidence_get_claim(
                  claims, claims_size, OE_CLAIM_UNIQUE_ID))) {
            LOG("Error extracting this enclave's mrenclave\n");
            error = ERR_UPGRADE_INTERNAL;
            goto do_upgrade_start_error;
        }
        LOG_HEX("This enclave's mrenclave:", claim->value, claim->value_size);
        if (claim->value_size != UPGRADE_MRENCLAVE_SIZE ||
            memcmp(claim->value,
                   upgrade_ctx.my_mrenclave,
                   UPGRADE_MRENCLAVE_SIZE) != 0) {
            LOG("This enclave's mrenclave does not match the spec's "
                "mrenclave\n");
            error = ERR_UPGRADE_SPEC;
            goto do_upgrade_start_error;
        }
        generate_message_to_verify();
        LOG_HEX("Message to verify:",
                upgrade_ctx.expected_message_hash,
                sizeof(upgrade_ctx.expected_message_hash));
        upgrade_ctx.state = upgrade_state_await_spec_sigs;
        oe_free(claims);
        free_evidence();
        return TX_NO_DATA();
    do_upgrade_start_error:
        if (claims)
            oe_free(claims);
        reset_upgrade();
        THROW(error);
    case OP_UPGRADE_SPEC_SIG:
        check_state(upgrade_state_await_spec_sigs);

        if (APDU_DATA_SIZE(rx) < 1) {
            reset_upgrade();
            THROW(ERR_UPGRADE_PROTOCOL);
        }
        // Check to see whether we find a matching authorized signer
        secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        if (!secp256k1_ecdsa_signature_parse_der(
                secp_ctx, &signature, APDU_DATA_PTR, APDU_DATA_SIZE(rx))) {
            secp256k1_context_destroy(secp_ctx);
            reset_upgrade();
            THROW(ERR_UPGRADE_SIGNATURE);
        }
        signature_valid = 0;
        for (unsigned int i = 0; i < TOTAL_AUTHORIZERS; i++) {
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

            // Found a valid signature?
            if (signature_valid) {
                LOG("Valid signature received!\n");
                upgrade_ctx.authorized_signer_verified[i] = true;
                break;
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
            upgrade_ctx.state = upgrade_state_send_self_id;
            LOG("Threshold reached!\n");
        } else {
            SET_APDU_OP(1); // We need more
        }
        return TX_NO_DATA();
    case OP_UPGRADE_IDENTIFY_SELF:
        check_state(upgrade_state_send_self_id);

        if (!upgrade_ctx.evidence) {
            secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
            do {
                if (!random_getrandom(upgrade_ctx.my_privkey,
                                      sizeof(upgrade_ctx.my_privkey))) {
                    LOG("Unable to generate private key\n");
                    THROW(ERR_UPGRADE_INTERNAL);
                }
            } while (!secp256k1_ec_pubkey_create(
                secp_ctx, &pubkey, upgrade_ctx.my_privkey));
            upgrade_ctx.my_pubkey_len = sizeof(upgrade_ctx.my_pubkey);
            secp256k1_ec_pubkey_serialize(secp_ctx,
                                          upgrade_ctx.my_pubkey,
                                          &upgrade_ctx.my_pubkey_len,
                                          &pubkey,
                                          SECP256K1_EC_COMPRESSED);
            if (upgrade_ctx.my_pubkey_len != sizeof(upgrade_ctx.my_pubkey)) {
                LOG("Unable to serialize pubkey\n");
                reset_upgrade();
                secp256k1_context_destroy(secp_ctx);
                THROW(ERR_UPGRADE_INTERNAL);
            }
            LOG_HEX("My pubkey:",
                    upgrade_ctx.my_pubkey,
                    sizeof(upgrade_ctx.my_pubkey));
            secp256k1_context_destroy(secp_ctx);
            explicit_bzero(&format, sizeof(format));
            format.id = EVIDENCE_FORMAT;
            if (!evidence_get_format_settings(&format)) {
                LOG("Unable to get evidence format\n");
                reset_upgrade();
                THROW(ERR_UPGRADE_INTERNAL);
            }
            memcpy(format.settings,
                   upgrade_ctx.their_mrenclave,
                   UPGRADE_MRENCLAVE_SIZE);
            upgrade_ctx.evidence_external = false;
            if (!evidence_generate(&format,
                                   upgrade_ctx.my_pubkey,
                                   sizeof(upgrade_ctx.my_pubkey),
                                   &upgrade_ctx.evidence,
                                   &upgrade_ctx.evidence_size)) {
                LOG("Unable to generate enclave evidence for peer\n");
                reset_upgrade();
                THROW(ERR_UPGRADE_INTERNAL);
            }
            oe_free(format.settings);
            explicit_bzero(&format, sizeof(format));
            upgrade_ctx.trx_offset = 0;
        }

        tx = send_data(upgrade_ctx.evidence,
                       upgrade_ctx.evidence_size,
                       &upgrade_ctx.trx_offset,
                       &baux);
        SET_APDU_OP(baux ? 1 : 0); // More to send?

        if (!baux) {
            LOG("Self evidence completely sent\n");
            free_evidence();
            upgrade_ctx.state = upgrade_state_await_peer_id;
        }

        return TX_FOR_DATA_SIZE(tx);
    case OP_UPGRADE_IDENTIFY_PEER:
        check_state(upgrade_state_await_peer_id);

        upgrade_ctx.evidence_external = true;
        if (receive_data(rx,
                         &upgrade_ctx.evidence,
                         &upgrade_ctx.evidence_size,
                         &upgrade_ctx.trx_offset)) {
            SET_APDU_OP(1); // More
            return TX_NO_DATA();
        }
        // We received the entire peer evidence. Perform validation
        if (!evidence_verify_and_extract_claims(EVIDENCE_FORMAT,
                                                upgrade_ctx.evidence,
                                                upgrade_ctx.evidence_size,
                                                &claims,
                                                &claims_size)) {
            LOG("Error verifying peer enclave's evidence\n");
            goto do_upgrade_identify_peer_error;
        }
        if (!(claim = evidence_get_claim(
                  claims, claims_size, OE_CLAIM_UNIQUE_ID))) {
            LOG("Error extracting peer enclave's mrenclave\n");
            goto do_upgrade_identify_peer_error;
        }
        LOG_HEX("Peer enclave's mrenclave:", claim->value, claim->value_size);
        if (claim->value_size != UPGRADE_MRENCLAVE_SIZE ||
            memcmp(claim->value,
                   upgrade_ctx.their_mrenclave,
                   UPGRADE_MRENCLAVE_SIZE) != 0) {
            LOG("Peer enclave's mrenclave does not match the spec's "
                "mrenclave\n");
            goto do_upgrade_identify_peer_error;
        }
        if (!(claim = evidence_get_custom_claim(claims, claims_size))) {
            LOG("Error extracting peer enclave's public key\n");
            goto do_upgrade_identify_peer_error;
        }
        secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        if (claim->value_size != sizeof(upgrade_ctx.their_pubkey) ||
            !secp256k1_ec_pubkey_parse(
                secp_ctx, &pubkey, claim->value, claim->value_size)) {
            LOG("Invalid peer public key received");
            secp256k1_context_destroy(secp_ctx);
            goto do_upgrade_identify_peer_error;
        }
        secp256k1_context_destroy(secp_ctx);
        memcpy(upgrade_ctx.their_pubkey, claim->value, claim->value_size);
        LOG_HEX("Peer public key:",
                upgrade_ctx.their_pubkey,
                sizeof(upgrade_ctx.their_pubkey));
        upgrade_ctx.state = upgrade_state_ready_for_xchg;
        SET_APDU_OP(0); // Done
        if (claims)
            oe_free(claims);
        free_evidence();
        return TX_NO_DATA();
    do_upgrade_identify_peer_error:
        if (claims)
            oe_free(claims);
        reset_upgrade();
        THROW(ERR_UPGRADE_AUTH);
    case OP_UPGRADE_PROCESS_DATA:
        check_state(upgrade_state_ready_for_xchg);

        secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        if (!secp256k1_ec_pubkey_parse(secp_ctx,
                                       &pubkey,
                                       upgrade_ctx.their_pubkey,
                                       sizeof(upgrade_ctx.their_pubkey)) ||
            !secp256k1_ecdh(secp_ctx,
                            key,
                            &pubkey,
                            upgrade_ctx.my_privkey,
                            secp256k1_ecdh_hash_function_sha256,
                            NULL)) {
            LOG("Unable to generate data processing key\n");
            reset_upgrade();
            secp256k1_context_destroy(secp_ctx);
            THROW(ERR_UPGRADE_INTERNAL);
        }
        secp256k1_context_destroy(secp_ctx);
        explicit_bzero(upgrade_ctx.my_privkey, sizeof(upgrade_ctx.my_privkey));
        explicit_bzero(upgrade_ctx.my_pubkey, sizeof(upgrade_ctx.my_pubkey));
        explicit_bzero(upgrade_ctx.their_pubkey,
                       sizeof(upgrade_ctx.their_pubkey));

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
            LOG("Inconsistent internal state when processing data\n");
            reset_upgrade();
            THROW(ERR_UPGRADE_INTERNAL);
        }
    default:
        reset_upgrade();
        THROW(ERR_UPGRADE_PROTOCOL);
        break;
    }
}
