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

#include "os.h"

#include "auth.h"
#include "svarint.h"
#include "mem.h"

#include "dbg.h"

// IMPORTANT: This callback only executes for the scriptSig at the desired input
// (the one that is requested to sign)
// In all the other cases the parser is not even initialized or called,
// so it is not possible for this callback to execute.
static void btcscript_cb(const btcscript_cb_event_t event) {
    uint8_t redeemscript_length_size;
    uint8_t redeemscript_length[MAX_SVARINT_ENCODING_SIZE];

    if (event == BTCSCRIPT_EV_OPCODE && auth.tx.script_ctx.operand_size > 0 &&
        auth.tx.script_ctx.operand_size == auth.tx.script_ctx.bytes_remaining) {
        // This is a push of exactly the remaining script bytes => this is the
        // last push of the script => this is the redeemScript
        auth.tx.redeemscript_found = 1;
        // Hash the script size using the size of the operand (redeemScript)
        redeemscript_length_size =
            svarint_encode(auth.tx.script_ctx.operand_size,
                           redeemscript_length,
                           sizeof(redeemscript_length));
        sha256_update(&auth.tx.sig_hash_ctx,
                      redeemscript_length,
                      redeemscript_length_size);
    } else if (event == BTCSCRIPT_EV_OPERAND && auth.tx.redeemscript_found) {
        sha256_update(&auth.tx.sig_hash_ctx,
                      &auth.tx.script_ctx.operand_byte,
                      sizeof(auth.tx.script_ctx.operand_byte));
    }
}

static void btctx_cb(const btctx_cb_event_t event) {
    // Update txhash
    sha256_update(&auth.tx.tx_hash_ctx, auth.tx.ctx.raw, auth.tx.ctx.raw_size);

    // The bridge currently only generates pegout transactions with
    // versions 1 or 2. Validate that.
    if (event == BTCTX_EV_VERSION && auth.tx.ctx.parsed.version != 1 &&
        auth.tx.ctx.parsed.version != 2) {
        LOG("[E] Unsupported TX Version: %u\n", auth.tx.ctx.parsed.version);
        THROW(ERR_AUTH_INVALID_TX_VERSION);
    }

    // Validate that the input index to sign is valid
    if (event == BTCTX_EV_VIN_COUNT &&
        auth.input_index_to_sign >= auth.tx.ctx.parsed.varint.value) {
        LOG("[E] Input index to sign > number of inputs.\n");
        THROW(ERR_AUTH_INVALID_TX_INPUT_INDEX);
    }

    // Update sighash
    if (event == BTCTX_EV_VIN_SLENGTH) {
        if (auth.tx.ctx.inout_current == auth.input_index_to_sign) {
            // Parse this scriptSig
            auth.tx.redeemscript_found = 0;
            btcscript_init(&auth.tx.script_ctx,
                           &btcscript_cb,
                           auth.tx.ctx.parsed.varint.value);
        } else {
            // All other scriptSigs get replaced by an empty scriptSig
            // when calculating the sigHash
            sha256_update(&auth.tx.sig_hash_ctx, (uint8_t[]){0x00}, 1);
        }
    } else if (event == BTCTX_EV_VIN_SCRIPT_DATA &&
               auth.tx.ctx.inout_current == auth.input_index_to_sign) {
        if (btcscript_consume(auth.tx.ctx.raw, auth.tx.ctx.raw_size) !=
            auth.tx.ctx.raw_size) {
            LOG("[E] Expected to consume %u bytes from the script but didn't",
                auth.tx.ctx.raw_size);
            THROW(ERR_AUTH_TX_HASH_MISMATCH);
        }

        if (btcscript_result() < 0) {
            LOG("[E] Error %u parsing the scriptSig", btcscript_result());
            THROW(ERR_AUTH_TX_HASH_MISMATCH);
        }

        if (auth.tx.ctx.script_remaining == 0) {
            if (btcscript_result() != BTCSCRIPT_ST_DONE) {
                LOG("[E] No more scriptSig bytes to parse but "
                    "the script parser isn't finished");
                THROW(ERR_AUTH_TX_HASH_MISMATCH);
            }
            if (!auth.tx.redeemscript_found) {
                LOG("[E] Finished parsing the scriptSig "
                    "but the redeemScript was not found");
                THROW(ERR_AUTH_TX_HASH_MISMATCH);
            }
        }
    } else if (event != BTCTX_EV_VIN_SCRIPT_DATA) {
        sha256_update(
            &auth.tx.sig_hash_ctx, auth.tx.ctx.raw, auth.tx.ctx.raw_size);
    }
}

/*
 * Implement the BTC tx parsing and calculations portion
 * of the signing authorization protocol.
 *
 * @arg[in] rx      number of received bytes from the host
 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign_handle_btctx(volatile unsigned int rx) {
    uint8_t apdu_offset = 0;

    if (auth.state != STATE_AUTH_BTCTX) {
        LOG("[E] Expected to be in the BTC tx state\n");
        THROW(ERR_AUTH_INVALID_STATE);
    }

    // Read little endian TX length
    // (part of the legacy protocol, includes this length)
    if (auth.tx.remaining_bytes == 0) {
        for (uint8_t i = 0; i < BTCTX_LENGTH_SIZE; i++) {
            auth.tx.remaining_bytes += APDU_DATA_PTR[i] << (8 * i);
        }
        // BTC tx length includes the length of the length
        auth.tx.remaining_bytes -= BTCTX_LENGTH_SIZE;
        // Init tx parsing context
        btctx_init(&auth.tx.ctx, &btctx_cb);
        // Init both hash operations
        sha256_init(&auth.tx.tx_hash_ctx);
        sha256_init(&auth.tx.sig_hash_ctx);
        apdu_offset = BTCTX_LENGTH_SIZE;
    }

    auth.tx.remaining_bytes -= btctx_consume(APDU_DATA_PTR + apdu_offset,
                                             APDU_DATA_SIZE(rx) - apdu_offset);

    if (btctx_result() < 0) {
        LOG("[E] Error parsing BTC tx: %d\n", btctx_result());
        // To comply with the legacy implementation
        THROW(ERR_AUTH_TX_HASH_MISMATCH);
    }

    if (btctx_result() == BTCTX_ST_DONE) {
        if (auth.tx.remaining_bytes > 0) {
            LOG("[E] Error parsing BTC tx: more bytes reported "
                "than actual tx bytes\n");
            // To comply with the legacy implementation
            THROW(ERR_AUTH_INVALID_DATA_SIZE);
        }

        // Finalize TX hash computation
        sha256_final(&auth.tx.tx_hash_ctx, auth.tx_hash);
        sha256_init(&auth.tx.tx_hash_ctx);
        sha256_update(&auth.tx.tx_hash_ctx, auth.tx_hash, 32);
        sha256_final(&auth.tx.tx_hash_ctx, auth.tx_hash);
        for (int j = 0; j < 16; j++) {
            uint8_t aux = auth.tx_hash[j];
            auth.tx_hash[j] = auth.tx_hash[31 - j];
            auth.tx_hash[31 - j] = aux;
        }

        // Add SIGHASH_ALL hash type at the end
        sha256_update(&auth.tx.sig_hash_ctx,
                      (uint8_t[])SIGHASH_ALL_BYTES,
                      sizeof(SIGHASH_ALL_SIZE));
        sha256_final(&auth.tx.sig_hash_ctx, auth.sig_hash);

        sha256_init(&auth.tx.sig_hash_ctx);
        sha256_update(&auth.tx.sig_hash_ctx, auth.sig_hash, 32);
        sha256_final(&auth.tx.sig_hash_ctx, auth.sig_hash);

        // Log hashes for debugging purposes
        LOG_HEX("TX hash:     ", auth.tx_hash, sizeof(auth.tx_hash));
        LOG_HEX("TX sig hash: ", auth.sig_hash, sizeof(auth.sig_hash));

        // Request RSK transaction receipt
        SET_APDU_OP(P1_RECEIPT);
        SET_APDU_TXLEN(AUTH_MAX_EXCHANGE_SIZE);
        auth.expected_bytes = APDU_TXLEN();
        auth_transition_to(STATE_AUTH_RECEIPT);
        return TX_FOR_TXLEN();
    }

    if (auth.tx.remaining_bytes == 0) {

        LOG("[E] Error parsing BTC tx: no more bytes should "
            "remain but haven't finished parsing\n");
        // To comply with the legacy implementation
        THROW(ERR_AUTH_TX_HASH_MISMATCH);
    }

    SET_APDU_TXLEN(MIN(auth.tx.remaining_bytes, AUTH_MAX_EXCHANGE_SIZE));
    auth.expected_bytes = APDU_TXLEN();
    return TX_FOR_TXLEN();
}