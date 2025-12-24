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

#include "hal/hash.h"
#include "hal/platform.h"
#include "hal/exceptions.h"

#include "auth.h"
#include "svarint.h"
#include "mem.h"
#include "memutil.h"

#include "hal/log.h"

static void btctx_cb(const btctx_cb_event_t event) {
    // Update txhash
    hash_sha256_update(
        &auth.tx.tx_hash_ctx, auth.tx.ctx.raw, auth.tx.ctx.raw_size);

    if (event == BTCTX_EV_VERSION) {
        hash_sha256_update(
            &auth.tx.sig_hash_ctx, auth.tx.ctx.raw, auth.tx.ctx.raw_size);
    }

    if (event == BTCTX_EV_VIN_COUNT) {
        hash_sha256_init(&auth.tx.prevouts_hash_ctx);
        hash_sha256_init(&auth.tx.sequence_hash_ctx);
        auth.tx.aux_offset = 0;
    }

    if (event == BTCTX_EV_VIN_TXH_DATA || event == BTCTX_EV_VIN_TXIX) {
        hash_sha256_update(
            &auth.tx.prevouts_hash_ctx, auth.tx.ctx.raw, auth.tx.ctx.raw_size);

        if (auth.tx.ctx.inout_current == auth.input_index_to_sign) {
            SAFE_MEMMOVE(auth.tx.ip_prevout,
                         sizeof(auth.tx.ip_prevout),
                         auth.tx.aux_offset,
                         auth.tx.ctx.raw,
                         sizeof(auth.tx.ctx.raw),
                         MEMMOVE_ZERO_OFFSET,
                         auth.tx.ctx.raw_size,
                         THROW(ERR_AUTH_INVALID_DATA_SIZE));
            auth.tx.aux_offset += auth.tx.ctx.raw_size;
        }
    }

    if (event == BTCTX_EV_VIN_SEQNO) {
        hash_sha256_update(
            &auth.tx.sequence_hash_ctx, auth.tx.ctx.raw, auth.tx.ctx.raw_size);

        if (auth.tx.ctx.inout_current == auth.input_index_to_sign) {
            SAFE_MEMMOVE(auth.tx.ip_seqno,
                         sizeof(auth.tx.ip_seqno),
                         MEMMOVE_ZERO_OFFSET,
                         auth.tx.ctx.raw,
                         sizeof(auth.tx.ctx.raw),
                         MEMMOVE_ZERO_OFFSET,
                         auth.tx.ctx.raw_size,
                         THROW(ERR_AUTH_INVALID_DATA_SIZE));
        }
    }

    if (event == BTCTX_EV_VOUT_COUNT) {
        hash_sha256_final(&auth.tx.prevouts_hash_ctx, auth.tx.aux_hash);
        hash_sha256_init(&auth.tx.prevouts_hash_ctx);
        hash_sha256_update(&auth.tx.prevouts_hash_ctx,
                           auth.tx.aux_hash,
                           sizeof(auth.tx.aux_hash));
        hash_sha256_final(&auth.tx.prevouts_hash_ctx, auth.tx.aux_hash);
        hash_sha256_update(
            &auth.tx.sig_hash_ctx, auth.tx.aux_hash, sizeof(auth.tx.aux_hash));

        hash_sha256_final(&auth.tx.sequence_hash_ctx, auth.tx.aux_hash);
        hash_sha256_init(&auth.tx.sequence_hash_ctx);
        hash_sha256_update(&auth.tx.sequence_hash_ctx,
                           auth.tx.aux_hash,
                           sizeof(auth.tx.aux_hash));
        hash_sha256_final(&auth.tx.sequence_hash_ctx, auth.tx.aux_hash);
        hash_sha256_update(
            &auth.tx.sig_hash_ctx, auth.tx.aux_hash, sizeof(auth.tx.aux_hash));

        // Previously saved outpoint of input to sign
        hash_sha256_update(&auth.tx.sig_hash_ctx,
                           auth.tx.ip_prevout,
                           sizeof(auth.tx.ip_prevout));

        hash_sha256_init(&auth.tx.outputs_hash_ctx);
    }

    if (event == BTCTX_EV_VOUT_VALUE || event == BTCTX_EV_VOUT_SLENGTH ||
        event == BTCTX_EV_VOUT_SCRIPT_DATA) {
        hash_sha256_update(
            &auth.tx.outputs_hash_ctx, auth.tx.ctx.raw, auth.tx.ctx.raw_size);
    }

    if (event == BTCTX_EV_LOCKTIME) {
        hash_sha256_final(&auth.tx.outputs_hash_ctx, auth.tx.outputs_hash);
        hash_sha256_init(&auth.tx.outputs_hash_ctx);
        hash_sha256_update(&auth.tx.outputs_hash_ctx,
                           auth.tx.outputs_hash,
                           sizeof(auth.tx.outputs_hash));
        hash_sha256_final(&auth.tx.outputs_hash_ctx, auth.tx.outputs_hash);

        SAFE_MEMMOVE(auth.tx.lock_time,
                     sizeof(auth.tx.lock_time),
                     MEMMOVE_ZERO_OFFSET,
                     auth.tx.ctx.raw,
                     sizeof(auth.tx.ctx.raw),
                     MEMMOVE_ZERO_OFFSET,
                     auth.tx.ctx.raw_size,
                     THROW(ERR_AUTH_INVALID_DATA_SIZE));
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

#define TX_METADATA_SIZE (BTCTX_LENGTH_SIZE + EXTRADATA_SIZE)

    if (auth.state != STATE_AUTH_BTCTX) {
        LOG("[E] Expected to be in the BTC tx state\n");
        THROW(ERR_AUTH_INVALID_STATE);
    }

    if (!auth.tx.processing_extradata) {
        // Read little endian TX length
        // (part of the legacy protocol, includes this length)
        if (auth.tx.remaining_bytes == 0) {
            for (uint8_t i = 0; i < BTCTX_LENGTH_SIZE; i++) {
                auth.tx.remaining_bytes += APDU_DATA_PTR[i] << (8 * i);
            }
            if (auth.tx.remaining_bytes <= TX_METADATA_SIZE) {
                // Prevent underflow
                LOG("[E] BTC transaction length too small\n");
                THROW(ERR_AUTH_INVALID_DATA_SIZE);
            }
            // BTC tx length includes the length of the length
            // and the length of the sighash computation mode and
            // extradata length
            auth.tx.remaining_bytes -= TX_METADATA_SIZE;
            // Init both hash operations
            hash_sha256_init(&auth.tx.tx_hash_ctx);
            hash_sha256_init(&auth.tx.sig_hash_ctx);
            apdu_offset = BTCTX_LENGTH_SIZE;
            // Following two bytes indicate extradata size
            // (2 bytes LE)
            auth.tx.processing_extradata = false;
            auth.tx.extradata_size = 0;
            auth.tx.extradata_size += APDU_DATA_PTR[apdu_offset++];
            auth.tx.extradata_size += APDU_DATA_PTR[apdu_offset++] << 8;
            // Validate computation mode and init tx parsing context
            btctx_init(&auth.tx.ctx, &btctx_cb);
            if (!auth.tx.extradata_size) {
                LOG("[E] Invalid extradata size");
                THROW(ERR_AUTH_INVALID_EXTRADATA_SIZE);
            }
        }

        auth.tx.remaining_bytes -= btctx_consume(
            APDU_DATA_PTR + apdu_offset, APDU_DATA_SIZE(rx) - apdu_offset);

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
            hash_sha256_final(&auth.tx.tx_hash_ctx, auth.tx_hash);
            hash_sha256_init(&auth.tx.tx_hash_ctx);
            hash_sha256_update(&auth.tx.tx_hash_ctx, auth.tx_hash, 32);
            hash_sha256_final(&auth.tx.tx_hash_ctx, auth.tx_hash);
            for (int j = 0; j < 16; j++) {
                uint8_t aux = auth.tx_hash[j];
                auth.tx_hash[j] = auth.tx_hash[31 - j];
                auth.tx_hash[31 - j] = aux;
            }

            // Move onto extradata processing
            auth.tx.processing_extradata = true;
            auth.tx.remaining_bytes = (uint32_t)auth.tx.extradata_size;
        }
    } else {
        // Hash extradata
        hash_sha256_update(
            &auth.tx.sig_hash_ctx, APDU_DATA_PTR, APDU_DATA_SIZE(rx));
        auth.tx.remaining_bytes -= APDU_DATA_SIZE(rx);
        if (auth.tx.remaining_bytes == 0) {
            auth.tx.finalise = true;
        }
    }

    if (auth.tx.finalise) {
        // Hash inputs seqnos, outputs and lock time
        hash_sha256_update(
            &auth.tx.sig_hash_ctx, auth.tx.ip_seqno, sizeof(auth.tx.ip_seqno));
        hash_sha256_update(&auth.tx.sig_hash_ctx,
                           auth.tx.outputs_hash,
                           sizeof(auth.tx.outputs_hash));
        hash_sha256_update(&auth.tx.sig_hash_ctx,
                           auth.tx.lock_time,
                           sizeof(auth.tx.lock_time));

        // Add SIGHASH_ALL hash type at the end
        hash_sha256_update(&auth.tx.sig_hash_ctx,
                           (uint8_t[])SIGHASH_ALL_BYTES,
                           sizeof(SIGHASH_ALL_SIZE));
        hash_sha256_final(&auth.tx.sig_hash_ctx, auth.sig_hash);

        hash_sha256_init(&auth.tx.sig_hash_ctx);
        hash_sha256_update(&auth.tx.sig_hash_ctx, auth.sig_hash, 32);
        hash_sha256_final(&auth.tx.sig_hash_ctx, auth.sig_hash);

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