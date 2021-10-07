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
#include <stdbool.h>
#include <string.h>
#include "defs.h"
#include "varint.h"
#include "txparser.h"
#include "memutil.h"

#include "dbg.h"

#define SET_APDU_FOR_BTC()  \
    SET_APDU_CLA();         \
    SET_APDU_CMD(INS_SIGN); \
    SET_APDU_OP(P1_BTC);

// INIT parser
void SM_TX_START(TX_CTX *ctx,
                 PARSE_STM *state,
                 unsigned int rx,
                 unsigned int *tx) {
    SET_APDU_FOR_BTC();
    SET_APDU_TXLEN(9); // Return TXLen + Version + in-counter
    ctx->tx_total_read = 0;
    ctx->currentTxInput = 0;
    ctx->validHashes = false;
    LOG(" TX_START: Input index to sign:%u\n", ctx->tx_input_index_to_sign);
    // Init both hash operations
    sha256_init(&ctx->TX_hash);
    sha256_init(&ctx->signatureHash);
    *state = S_TX_HDR;
    *tx = TX_FOR_TXLEN();
}
// parsing field header
void SM_TX_HDR(TX_CTX *ctx,
               PARSE_STM *state,
               unsigned int rx,
               unsigned int *tx) {
    sha256_update(&ctx->TX_hash,
                  APDU_DATA_PTR + 4,
                  rx - (DATA + 4)); // Update TX hash
    sha256_update(&ctx->signatureHash,
                  APDU_DATA_PTR + 4,
                  rx - (DATA + 4)); // Update SignatureHash
    ctx->tx_total_read += rx - (DATA + 4);
    SAFE_MEMMOVE(&ctx->tx_total_len,
                 sizeof(ctx->tx_total_len),
                 APDU_DATA_PTR,
                 APDU_TOTAL_DATA_SIZE,
                 4,
                 THROW(0x6A87));
    SAFE_MEMMOVE(&ctx->tx_version,
                 sizeof(ctx->tx_version),
                 APDU_DATA_PTR + 4,
                 APDU_TOTAL_DATA_SIZE - 4,
                 4,
                 THROW(0x6A87));
    LOG(" TX_HDR: TX total len %u\n", ctx->tx_total_len);
    LOG(" TX_HDR: version %u\n", ctx->tx_version);
    // The bridge currently only generates pegout transactions with
    // versions 1 or 2. Validate that.
    if (ctx->tx_version != 1 && ctx->tx_version != 2) {
        LOG("[E] Unsupported TX Version: %u\n", ctx->tx_version);
        THROW(0x6A8E);
    }
    if (varintCanDecode(APDU_DATA_PTR + 4 + 4, 1))
        ctx->btc_input_counter = APDU_AT(DATA + 4 + 4);
    else { // More than 254 inputs not supported
        LOG("[E] More than 254 inputs not supported.\n");
        THROW(0x6A88);
    }
    LOG(" TX_HDR: num. inputs %d\n", ctx->btc_input_counter);
    if (ctx->btc_input_counter <= ctx->tx_input_index_to_sign) {
        LOG("[E] Input index to sign > number of inputs.\n");
        THROW(0x6A88);
    }
    SET_APDU_FOR_BTC();
    SET_APDU_TXLEN(32 + 4 + 1); // Previous hash+outputindex+ScriptLength
    *state = S_TX_INPUT_START;
    *tx = TX_FOR_TXLEN();
}

void SM_TX_INPUT_START(TX_CTX *ctx,
                       PARSE_STM *state,
                       unsigned int rx,
                       unsigned int *tx) {
    LOG(" TX_INPUT_START: ---Current TX Input: %d ----\n", ctx->currentTxInput);
    sha256_update(&ctx->TX_hash, APDU_DATA_PTR, rx - DATA); // Update TX hash
    sha256_update(&ctx->signatureHash,
                  APDU_DATA_PTR,
                  (rx - DATA) - 1); // Update signatureHash minus scriptlength
    LOG_HEX("SM_TX_INPUT_START received: ", APDU_DATA_PTR, rx - DATA);
    ctx->tx_total_read += rx - DATA;
    // Read Script
    ctx->script_read = 0;
    switch (APDU_AT(DATA + 32 + 4)) {
    default: // 8 bits
        // script length + sequence_no
        ctx->script_length = APDU_AT(DATA + 32 + 4);
        SET_APDU_TXLEN(0);
        break;
    case 0xFD: // 16 bits
        SET_APDU_TXLEN(2);
        break;
    case 0xFE: // 24 bits
        SET_APDU_TXLEN(3);
        break;
    case 0xFF: // 32 bits
        SET_APDU_TXLEN(4);
        break;
    }
    *state = S_TX_VARINT;
    SET_APDU_FOR_BTC();
    *tx = TX_FOR_TXLEN();
}

// Load multi-byte varint
void SM_TX_VARINT(TX_CTX *ctx,
                  PARSE_STM *state,
                  unsigned int rx,
                  unsigned int *tx) {
    sha256_update(&ctx->TX_hash, APDU_DATA_PTR, rx - DATA); // Update TX hash
    // Create VARINT for signaturehash
    if (rx - DATA > 3)
        THROW(0x6A87);
    // Read length from input
    if (rx - DATA > 0) {
        ctx->script_length = 0;
        SAFE_MEMMOVE(&ctx->script_length,
                     sizeof(ctx->script_length),
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     APDU_DATA_SIZE(rx),
                     THROW(0x6A87));
    }
    ctx->tx_total_read += rx - DATA;
    LOG(" TX_VARINT: varint len: %d script_length %d\n",
        rx - DATA,
        ctx->script_length);
    ctx->script_length +=
        4; // We treat sequence number as part of script, for simplicity.
    // Prepare to request chunked script
    if (ctx->script_length > MAX_USB_TRANSFER)
        SET_APDU_TXLEN(MAX_USB_TRANSFER); // read partial script
    else
        SET_APDU_TXLEN(ctx->script_length); // read whole script + sequence_no
    *state = S_TX_INPUT_READ;
    SET_APDU_FOR_BTC();
    *tx = TX_FOR_TXLEN();
}

void SM_TX_INPUT_READ(TX_CTX *ctx,
                      PARSE_STM *state,
                      unsigned int rx,
                      unsigned int *tx) {
    unsigned char tempVarint[5];
    unsigned char varintLen;
    sha256_update(&ctx->TX_hash, APDU_DATA_PTR, rx - DATA); // Update TX hash

    LOG(" TX_INPUT_READ: read %d bytes (script+seqno)\nScript: ", rx - DATA);
    LOG_HEX(" Script: ", APDU_DATA_PTR, rx - DATA);

    if (ctx->tx_input_index_to_sign == ctx->currentTxInput) {
        if (ctx->script_read ==
            0) { // Replace script in this input for SignatureHash
            // We do this only at the *beggining* of the script, because it
            // cointains the no-ops that need to be removed. Now the script
            // start with an unknown number of no-ops, we need to look for the
            // first non-0 op
            unsigned int pushOffset;
            for (pushOffset = 0; pushOffset < (rx - DATA); pushOffset++)
                if (APDU_AT(DATA + pushOffset))
                    break;
            if (pushOffset == rx - DATA) // push op couldn't be found
                THROW(0x6A8D);
            // Skip push instruction (could be , OP_PUSHDATA2 or OP_PUSHDATA4)
            switch (APDU_AT(DATA + pushOffset)) {
            case 0x4c: // OP_PUSHDATA1
                pushOffset += 2;
                break;
            case 0x4d: // OP_PUSHDATA2
                pushOffset += 3;
                break;
            case 0x4e: // OP_PUSHDATA4
                pushOffset += 5;
                break;
            default: // Unexpected opcode
                THROW(0x6A8D);
            }
            LOG(" Redeem script offset: %u\n", pushOffset);
            LOG(" Creating varint for new script: %u\n",
                ctx->script_length - pushOffset - 4);
            // Now we need to generate a varint with the new size of the script
            // (Check and fail if the new script size is not positive)
            if (ctx->script_length <= pushOffset + 4) {
                THROW(0x6A8D);
            }
            createVarint(
                ctx->script_length - pushOffset - 4, tempVarint, &varintLen);
            sha256_update(&ctx->signatureHash,
                          tempVarint,
                          varintLen); // Update SignatureHash with new Varint
                                      // containing new script size
            LOG_HEX(" VARINT new script length: ", tempVarint, varintLen);
            LOG(" TX_VARINT: pushOffset: %d CreateVarint: lengtn %d\n",
                pushOffset,
                varintLen);
            LOG_HEX(" DATA after pushOffset: ",
                    APDU_DATA_PTR + pushOffset,
                    (rx - DATA) - pushOffset);
            // Make sure there is actually a script portion
            // to hash as part of the sighash computation
            if ((rx - DATA) > pushOffset) {
                sha256_update(
                    &ctx->signatureHash,
                    APDU_DATA_PTR + pushOffset,
                    (rx - DATA) -
                        pushOffset); // Update TX hash minus first 4 OPs
            }
        } else {
            sha256_update(&ctx->signatureHash,
                          APDU_DATA_PTR,
                          (rx - DATA)); // Update signatureHash normally
        }
    } else if (ctx->script_read ==
               0) { // Update SignatureHash with fake 0-len script and offset
        unsigned char fakeScript[5];
        fakeScript[0] = 0;
        fakeScript[1] = fakeScript[2] = fakeScript[3] = fakeScript[4] = 0xff;
        sha256_update(
            &ctx->signatureHash, fakeScript, 5); // Update SignatureHash
        LOG_HEX(" Fake script: ", fakeScript, sizeof(fakeScript));
    }

    ctx->script_read += rx - DATA; // Advance script pointer
    // Check script validity TODO
    ctx->tx_total_read += rx - DATA;
    SET_APDU_FOR_BTC();
    *tx = TX_FOR_TXLEN();
    // Finish reading script if >254
    ctx->script_length -= (rx - DATA);
    LOG(" TX_INPUT_READ: Script remaining: %d\n", ctx->script_length);
    if (ctx->script_length > 0) {
        if (ctx->script_length > MAX_USB_TRANSFER)
            SET_APDU_TXLEN(MAX_USB_TRANSFER); // read partial script
        else
            SET_APDU_TXLEN(
                ctx->script_length); // read whole script + sequence_no
        return;
    } else { // Script completely read
        ctx->btc_input_counter -= 1;
        LOG(" TX_INPUT_READ: total read %d  total len: %d, "
            "btc_input_counter %d)\n",
            ctx->tx_total_read,
            ctx->tx_total_len,
            ctx->btc_input_counter);
        ctx->currentTxInput++;
        if (ctx->btc_input_counter == 0) {
            *state = S_TX_REMAINING; // We parsed all inputs
            if (ctx->tx_total_len - ctx->tx_total_read > MAX_USB_TRANSFER)
                SET_APDU_TXLEN(MAX_USB_TRANSFER);
            else
                SET_APDU_TXLEN(ctx->tx_total_len - ctx->tx_total_read);
        } else {
            *state = S_TX_INPUT_START;
            SET_APDU_TXLEN(32 + 4 +
                           1); // Previous hash+outputindex+ScriptLenght
        }
    }
}

void SM_TX_INPUT_REMAINING(TX_CTX *ctx,
                           PARSE_STM *state,
                           unsigned int rx,
                           unsigned int *tx) {
    LOG(" TX_REMAINING: read %d bytes\n", rx - DATA);
    if (rx > DATA) {
        sha256_update(
            &ctx->TX_hash, APDU_DATA_PTR, rx - DATA); // Update TX hash
        sha256_update(&ctx->signatureHash,
                      APDU_DATA_PTR,
                      rx - DATA); // Update signature hash
        ctx->tx_total_read += rx - DATA;
    }
    LOG_HEX(" DATA recv: ", APDU_DATA_PTR, (int)rx - DATA);
    SET_APDU_FOR_BTC();
    LOG(" TX_REMAINING: total read %d  total len: %d)\n",
        ctx->tx_total_read,
        ctx->tx_total_len);
    if (ctx->tx_total_read == ctx->tx_total_len - 4) {
        *state = S_TX_END;
        SET_APDU_TXLEN(0);
    } else {
        if (ctx->tx_total_len - ctx->tx_total_read > MAX_USB_TRANSFER)
            SET_APDU_TXLEN(MAX_USB_TRANSFER);
        else
            SET_APDU_TXLEN(ctx->tx_total_len - ctx->tx_total_read);
    }
    *tx = TX_FOR_TXLEN();
}

void SM_TX_END(TX_CTX *ctx,
               PARSE_STM *state,
               unsigned int rx,
               unsigned int *tx) {
    LOG(" TX_END\n");
    // ----- Finish TX Hash calculation
    sha256_final(&ctx->TX_hash, ctx->TXHashBuf);
    // Double sha256
    sha256_init(&ctx->TX_hash);
    sha256_update(&ctx->TX_hash, ctx->TXHashBuf, sizeof(ctx->TXHashBuf));
    sha256_final(&ctx->TX_hash, ctx->TXHashBuf);
    // Invert bytes
    for (unsigned char q, i = 0; i < sizeof(ctx->TXHashBuf) / 2; i++) {
        q = ctx->TXHashBuf[i];
        ctx->TXHashBuf[i] = ctx->TXHashBuf[sizeof(ctx->TXHashBuf) - i - 1];
        ctx->TXHashBuf[sizeof(ctx->TXHashBuf) - i - 1] = q;
    }
    LOG_HEX(" TX_HASH", ctx->TXHashBuf, sizeof(ctx->TXHashBuf));
    // Add HashType to Temporary Transaction
    unsigned int hashType = SIGHASH_ALL;
    sha256_update(
        &ctx->signatureHash, (unsigned char *)&hashType, sizeof(hashType));
    // ---- Finish SignatureHash calculation
    sha256_final(&ctx->signatureHash, ctx->signatureHashBuf);
    // Double sha256
    sha256_init(&ctx->signatureHash);
    sha256_update(&ctx->signatureHash,
                  ctx->signatureHashBuf,
                  sizeof(ctx->signatureHashBuf));
    sha256_final(&ctx->signatureHash, ctx->signatureHashBuf);
    LOG_HEX(
        " TX_SIGHASH", ctx->signatureHashBuf, sizeof(ctx->signatureHashBuf));
    ctx->validHashes = true; // Indicated hashes have been calculated
    SET_APDU_CLA();
    SET_APDU_CMD(INS_SIGN);
    SET_APDU_OP(P1_RECEIPT);
    SET_APDU_TXLEN(0);
    *tx = TX_FOR_TXLEN();
    *state = S_CMD_START;
}
