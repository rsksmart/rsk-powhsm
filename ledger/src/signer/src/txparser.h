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

#ifndef TXPARSER_H
#define TXPARSER_H

#include <stdbool.h>

#include "sha256.h"
#include "keccak256.h"
#include "defs.h"

// TX state machine parsing context
typedef struct {
    unsigned int tx_version;             // Transaction version
    unsigned int tx_total_len;           // BTC transaction total length
    unsigned int tx_total_read;          // BTC transaction total read
    unsigned int script_length;          // TX Script length
    unsigned int tx_input_index_to_sign; // Index to sign
    unsigned int btc_input_counter;      // Amount of inputs in the TX
    unsigned int currentTxInput;         // Current input being parsed
    // Sha256 hashes CTXs
    SHA256_CTX TX_hash;
    SHA256_CTX signatureHash;
    unsigned int script_read; // Script offset inside TX
    // Signature hash of the selected input, and hash of the whole BTC TX
    unsigned char signatureHashBuf[32];
    unsigned char TXHashBuf[32];
    bool validHashes; // Indicates valid hashes have been calculated
    bool validContract, validSignature; // Individual checks indicators
    // Input validation
    unsigned char expectedRXBytes;
} TX_CTX;

// Signature type
#define SIGHASH_ALL 1
#define TXDEBUG 0
void SM_TX_START(TX_CTX *ctx,
                 PARSE_STM *state,
                 unsigned int rx,
                 unsigned int *tx); // INIT parser
void SM_TX_HDR(TX_CTX *ctx,
               PARSE_STM *state,
               unsigned int rx,
               unsigned int *tx); // parsing field header
void SM_TX_VARINT(TX_CTX *ctx,
                  PARSE_STM *state,
                  unsigned int rx,
                  unsigned int *tx); // Load multi-byte varint
// Input parser
void SM_TX_INPUT_START(TX_CTX *ctx,
                       PARSE_STM *state,
                       unsigned int rx,
                       unsigned int *tx);
void SM_TX_INPUT_READ(TX_CTX *ctx,
                      PARSE_STM *state,
                      unsigned int rx,
                      unsigned int *tx);
// Read script
void SM_TX_SCRIPT_READ(TX_CTX *ctx,
                       PARSE_STM *state,
                       unsigned int rx,
                       unsigned int *tx);
// Read remaining of TX
void SM_TX_INPUT_REMAINING(TX_CTX *ctx,
                           PARSE_STM *state,
                           unsigned int rx,
                           unsigned int *tx);
// Check and do signature
void SM_TX_END(TX_CTX *ctx,
               PARSE_STM *state,
               unsigned int rx,
               unsigned int *tx);

#endif // TXPARSER_H
