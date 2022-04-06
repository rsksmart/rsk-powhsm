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

#ifndef MPPARSER_H
#define MPPARSER_H

#include <stdbool.h>

#include "defs.h"
#include "keccak256.h"

#define MAX_MP_TRANSFER_SIZE 50
//#define NodeHash_ctx ReceiptHash_ctx

// MP state machine parsing context
typedef struct {
    // RLP Receipt keccak256 hash
    SHA3_CTX ReceiptHash_ctx;
    SHA3_CTX NodeHash_ctx;
    // Hashes to control
    unsigned char receiptHash[HASHLEN];
    bool receiptHashChecked;
    unsigned char receiptsRoot[HASHLEN];
    bool receiptsRootChecked;
    unsigned char nodeCount; // Tree node count
    unsigned char nodeIndex; // Amount of parsed nodes
    unsigned char nodeLen;   // Current node len
    unsigned char offset;    // read count
    unsigned int childrensize;
    // Current node flags
    unsigned char node_version, has_long_value, shared_prefix_present,
        node_present_left, node_present_right, node_is_embedded_left,
        node_is_embedded_right;
    unsigned char left_node_hash[HASHLEN];
    unsigned char right_node_hash[HASHLEN];
    unsigned char value_hash[HASHLEN];
    unsigned char current_node_hash[HASHLEN];
    // Hash to sign
    unsigned char signatureHash[HASHLEN];
    // Input validation
    unsigned char expectedRXBytes;
} MP_CTX;

void MP_START(MP_CTX *ctx,
              PARSE_STM *state,
              unsigned int rx,
              unsigned int *tx,
              unsigned char *Receipt_Hash,
              unsigned char *receiptsRoot,
              unsigned char *signatureHash); // INIT parser
void MP_NODE_SHARED_PREFIX_HDR(MP_CTX *ctx,
                               PARSE_STM *state,
                               unsigned int rx,
                               unsigned int *tx);
void MP_NODE_SHARED_PREFIX_BODY(MP_CTX *ctx,
                                PARSE_STM *state,
                                unsigned int rx,
                                unsigned int *tx);
void MP_NODE_SHARED_PREFIX_VARINT_HDR(MP_CTX *ctx,
                                      PARSE_STM *state,
                                      unsigned int rx,
                                      unsigned int *tx);
void MP_NODE_SHARED_PREFIX_VARINT_BODY(MP_CTX *ctx,
                                       PARSE_STM *state,
                                       unsigned int rx,
                                       unsigned int *tx);
void MP_NODE_HDR(MP_CTX *ctx,
                 PARSE_STM *state,
                 unsigned int rx,
                 unsigned int *tx);
void MP_NODE_HDR2(MP_CTX *ctx,
                  PARSE_STM *state,
                  unsigned int rx,
                  unsigned int *tx);
void MP_NODE_LEFT(MP_CTX *ctx,
                  PARSE_STM *state,
                  unsigned int rx,
                  unsigned int *tx);
void MP_NODE_LEFT_BYTES(MP_CTX *ctx,
                        PARSE_STM *state,
                        unsigned int rx,
                        unsigned int *tx);
void MP_NODE_RIGHT(MP_CTX *ctx,
                   PARSE_STM *state,
                   unsigned int rx,
                   unsigned int *tx);
void MP_NODE_RIGHT_BYTES(MP_CTX *ctx,
                         PARSE_STM *state,
                         unsigned int rx,
                         unsigned int *tx);
void MP_NODE_CHILDRENSIZE(MP_CTX *ctx,
                          PARSE_STM *state,
                          unsigned int rx,
                          unsigned int *tx);
void MP_NODE_VARINT_HDR(MP_CTX *ctx,
                        PARSE_STM *state,
                        unsigned int rx,
                        unsigned int *tx);
void MP_NODE_VARINT_BODY(MP_CTX *ctx,
                         PARSE_STM *state,
                         unsigned int rx,
                         unsigned int *tx);
void MP_NODE_VALUE(MP_CTX *ctx,
                   PARSE_STM *state,
                   unsigned int rx,
                   unsigned int *tx);
void MP_NODE_VALUE_LEN(MP_CTX *ctx,
                       PARSE_STM *state,
                       unsigned int rx,
                       unsigned int *tx);
void MP_NODE_REMAINING(MP_CTX *ctx,
                       PARSE_STM *state,
                       unsigned int rx,
                       unsigned int *tx);
#endif // MPPARSER_H
