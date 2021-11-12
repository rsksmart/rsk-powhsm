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

#include "dbg.h"

#include <string.h>
#include "defs.h"
#include "merkleProof.h"
#include "varint.h"
#include "mem.h"
#include "memutil.h"

#define SET_APDU_FOR_MP()   \
    SET_APDU_CLA();         \
    SET_APDU_CMD(INS_SIGN); \
    SET_APDU_OP(P1_MERKLEPROOF);

void increment_offset(MP_CTX *ctx, unsigned int rx) {
    if (rx < DATA || (ctx->offset + rx - DATA) > ctx->nodeLen) {
        THROW(0x6A99);
    }
    ctx->offset += rx - DATA;
}

void MP_START(MP_CTX *ctx,
              PARSE_STM *state,
              unsigned int rx,
              unsigned int *tx,
              unsigned char *Receipt_Hash,
              unsigned char *receiptsRoot,
              unsigned char *signatureHash) // INIT parser
{
    // Input len check
    if (rx - DATA != 1 || APDU_AT(DATA) == 0)
        THROW(0x6A87);
    // Clean context
    memset(ctx, 0, sizeof(*ctx));
    ctx->nodeCount = APDU_AT(DATA);
    ctx->nodeIndex = 0;
    ctx->receiptHashChecked = false;
    ctx->receiptsRootChecked = false;
    // Copy parameters (ReceiptHash and ReceiptsRoot)
    SAFE_MEMMOVE(ctx->receiptHash,
                 sizeof(ctx->receiptHash),
                 0,
                 Receipt_Hash,
                 HASHLEN,
                 0,
                 HASHLEN,
                 THROW(0x6A87));
    SAFE_MEMMOVE(ctx->receiptsRoot,
                 sizeof(ctx->receiptsRoot),
                 0,
                 receiptsRoot,
                 HASHLEN,
                 0,
                 HASHLEN,
                 THROW(0x6A87));
    SAFE_MEMMOVE(ctx->signatureHash,
                 sizeof(ctx->signatureHash),
                 0,
                 signatureHash,
                 HASHLEN,
                 0,
                 HASHLEN,
                 THROW(0x6A87));
    LOG("MP START rx:%d\n", rx);
    SET_APDU_FOR_MP();
    SET_APDU_TXLEN(2); // NodeLen+Flags
    *state = S_MP_NODE_HDR;
    *tx = TX_FOR_TXLEN();
}

void MP_NODE_HDR(MP_CTX *ctx,
                 PARSE_STM *state,
                 unsigned int rx,
                 unsigned int *tx) {
    LOG("---------------- Node start: %d--------------------\n",
        ctx->nodeIndex);
    // Init node hash
    keccak_init(&ctx->NodeHash_ctx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, APDU_DATA_PTR + 1, 1);
    ctx->nodeLen = APDU_AT(DATA);
    // Verify node is at least one byte long
    if (ctx->nodeLen == 0) {
        THROW(0x6A87);
    }
    // Zero out left and right node hashes
    explicit_bzero(ctx->left_node_hash, sizeof(ctx->left_node_hash));
    explicit_bzero(ctx->right_node_hash, sizeof(ctx->right_node_hash));
    ctx->offset = 1;
    unsigned char flags = APDU_AT(DATA + 1);
    // Parse flags
    ctx->node_version = (flags & 0b11000000) >> 6;
    ctx->has_long_value = (flags & 0b00100000) > 0;
    ctx->shared_prefix_present = (flags & 0b00010000) > 0;
    ctx->node_present_left = (flags & 0b00001000) > 0;
    ctx->node_present_right = (flags & 0b00000100) > 0;
    ctx->node_is_embedded_left = (flags & 0b00000010) > 0;
    ctx->node_is_embedded_right = (flags & 0b00000001) > 0;
    LOG("MP NODEHDR nodelen:%d node_version: %d has_long_value: %d "
        "shared_prefix_present: %d node_present_left: %d node_present_right: "
        "%d node_embedded_left: %d node_embeddeD_right: %d \n",
        ctx->nodeLen,
        ctx->node_version,
        ctx->has_long_value,
        ctx->shared_prefix_present,
        ctx->node_present_left,
        ctx->node_present_right,
        ctx->node_is_embedded_left,
        ctx->node_is_embedded_right);
    // Check node version
    if (ctx->node_version != 1)
        THROW(0x6A92);

    // First node MUST be a leaf node
    if (!ctx->nodeIndex &&
        (ctx->node_present_left || ctx->node_present_right)) {
        // Fail indicating a receipt hash mismatch.
        THROW(0x6A94);
    }

    SET_APDU_FOR_MP();
    *tx = TX_FOR_TXLEN();

    // Read shared path
    if (ctx->shared_prefix_present) {
        SET_APDU_TXLEN(1); // Read node len
        *state = S_MP_NODE_SHARED_PREFIX_HDR;
    } else {

        if (ctx->node_present_left) {
            *state = S_MP_NODE_LEFT;
            if (!ctx->node_is_embedded_left) {
                // Read left node hash
                SET_APDU_TXLEN(HASHLEN);
            } else {
                // Read left node bytes
                SET_APDU_TXLEN(1); // Read node len
            }
        } else { // Read right node
            SET_APDU_TXLEN(0);
            *state = S_MP_NODE_HDR2;
        }
    }
}

void MP_NODE_SHARED_PREFIX_HDR(MP_CTX *ctx,
                               PARSE_STM *state,
                               unsigned int rx,
                               unsigned int *tx) {
    LOG("MP SP_HDR rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, APDU_DATA_PTR, rx - DATA);

    unsigned char first_byte = APDU_AT(DATA);
    unsigned int length;

    SET_APDU_FOR_MP();
    if ((first_byte >= 0) && (first_byte <= 31))
        length = first_byte + 1;
    if ((first_byte >= 32) && (first_byte <= 254))
        length = first_byte + 128;
    if (first_byte == 255) { // Read VARINT
        SET_APDU_TXLEN(1);   // Varint HDR
        *state = S_MP_NODE_SHARED_PREFIX_VARINT_HDR;
    } else { // Read directly length in bits
        SET_APDU_TXLEN((length >> 3) + 1);
        *state = S_MP_NODE_SHARED_PREFIX_BODY;
    }
    *tx = TX_FOR_TXLEN();
}

void MP_NODE_SHARED_PREFIX_VARINT_HDR(MP_CTX *ctx,
                                      PARSE_STM *state,
                                      unsigned int rx,
                                      unsigned int *tx) {
    LOG("MP SP_VARINT_HDR rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, APDU_DATA_PTR, rx - DATA);
    SET_APDU_FOR_MP();
    switch (APDU_AT(DATA)) {
    default: // 8 bits
        SET_APDU_TXLEN((APDU_AT(DATA) >> 3) + 1);
        *state = S_MP_NODE_SHARED_PREFIX_BODY;
        return;
    case 0xFD: // 16 bits
        SET_APDU_TXLEN(2);
        break;
    case 0xFE: // 32 bits
        SET_APDU_TXLEN(4);
        break;
    case 0xFF: // 64 bits
        SET_APDU_TXLEN(8);
        break;
    }
    *tx = TX_FOR_TXLEN();
    *state = S_MP_NODE_SHARED_PREFIX_VARINT_BODY;
}

void MP_NODE_SHARED_PREFIX_VARINT_BODY(MP_CTX *ctx,
                                       PARSE_STM *state,
                                       unsigned int rx,
                                       unsigned int *tx) {
    LOG("MP SP_VARINT_BODY rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, APDU_DATA_PTR, rx - DATA);
    SET_APDU_FOR_MP();
    unsigned int length = 0;
    // Make sure we got data
    if (!APDU_DATA_SIZE(rx))
        THROW(0x6A87);
    // Read length from input
    SAFE_MEMMOVE(&length,
                 sizeof(length),
                 0,
                 APDU_DATA_PTR,
                 APDU_TOTAL_DATA_SIZE,
                 0,
                 APDU_DATA_SIZE(rx),
                 THROW(0x6A87));
    // Shared prefixes over MAX_MP_TRANSFER_SIZE not supported
    if ((length >> 3) + 1 > MAX_MP_TRANSFER_SIZE)
        THROW(0x6A93);
    SET_APDU_TXLEN((length >> 3) + 1);
    *tx = TX_FOR_TXLEN();
    *state = S_MP_NODE_SHARED_PREFIX_BODY;
}

void MP_NODE_SHARED_PREFIX_BODY(MP_CTX *ctx,
                                PARSE_STM *state,
                                unsigned int rx,
                                unsigned int *tx) {
    LOG("MP SP_BODY rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, APDU_DATA_PTR, rx - DATA);

    SET_APDU_FOR_MP();

    // After parsing the prefix body, we continue with the left node.
    if (ctx->node_present_left) {
        *state = S_MP_NODE_LEFT;
        if (!ctx->node_is_embedded_left) {
            // Read left node hash
            SET_APDU_TXLEN(HASHLEN);
        } else {
            // Read left node bytes
            SET_APDU_TXLEN(1); // Read node len
        }
    } else { // Read right node
        SET_APDU_TXLEN(0);
        *state = S_MP_NODE_HDR2;
    }

    *tx = TX_FOR_TXLEN();
}

void MP_NODE_LEFT(MP_CTX *ctx,
                  PARSE_STM *state,
                  unsigned int rx,
                  unsigned int *tx) {
    LOG("MP LEFT rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, APDU_DATA_PTR, rx - DATA);
    SET_APDU_FOR_MP();
    // Read hash
    if (rx - DATA == HASHLEN) {
        // Copy hash and continue parsing
        SAFE_MEMMOVE(ctx->left_node_hash,
                     sizeof(ctx->left_node_hash),
                     0,
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     0,
                     HASHLEN,
                     THROW(0x6A87));
        SET_APDU_TXLEN(0);
        *state = S_MP_NODE_HDR2;
        LOG_HEX("Left: ", ctx->left_node_hash, HASHLEN);
    }
    // Prepare to read bytes
    if (rx - DATA == 1) {
        SET_APDU_TXLEN(APDU_AT(DATA));
        *state = S_MP_NODE_LEFT_BYTES;
    }
    *tx = TX_FOR_TXLEN();
}

void MP_NODE_LEFT_BYTES(MP_CTX *ctx,
                        PARSE_STM *state,
                        unsigned int rx,
                        unsigned int *tx) {
    LOG("MP LEFT_BYTES rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, APDU_DATA_PTR, rx - DATA);
    // Per RSKIP107 we know the node fits in a single message, proceed to hash
    // left node
    keccak_init(&ctx->ReceiptHash_ctx);
    keccak_update(&ctx->ReceiptHash_ctx, APDU_DATA_PTR, rx - DATA);
    keccak_final(&ctx->ReceiptHash_ctx, ctx->left_node_hash);
    LOG_HEX("Hash: ", ctx->left_node_hash, HASHLEN);
    SET_APDU_FOR_MP();
    SET_APDU_TXLEN(0);
    *state = S_MP_NODE_HDR2;
    *tx = TX_FOR_TXLEN();
}

void MP_NODE_HDR2(MP_CTX *ctx,
                  PARSE_STM *state,
                  unsigned int rx,
                  unsigned int *tx) {
    LOG("MP HDR2 rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, APDU_DATA_PTR, rx - DATA);
    SET_APDU_FOR_MP();
    if (ctx->node_present_right) {
        *state = S_MP_NODE_RIGHT;
        if (!ctx->node_is_embedded_right)
            SET_APDU_TXLEN(HASHLEN);
        else
            SET_APDU_TXLEN(1); // Read node len
    } else {
        *state = S_MP_NODE_CHILDRENSIZE;
        SET_APDU_TXLEN(0);
    }
    *tx = TX_FOR_TXLEN();
}

void MP_NODE_RIGHT(MP_CTX *ctx,
                   PARSE_STM *state,
                   unsigned int rx,
                   unsigned int *tx) {
    LOG("MP RIGHT rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, APDU_DATA_PTR, rx - DATA);
    SET_APDU_FOR_MP();
    // Read hash
    if (rx - DATA == HASHLEN) {
        // Copy hash and continue parsing
        SAFE_MEMMOVE(ctx->right_node_hash,
                     sizeof(ctx->right_node_hash),
                     0,
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     0,
                     HASHLEN,
                     THROW(0x6A87));
        SET_APDU_TXLEN(0);
        *state = S_MP_NODE_CHILDRENSIZE;
        LOG_HEX("Right: ", ctx->right_node_hash, HASHLEN);
    }
    // Prepare to read bytes
    if (rx - DATA == 1) {
        SET_APDU_TXLEN(APDU_AT(DATA));
        *state = S_MP_NODE_RIGHT_BYTES;
    }
    *tx = TX_FOR_TXLEN();
}

void MP_NODE_RIGHT_BYTES(MP_CTX *ctx,
                         PARSE_STM *state,
                         unsigned int rx,
                         unsigned int *tx) {
    LOG("MP RIGHT_BYTES rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, APDU_DATA_PTR, rx - DATA);
    // Per RSKIP107 we know the node fits in a single message, proceed to hash
    // left node
    keccak_init(&ctx->ReceiptHash_ctx);
    keccak_update(&ctx->ReceiptHash_ctx, APDU_DATA_PTR, rx - DATA);
    keccak_final(&ctx->ReceiptHash_ctx, ctx->right_node_hash);
    SET_APDU_FOR_MP();
    SET_APDU_TXLEN(0);
    *state = S_MP_NODE_CHILDRENSIZE;
    *tx = TX_FOR_TXLEN();
}

void MP_NODE_CHILDRENSIZE(MP_CTX *ctx,
                          PARSE_STM *state,
                          unsigned int rx,
                          unsigned int *tx) {
    LOG("MP CHILDRENSIZE rx:%d\n", rx);
    increment_offset(ctx, rx);
    SET_APDU_FOR_MP();
    if (ctx->node_present_left ||
        ctx->node_present_right) { // read ChildrenSize VARINT
        SET_APDU_TXLEN(1);
        *state = S_MP_NODE_VARINT_HDR;
    } else {
        SET_APDU_TXLEN(0);
        *state = S_MP_NODE_VALUE;
    }
    *tx = TX_FOR_TXLEN();
}

void MP_NODE_VARINT_HDR(MP_CTX *ctx,
                        PARSE_STM *state,
                        unsigned int rx,
                        unsigned int *tx) {
    LOG("MP VARINT_HDR rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, APDU_DATA_PTR, rx - DATA);
    SET_APDU_FOR_MP();
    SET_APDU_TXLEN(varintLen(APDU_AT(DATA)));
    *state = S_MP_NODE_VARINT_BODY;
    *tx = TX_FOR_TXLEN();
}

void MP_NODE_VARINT_BODY(MP_CTX *ctx,
                         PARSE_STM *state,
                         unsigned int rx,
                         unsigned int *tx) {
    LOG("MP VARINT_BODY rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, APDU_DATA_PTR, rx - DATA);
    SET_APDU_FOR_MP();
    SET_APDU_TXLEN(0);
    *state = S_MP_NODE_VALUE;
    *tx = TX_FOR_TXLEN();
}

void MP_NODE_VALUE(MP_CTX *ctx,
                   PARSE_STM *state,
                   unsigned int rx,
                   unsigned int *tx) {
    LOG("MP VALUE rx:%d\n", rx);

    if (!ctx->nodeIndex && !ctx->has_long_value) {
        // We are reading the first node of the partial merkle
        // proof, which in a valid proof MUST be the leaf and contain the
        // receipt as a value. Any receipt is by definition more than 32 bytes
        // in size, and therefore a merkle proof node that contains it should
        // encode it as a long value (i.e., containing hash and length only)
        // Hence, getting here indicates the given proof is INVALID.
        // Fail indicating a receipt hash mismatch.
        THROW(0x6A94);
    }

    increment_offset(ctx, rx);
    SET_APDU_FOR_MP();
    if (ctx->has_long_value) {
        // Read value header
        SET_APDU_TXLEN(HASHLEN + 3); // ValueHash+ValueLen
        *state = S_MP_NODE_VALUE_LEN;
    } else { // Read remaining bytes
        SET_APDU_TXLEN(ctx->nodeLen - ctx->offset);
        *state = S_MP_NODE_REMAINING;
    }
    *tx = TX_FOR_TXLEN();
}

void MP_NODE_VALUE_LEN(MP_CTX *ctx,
                       PARSE_STM *state,
                       unsigned int rx,
                       unsigned int *tx) {
    LOG("MP VALUE_LEN rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, APDU_DATA_PTR, rx - DATA);
    // ValueHash
    SAFE_MEMMOVE(ctx->value_hash,
                 sizeof(ctx->value_hash),
                 0,
                 APDU_DATA_PTR,
                 APDU_TOTAL_DATA_SIZE,
                 0,
                 HASHLEN,
                 THROW(0x6A87));
    // Check Receipt hash, must be equal that the first trie node value
    if (!ctx->nodeIndex) {
        if (memcmp(ctx->value_hash, ctx->receiptHash, HASHLEN)) {
            THROW(0x6A94);
        } else {
            ctx->receiptHashChecked = true;
            LOG("Receipt Hash MATCH\n");
        }
    }
    SET_APDU_FOR_MP();
    SET_APDU_TXLEN(ctx->nodeLen - ctx->offset);
    *tx = TX_FOR_TXLEN();
    *state = S_MP_NODE_REMAINING;
}

void MP_NODE_REMAINING(MP_CTX *ctx,
                       PARSE_STM *state,
                       unsigned int rx,
                       unsigned int *tx) {
    LOG("MP REMAINING rx:%d\n", rx);
    // Check chaining of this node with the parent
    if (ctx->nodeIndex > 0) {
        int cmpLeft =
            memcmp(ctx->current_node_hash, ctx->left_node_hash, HASHLEN);
        int cmpRight =
            memcmp(ctx->current_node_hash, ctx->right_node_hash, HASHLEN);
        if (cmpLeft && cmpRight) {
            LOG("Node Chaining check MISMATCH\n");
            THROW(0x6A95);
        } else
            LOG("Node Chaining check PASSED\n");
    }
    // Update node hash (only if there is more data)
    if (rx > DATA) {
        keccak_update(&ctx->NodeHash_ctx, APDU_DATA_PTR, rx - DATA);
    }
    SET_APDU_FOR_MP();
    ctx->nodeCount--;
    ctx->nodeIndex++;
    keccak_final(&ctx->NodeHash_ctx, ctx->current_node_hash);
    LOG_HEX("Node hash: ", ctx->current_node_hash, HASHLEN);
    // Check Node Trie ROOT
    if (!ctx->nodeCount) {
        if (memcmp(ctx->current_node_hash, ctx->receiptsRoot, HASHLEN)) {
            THROW(0x6A96);
        } else {
            ctx->receiptsRootChecked = true;
            LOG("Receipt trie root MATCH\n");
        }
    }
    if (ctx->nodeCount) {
        SET_APDU_TXLEN(2); // NodeLen+Flags
        *state = S_MP_NODE_HDR;
    } else if (ctx->receiptsRootChecked &&
               ctx->receiptHashChecked) { // Finished reading trie
        SET_APDU_TXLEN(0);
        *state = S_SIGN_MESSAGE;
    } else { // Coudln't check trie path
        THROW(0x6A96);
    }
    *tx = TX_FOR_TXLEN();
}
