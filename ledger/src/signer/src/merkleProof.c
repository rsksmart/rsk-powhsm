/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   MP parser state machine
 ********************************************************************************/

#include "os.h"

#include "dbg.h"

#include <string.h>
#include "defs.h"
#include "merkleProof.h"
#include "varint.h"
#include "mem.h"

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
    if (rx - DATA != 1 || G_io_apdu_buffer[DATA] == 0)
        THROW(0x6A87);
    // Clean context
    memset(ctx, 0, sizeof(*ctx));
    ctx->nodeCount = G_io_apdu_buffer[DATA];
    ctx->nodeIndex = 0;
    ctx->receiptHashChecked = false;
    ctx->receiptsRootChecked = false;
    // Copy parameters (ReceiptHash and ReceiptsRoot)
    memcpy(ctx->receiptHash, Receipt_Hash, HASHLEN);
    memcpy(ctx->receiptsRoot, receiptsRoot, HASHLEN);
    memcpy(ctx->signatureHash, signatureHash, HASHLEN);
    LOG("MP START rx:%d\n", rx);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    G_io_apdu_buffer[TXLEN] = 2; // NodeLen+Flags
    *state = S_MP_NODE_HDR;
    *tx = 4;
}

void MP_NODE_HDR(MP_CTX *ctx,
                 PARSE_STM *state,
                 unsigned int rx,
                 unsigned int *tx) {
    LOG("---------------- Node start: %d--------------------\n", ctx->nodeIndex);
    // Init node hash
    keccak_init(&ctx->NodeHash_ctx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA + 1], 1);
    ctx->nodeLen = G_io_apdu_buffer[DATA];
    // Verify node is at least one byte long
    if (ctx->nodeLen == 0) {
        THROW(0x6A87);
    }
    // Zero out left and right node hashes
    explicit_bzero(ctx->left_node_hash, sizeof(ctx->left_node_hash));
    explicit_bzero(ctx->right_node_hash, sizeof(ctx->right_node_hash));
    ctx->offset = 1;
    unsigned char flags = G_io_apdu_buffer[DATA + 1];
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
    if (!ctx->nodeIndex && (ctx->node_present_left || ctx->node_present_right)) {
        // Fail indicating a receipt hash mismatch.
        THROW(0x6A94);
    }

    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;

    // Read shared path
    if (ctx->shared_prefix_present) {
        G_io_apdu_buffer[TXLEN] = 1; // Read node len
        *state = S_MP_NODE_SHARED_PREFIX_HDR;
    } else {

        if (ctx->node_present_left) {
            *state = S_MP_NODE_LEFT;
            if (!ctx->node_is_embedded_left) {
                // Read left node hash
                G_io_apdu_buffer[TXLEN] = HASHLEN;
            } else {
                // Read left node bytes
                G_io_apdu_buffer[TXLEN] = 1; // Read node len
            }
        } else { // Read right node
            G_io_apdu_buffer[TXLEN] = 0;
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
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);

    unsigned char first_byte = G_io_apdu_buffer[DATA];
    unsigned int length;

    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;
    if ((first_byte >= 0) && (first_byte <= 31))
        length = first_byte + 1;
    if ((first_byte >= 32) && (first_byte <= 254))
        length = first_byte + 128;
    if (first_byte == 255) {         // Read VARINT
        G_io_apdu_buffer[TXLEN] = 1; // Varint HDR
        *state = S_MP_NODE_SHARED_PREFIX_VARINT_HDR;
    } else { // Read directly length in bits
        G_io_apdu_buffer[TXLEN] = (length >> 3) + 1;
        *state = S_MP_NODE_SHARED_PREFIX_BODY;
    }
}

void MP_NODE_SHARED_PREFIX_VARINT_HDR(MP_CTX *ctx,
                                      PARSE_STM *state,
                                      unsigned int rx,
                                      unsigned int *tx) {
    LOG("MP SP_VARINT_HDR rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;
    switch (G_io_apdu_buffer[DATA]) {
    default: // 8 bits
        G_io_apdu_buffer[TXLEN] = (G_io_apdu_buffer[DATA] >> 3) + 1;
        *state = S_MP_NODE_SHARED_PREFIX_BODY;
        return;
    case 0xFD: // 16 bits
        G_io_apdu_buffer[TXLEN] = 2;
        break;
    case 0xFE: // 32 bits
        G_io_apdu_buffer[TXLEN] = 4;
        break;
    case 0xFF: // 64 bits
        G_io_apdu_buffer[TXLEN] = 8;
        break;
    }
    *state = S_MP_NODE_SHARED_PREFIX_VARINT_BODY;
}

void MP_NODE_SHARED_PREFIX_VARINT_BODY(MP_CTX *ctx,
                                       PARSE_STM *state,
                                       unsigned int rx,
                                       unsigned int *tx) {
    LOG("MP SP_VARINT_BODY rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;
    unsigned int length = 0;
    // Read length from input, making sure the destination buffer is large enough
    if (rx > DATA && sizeof(length) >= (rx - DATA))
        memmove(&length, &G_io_apdu_buffer[DATA], rx - DATA);
    else
        THROW(0x6A87);
    // Shared prefixes over MAX_MP_TRANSFER_SIZE not supported
    if ((length >> 3) + 1 > MAX_MP_TRANSFER_SIZE)
        THROW(0x6A93);
    G_io_apdu_buffer[TXLEN] = (length >> 3) + 1;
    *state = S_MP_NODE_SHARED_PREFIX_BODY;
}

void MP_NODE_SHARED_PREFIX_BODY(MP_CTX *ctx,
                                PARSE_STM *state,
                                unsigned int rx,
                                unsigned int *tx) {
    LOG("MP SP_BODY rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);

    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;

    // After parsing the prefix body, we continue with the left node.
    if (ctx->node_present_left) {
        *state = S_MP_NODE_LEFT;
        if (!ctx->node_is_embedded_left) {
            // Read left node hash
            G_io_apdu_buffer[TXLEN] = HASHLEN;
        } else {
            // Read left node bytes
            G_io_apdu_buffer[TXLEN] = 1; // Read node len
        }
    } else { // Read right node
        G_io_apdu_buffer[TXLEN] = 0;
        *state = S_MP_NODE_HDR2;
    }
}

void MP_NODE_LEFT(MP_CTX *ctx,
                  PARSE_STM *state,
                  unsigned int rx,
                  unsigned int *tx) {
    LOG("MP LEFT rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;
    // Read hash
    if (rx - DATA == HASHLEN) {
        // Copy hash and continue parsing
        memcpy(ctx->left_node_hash, &G_io_apdu_buffer[DATA], HASHLEN);
        G_io_apdu_buffer[TXLEN] = 0;
        *state = S_MP_NODE_HDR2;
        LOG_HEX("Left: ", ctx->left_node_hash, HASHLEN);
    }
    // Prepare to read bytes
    if (rx - DATA == 1) {
        G_io_apdu_buffer[TXLEN] = G_io_apdu_buffer[DATA];
        *state = S_MP_NODE_LEFT_BYTES;
    }
}

void MP_NODE_LEFT_BYTES(MP_CTX *ctx,
                        PARSE_STM *state,
                        unsigned int rx,
                        unsigned int *tx) {
    LOG("MP LEFT_BYTES rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    // Per RSKIP107 we know the node fits in a single message, proceed to hash
    // left node
    keccak_init(&ctx->ReceiptHash_ctx);
    keccak_update(&ctx->ReceiptHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    keccak_final(&ctx->ReceiptHash_ctx, ctx->left_node_hash);
    LOG_HEX("Hash: ", ctx->left_node_hash, HASHLEN);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    G_io_apdu_buffer[TXLEN] = 0;
    *state = S_MP_NODE_HDR2;
    *tx = 4;
}

void MP_NODE_HDR2(MP_CTX *ctx,
                  PARSE_STM *state,
                  unsigned int rx,
                  unsigned int *tx) {
    LOG("MP HDR2 rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;
    if (ctx->node_present_right) {
        *state = S_MP_NODE_RIGHT;
        if (!ctx->node_is_embedded_right)
            G_io_apdu_buffer[TXLEN] = HASHLEN;
        else
            G_io_apdu_buffer[TXLEN] = 1; // Read node len
    } else {
        *state = S_MP_NODE_CHILDRENSIZE;
        G_io_apdu_buffer[TXLEN] = 0;
    }
}

void MP_NODE_RIGHT(MP_CTX *ctx,
                   PARSE_STM *state,
                   unsigned int rx,
                   unsigned int *tx) {
    LOG("MP RIGHT rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;
    // Read hash
    if (rx - DATA == HASHLEN) {
        // Copy hash and continue parsing
        memcpy(ctx->right_node_hash, &G_io_apdu_buffer[DATA], HASHLEN);
        G_io_apdu_buffer[TXLEN] = 0;
        *state = S_MP_NODE_CHILDRENSIZE;
        LOG_HEX("Right: ", ctx->right_node_hash, HASHLEN);
    }
    // Prepare to read bytes
    if (rx - DATA == 1) {
        G_io_apdu_buffer[TXLEN] = G_io_apdu_buffer[DATA];
        *state = S_MP_NODE_RIGHT_BYTES;
    }
}

void MP_NODE_RIGHT_BYTES(MP_CTX *ctx,
                         PARSE_STM *state,
                         unsigned int rx,
                         unsigned int *tx) {
    LOG("MP RIGHT_BYTES rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    // Per RSKIP107 we know the node fits in a single message, proceed to hash
    // left node
    keccak_init(&ctx->ReceiptHash_ctx);
    keccak_update(&ctx->ReceiptHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    keccak_final(&ctx->ReceiptHash_ctx, ctx->right_node_hash);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    G_io_apdu_buffer[TXLEN] = 0;
    *state = S_MP_NODE_CHILDRENSIZE;
    *tx = 4;
}

void MP_NODE_CHILDRENSIZE(MP_CTX *ctx,
                          PARSE_STM *state,
                          unsigned int rx,
                          unsigned int *tx) {
    LOG("MP CHILDRENSIZE rx:%d\n", rx);
    increment_offset(ctx, rx);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;
    if (ctx->node_present_left ||
        ctx->node_present_right) { // read ChildrenSize VARINT
        G_io_apdu_buffer[TXLEN] = 1;
        *state = S_MP_NODE_VARINT_HDR;
    } else {
        G_io_apdu_buffer[TXLEN] = 0;
        *state = S_MP_NODE_VALUE;
    }
}

void MP_NODE_VARINT_HDR(MP_CTX *ctx,
                        PARSE_STM *state,
                        unsigned int rx,
                        unsigned int *tx) {
    LOG("MP VARINT_HDR rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    G_io_apdu_buffer[TXLEN] = varintLen(G_io_apdu_buffer[DATA]);
    *state = S_MP_NODE_VARINT_BODY;
    *tx = 4;
}

void MP_NODE_VARINT_BODY(MP_CTX *ctx,
                         PARSE_STM *state,
                         unsigned int rx,
                         unsigned int *tx) {
    LOG("MP VARINT_BODY rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    G_io_apdu_buffer[TXLEN] = 0;
    *state = S_MP_NODE_VALUE;
    *tx = 4;
}

void MP_NODE_VALUE(MP_CTX *ctx,
                   PARSE_STM *state,
                   unsigned int rx,
                   unsigned int *tx) {
    LOG("MP VALUE rx:%d\n", rx);

    if (!ctx->nodeIndex && !ctx->has_long_value) {
        // We are reading the first node of the partial merkle
        // proof, which in a valid proof MUST be the leaf and contain the receipt
        // as a value. Any receipt is by definition more than 32 bytes in size,
        // and therefore a merkle proof node that contains it should encode
        // it as a long value (i.e., containing hash and length only)
        // Hence, getting here indicates the given proof is INVALID. 
        // Fail indicating a receipt hash mismatch.
        THROW(0x6A94);
    }
    
    increment_offset(ctx, rx);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;
    if (ctx->has_long_value) {
        // Read value header
        G_io_apdu_buffer[TXLEN] = HASHLEN + 3; // ValueHash+ValueLen
        *state = S_MP_NODE_VALUE_LEN;
    } else { // Read remaining bytes
        G_io_apdu_buffer[TXLEN] = ctx->nodeLen - ctx->offset;
        *state = S_MP_NODE_REMAINING;
    }
}

void MP_NODE_VALUE_LEN(MP_CTX *ctx,
                       PARSE_STM *state,
                       unsigned int rx,
                       unsigned int *tx) {
    LOG("MP VALUE_LEN rx:%d\n", rx);
    increment_offset(ctx, rx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    // ValueHash
    memcpy(&ctx->value_hash, &G_io_apdu_buffer[DATA], HASHLEN);
    // Check Receipt hash, must be equal that the first trie node value
    if (!ctx->nodeIndex) {
        if (memcmp(ctx->value_hash, ctx->receiptHash, HASHLEN)) {
            THROW(0x6A94);
        } else {
            ctx->receiptHashChecked = true;
            LOG("Receipt Hash MATCH\n");
        }
    }
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    G_io_apdu_buffer[TXLEN] = ctx->nodeLen - ctx->offset;
    *tx = 4;
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
        keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    }
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;
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
        G_io_apdu_buffer[TXLEN] = 2; // NodeLen+Flags
        *state = S_MP_NODE_HDR;
    } else if (ctx->receiptsRootChecked && ctx->receiptHashChecked) { // Finished reading trie
        G_io_apdu_buffer[TXLEN] = 0;
        *state = S_SIGN_MESSAGE;
    } else { // Coudln't check trie path
        THROW(0x6A96);
    }
}
