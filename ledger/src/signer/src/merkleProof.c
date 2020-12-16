/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   MP parser state machine
 ********************************************************************************/

#ifndef FEDHM_EMULATOR
#include "os.h"
#else
#include <stdio.h>
#include <stdlib.h>
#endif

#include <string.h>
#include "defs.h"
#include "merkleProof.h"
#include "varint.h"
#include "mem.h"

// Print buffer in hex (Debug)
static void printHex(char *hdr, unsigned char *buf, int len) {
#ifdef FEDHM_EMULATOR
    puts(hdr);
    for (int i = 0; i < len; i++)
        printf("%02x", (unsigned char)buf[i]);
    printf("\n");
#endif
}

#ifndef FEDHM_EMULATOR
#define printf printnull
#endif

// Avoid printf on real device
void printnull(char *format, ...){};

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
    // Copy parameters (ReceiptHash and ReceiptsRoot)
    memcpy(ctx->receiptHash, Receipt_Hash, HASHLEN);
    memcpy(ctx->receiptsRoot, receiptsRoot, HASHLEN);
    memcpy(ctx->signatureHash, signatureHash, HASHLEN);
    printf("MP START rx:%d\n", rx);
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
    printf("---------------- Node start: %d--------------------\n",
           ctx->nodeIndex);
    // Init node hash
    keccak_init(&ctx->NodeHash_ctx);
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA + 1], 1);
    ctx->nodeLen = G_io_apdu_buffer[DATA];
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
    printf(
        "MP NODEHDR nodelen:%d node_version: %d has_long_value: %d "
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
    printf("MP SP_HDR rx:%d\n", rx);
    ctx->offset += rx - DATA;
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
    printf("MP SP_VARINT_HDR rx:%d\n", rx);
    ctx->offset += rx - DATA;
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
    printf("MP SP_VARINT_BODY rx:%d\n", rx);
    ctx->offset += rx - DATA;
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;
    unsigned int length = 0;
    // Read length from input
    if (rx - DATA > 0)
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
    printf("MP SP_BODY rx:%d\n", rx);
    ctx->offset += rx - DATA;
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
    printf("MP LEFT rx:%d\n", rx);
    ctx->offset += rx - DATA;
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;
    // Read hash
    if (rx - DATA == HASHLEN) {
        // Copy hash and continue parsing
        memcpy(&ctx->left_node_hash, &G_io_apdu_buffer[DATA], HASHLEN);
        G_io_apdu_buffer[TXLEN] = 0;
        *state = S_MP_NODE_HDR2;
        printHex("Left: ", ctx->left_node_hash, HASHLEN);
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
    printf("MP LEFT_BYTES rx:%d\n", rx);
    ctx->offset += rx - DATA;
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    // Per RSKIP107 we know the node fits in a single message, proceed to hash
    // left node
    keccak_init(&ctx->ReceiptHash_ctx);
    keccak_update(&ctx->ReceiptHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    keccak_final(&ctx->ReceiptHash_ctx, ctx->left_node_hash);
    printHex("Hash: ", ctx->left_node_hash, HASHLEN);
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
    printf("MP HDR2 rx:%d\n", rx);
    ctx->offset += rx - DATA;
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
    printf("MP RIGHT rx:%d\n", rx);
    ctx->offset += rx - DATA;
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;
    // Read hash
    if (rx - DATA == HASHLEN) {
        // Copy hash and continue parsing
        memcpy(&ctx->right_node_hash, &G_io_apdu_buffer[DATA], HASHLEN);
        G_io_apdu_buffer[TXLEN] = 0;
        *state = S_MP_NODE_CHILDRENSIZE;
        printHex("Right: ", ctx->right_node_hash, HASHLEN);
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
    printf("MP RIGHT_BYTES rx:%d\n", rx);
    ctx->offset += rx - DATA;
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
    printf("MP CHILDRENSIZE rx:%d\n", rx);
    ctx->offset += rx - DATA;
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
    printf("MP VARINT_HDR rx:%d\n", rx);
    ctx->offset += rx - DATA;
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
    printf("MP VARINT_BODY rx:%d\n", rx);
    ctx->offset += rx - DATA;
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
    printf("MP VALUE rx:%d\n", rx);
    ctx->offset += rx - DATA;
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
    printf("MP VALUE_LEN rx:%d\n", rx);
    ctx->offset += rx - DATA;
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    // ValueHash
    memcpy(&ctx->value_hash, &G_io_apdu_buffer[DATA], HASHLEN);
    // Check Receipt hash, must be equal that the first trie node value
    if (!ctx->nodeIndex) {
        if (memcmp(ctx->value_hash, ctx->receiptHash, HASHLEN))
            THROW(0x6A94);
        else
            printf("Receipt Hash MATCH\n");
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
    printf("MP REMAINING rx:%d\n", rx);
    // Check chaining of this node with the parent
    if (ctx->nodeIndex > 0) {
        int cmpLeft =
            memcmp(ctx->current_node_hash, ctx->left_node_hash, HASHLEN);
        int cmpRight =
            memcmp(ctx->current_node_hash, ctx->right_node_hash, HASHLEN);
        if (cmpLeft && cmpRight) {
            printf("Node Chaining check MISMATCH\n");
            THROW(0x6A95);
        } else
            printf("Node Chaining check PASSED\n");
    }
    // Update node hash
    keccak_update(&ctx->NodeHash_ctx, &G_io_apdu_buffer[DATA], rx - DATA);
    G_io_apdu_buffer[CLAPOS] = CLA;
    G_io_apdu_buffer[CMDPOS] = INS_SIGN;
    G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
    *tx = 4;
    ctx->nodeCount--;
    ctx->nodeIndex++;
    keccak_final(&ctx->NodeHash_ctx, ctx->current_node_hash);
    printHex("Node hash: ", ctx->current_node_hash, HASHLEN);
    // Check Node Trie ROOT
    if (!ctx->nodeCount) {
        if (memcmp(ctx->current_node_hash, ctx->receiptsRoot, HASHLEN))
            THROW(0x6A96);
        else
            printf("Receipt trie root MATCH\n");
    }
    if (ctx->nodeCount) {
        G_io_apdu_buffer[TXLEN] = 2; // NodeLen+Flags
        *state = S_MP_NODE_HDR;
    } else { // Finished reading trie
        G_io_apdu_buffer[TXLEN] = 0;
        *state = S_SIGN_MESSAGE;
    }
}
