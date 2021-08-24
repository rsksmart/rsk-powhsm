/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   Trie Merkle Proof parser state machine
 ********************************************************************************/

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
    unsigned char receiptsRoot[HASHLEN];
    unsigned char nodeCount; // Tree node count
    unsigned char nodeIndex; // Amount of parsed nodes
    unsigned char nodeLen;   // Current node len
    unsigned char offset;    // read count
    unsigned int childrensize;
    unsigned int valueLen;
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
