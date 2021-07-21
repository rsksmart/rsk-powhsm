#ifndef __MEM
#define __MEM

#include "txparser.h"
#include "rlp.h"
#include "bc_block.h"
#include "merkleProof.h"

// -----------------------------------------------------------------------
// Global state for signing and blockchain bookkeeping.
// -----------------------------------------------------------------------

typedef union {
    struct {
        // Receipt parsing context
        RLP_CTX rlp_ctx;
        // TX parsing context
        TX_CTX tx_ctx;
        // RLP Receipt keccak256 hash
        SHA3_CTX ReceiptHash_ctx;
    };
    // Trie Merkle Proof context
    MP_CTX mp_ctx;

    struct {
        block_t block;
        aux_bc_state_t aux_bc_st;
    };
} mem_t;

extern mem_t mem;

#define rlp_ctx (mem.rlp_ctx)
#define tx_ctx (mem.tx_ctx)
#define mp_ctx (mem.mp_ctx)
#define block (mem.block)
#define aux_bc_st (mem.aux_bc_st)
#define ReceiptHash (mem.ReceiptHash_ctx)

#endif
