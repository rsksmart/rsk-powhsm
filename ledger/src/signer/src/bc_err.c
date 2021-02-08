#include "bc_err.h"

#ifdef FEDHM_EMULATOR
#include <stdio.h>

static struct err_entry {
    err_code_t errcode;
    char errmsg[128];
} err_table[] = {
    {UNKNOWN, "Unknown error"},
    {PROT_INVALID, "Invalid or unexpected message"},
    {RLP_INVALID, "Invalid RLP"},
    {BLOCK_TOO_OLD, "Block too old"},
    {BLOCK_TOO_SHORT, "Block too short"},
    {PARENT_HASH_INVALID, "Invalid parent hash"},
    {RECEIPT_ROOT_INVALID, "Invalid receipt root"},
    {BLOCK_NUM_INVALID, "Block number > 4 bytes"},
    {BLOCK_DIFF_INVALID, "Block difficulty zero or > 32 bytes"},
    {UMM_ROOT_INVALID, "Invalid UMM root"},
    {BTC_HEADER_INVALID, "Invalid BTC merge mining header"},
    {MERKLE_PROOF_INVALID, "Invalid Merkle proof"},
    {BTC_CB_TXN_INVALID, "Invalid coinbase transaction"},
    {MM_RLP_LEN_MISMATCH, "Merge mining RLP lengths don't match"},
    {BTC_DIFF_MISMATCH, "BTC merge mining header doesn't match block diff"},
    {MERKLE_PROOF_MISMATCH, "Merkle proof doesn't match merkle root"},
    {MM_HASH_MISMATCH, "Merge mining hashes don't match"},
    {MERKLE_PROOF_OVERFLOW, "Merkle proof exceeds maximum size"},
    {CB_TXN_OVERFLOW, "Coinbase transaction exceeds maximum size"},
    {CB_TXN_HASH_MISMATCH, "Coinbase transaction hash mismatch"},
    {BUFFER_OVERFLOW, "Work area buffer overflow"},

    {CHAIN_MISMATCH, "Block is not parent of previous block"},
    {TOTAL_DIFF_OVERFLOW, "Total difficulty overflow"},

    {ANCESTOR_TIP_MISMATCH, "Ancestor tip mismatch"},
};

void show_error(err_code_t errcode) {
    char *msg = err_table[0].errmsg;
    for (unsigned int i = 1; i < sizeof(err_table) / sizeof(struct err_entry);
         i++) {
        if (err_table[i].errcode == errcode) {
            msg = err_table[i].errmsg;
            break;
        }
    }
    fprintf(stderr, "*** ERROR: %s\n", msg);
}
#else
void show_error(err_code_t errcode) {
}
#endif
