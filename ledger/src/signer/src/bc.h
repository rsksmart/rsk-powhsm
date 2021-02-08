#ifndef __BC
#define __BC

// -----------------------------------------------------------------------
// Constants referenced all around the code
// -----------------------------------------------------------------------

// Difficulty and BigInts
#define BIGINT_LEN 9
#define MAX_DIFFICULTY_SIZE 32

// Hashing
#define HASH_SIZE 32
#define KECCAK256_HASH_SIZE HASH_SIZE

// Merge mining constants
#define MM_HASH_PREFIX_SIZE 20
#define MM_HASH_SUFFIX_SIZE 4

// Coinbase transaction constants
#define CB_MAX_RSK_TAG_POSITION 64
#define CB_MAX_AFTER_MM_HASH 128
#define CB_MIN_TX_SIZE 64
#define CB_MIDSTATE_PREFIX 8
#define CB_MIDSTATE_DATA 40
#define CB_MIDSTATE_SUFFIX 4

// Field sizes and offsets
#define UMM_ROOT_SIZE 20
#define MAX_MERKLE_PROOF_SIZE 960
#define MAX_CB_TXN_SIZE 273
#define BTC_HEADER_SIZE 80
#define BTC_HEADER_RLP_LEN 82
#define MERKLE_ROOT_OFFSET 36

#endif