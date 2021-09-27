/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 *
 *   Hashing functions
 ********************************************************************************/

#ifndef __SIMULATOR_OS_HASHING
#define __SIMULATOR_OS_HASHING

#include "sha256.h"
#include "keccak256.h"

typedef enum { CX_ALGO_SHA256 = 0x01, CX_ALGO_KECCAK256 } cx_algo_t;

typedef struct cx_hash_header_s {
    cx_algo_t algo;
} cx_hash_t;

typedef struct cx_sha256_s {
    cx_hash_t header;
    SHA256_CTX ctx;
} cx_sha256_t;

typedef struct cx_sha3_s {
    cx_hash_t header;
    SHA3_CTX ctx;
} cx_sha3_t;

int cx_sha256_init(cx_sha256_t *hash);

int cx_keccak_init(cx_sha3_t *hash, int size);

int cx_hash(cx_hash_t *hash,
            int mode,
            unsigned char *in,
            unsigned int len,
            unsigned char *out);

#endif // __SIMULATOR_OS_HASHING