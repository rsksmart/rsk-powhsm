/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 *
 *   Hashing functions
 ********************************************************************************/

#include "os_hash.h"
#include "os_exceptions.h"
#include "dbg.h"

int cx_sha256_init(cx_sha256_t *hash) {
    hash->header.algo = CX_ALGO_SHA256;
    sha256_init(&hash->ctx);
}

int cx_keccak_init(cx_sha3_t *hash, int size) {
    hash->header.algo = CX_ALGO_KECCAK256;
    keccak_init(&hash->ctx);
}

int cx_hash(cx_hash_t *hash,
            int mode,
            unsigned char *in,
            unsigned int len,
            unsigned char *out) {
    switch (hash->algo) {
    case CX_ALGO_SHA256:
        if (!out) {
            sha256_update(&((cx_sha256_t *)hash)->ctx, in, len);
        } else {
            sha256_final(&((cx_sha256_t *)hash)->ctx, out);
        }
        break;
    case CX_ALGO_KECCAK256:
        if (!out) {
            keccak_update(&((cx_sha3_t *)hash)->ctx, in, len);
        } else {
            keccak_final(&((cx_sha3_t *)hash)->ctx, out);
        }
        break;
    default:
        LOG("Invalid hash algorithm given to cx_hash: %d", hash->algo);
        THROW(0x9999); // TODO: define proper simulator-only error codes
    }
}
