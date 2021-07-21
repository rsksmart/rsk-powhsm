#ifndef __HASH
#define __HASH

#include <string.h>
#include "bc.h"

// -----------------------------------------------------------------------
// Portable SHA256 and Keccak256 hashing.
// The goal of this file is to abstract out hashing implementation,
// which will depend on the environment where bulk PoW validation is
// executed. Environments can be:
//
//  - Development simulator: use sha256.h and sha256.c
//  - Speculos: use BOLOS_SDK, version 1.5
//  - Ledger (the real thing): use BOLOS_SDK, version 1.3
// -----------------------------------------------------------------------

#if FEDHM_EMULATOR

#include "sha256.h"
#include "keccak256.h"

typedef SHA256_CTX sha256_ctx_t;

#define SHA256_INIT(ctx) sha256_init(ctx)
#define SHA256_UPDATE(ctx, data, len) sha256_update(ctx, data, len)
#define SHA256_FINAL(ctx, hash) sha256_final(ctx, hash)

typedef SHA3_CTX keccak_ctx_t;

#define KECCAK_INIT(ctx) keccak_init(ctx)
#define KECCAK_UPDATE(ctx, data, len) keccak_update(ctx, data, len)
#define KECCAK_FINAL(ctx, hash) keccak_final(ctx, hash)

#else

#include "bolos_target.h"
#include "os.h"

typedef cx_sha256_t sha256_ctx_t;
typedef cx_sha3_t keccak_ctx_t;

#if TARGET_ID == 0x31100002 // SDK 1.3

#define SHA256_INIT(ctx) cx_sha256_init(ctx)
#define SHA256_UPDATE(ctx, data, len) \
    cx_hash((cx_hash_t*)(ctx), 0, data, len, NULL)
#define SHA256_FINAL(ctx, hash) \
    cx_hash((cx_hash_t*)(ctx), CX_LAST, NULL, 0, hash)

#define KECCAK_INIT(ctx) cx_keccak_init(ctx, 256)
#define KECCAK_UPDATE(ctx, data, len) \
    cx_hash((cx_hash_t*)(ctx), 0, (uint8_t*)data, len, NULL)
#define KECCAK_FINAL(ctx, hash) \
    cx_hash((cx_hash_t*)(ctx), CX_LAST, NULL, 0, hash)

#elif TARGET_ID == 0x31100004 // SDK 1.5

#define SHA256_INIT(ctx) cx_sha256_init(ctx)
#define SHA256_UPDATE(ctx, data, len) cx_hash(ctx, 0, data, len, NULL, 0)
#define SHA256_FINAL(ctx, hash) cx_hash(ctx, CX_LAST, NULL, 0, hash, HASH_SIZE)

#define KECCAK_INIT(ctx) cx_keccak_init(ctx, 256)
#define KECCAK_UPDATE(ctx, data, len) \
    cx_hash((cx_hash_t*)(ctx), 0, data, len, NULL, 0)
#define KECCAK_FINAL(ctx, hash) \
    cx_hash((cx_hash_t*)(ctx), CX_LAST, NULL, 0, hash, HASH_SIZE)

#else
#error "Unrecognized SDK"
#endif // TARGET_ID

#endif // FEDHM_EULATOR

// Convenience macros to deal with frequent hash ops
#define HEQ(h0, h1) (memcmp(h0, h1, HASH_SIZE) == 0)
#define HNEQ(h0, h1) (memcmp(h0, h1, HASH_SIZE) != 0)
#define HSTORE(dst, src) (memcpy(dst, src, HASH_SIZE))

// Revert hash in place
#define REV_HASH(hash)                                            \
    {                                                             \
        for (unsigned char __i = 0; __i < HASH_SIZE / 2; __i++) { \
            unsigned char __tmp = (hash)[__i];                    \
            (hash)[__i] = (hash)[HASH_SIZE - __i - 1];            \
            (hash)[HASH_SIZE - __i - 1] = __tmp;                  \
        }                                                         \
    }

/*
 * Compute a double sha256 and a final reversal.
 *
 * @arg[in]  ctx  sha256 context
 * @arg[in]  data pointer tobytes to double hash and reverse
 * @arg[in]  len  length of data to hash in bytes
 * @arg[out] hash 32-byte buffer where hash will be stored
 */
void double_sha256_rev(sha256_ctx_t* ctx,
                       uint8_t* data,
                       size_t len,
                       uint8_t* hash);

/*
 * Perform one step of the Merkle proof validation. The result
 * of the hash step will be stored in `left`, thus clobbering
 * `left`'s input value.
 *
 * @arg[in]     ctx s ha256 context
 * @arg[in/out] left  pointer to left hash, result will be stored here
 * @arg[in]     right pointer to right hash
 */
void fold_left(sha256_ctx_t* ctx, uint8_t* left, uint8_t* right);

#endif
