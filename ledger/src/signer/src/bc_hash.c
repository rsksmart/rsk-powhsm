#include "bc.h"
#include "bc_hash.h"

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
                       uint8_t* hash) {
    SHA256_INIT(ctx);
    SHA256_UPDATE(ctx, data, len);
    SHA256_FINAL(ctx, hash);
    SHA256_INIT(ctx);
    SHA256_UPDATE(ctx, hash, HASH_SIZE);
    SHA256_FINAL(ctx, hash);
    REV_HASH(hash);
}

/*
 * Perform one step of the Merkle proof validation. The result
 * of the hash step will be stored in `left`, thus clobbering
 * `left`'s input value.
 *
 * @arg[in]     ctx s ha256 context
 * @arg[in/out] left  pointer to left hash, result will be stored here
 * @arg[in]     right pointer to right hash
 */
void fold_left(sha256_ctx_t* ctx, uint8_t* left, uint8_t* right) {
    REV_HASH(left);
    REV_HASH(right);
    SHA256_INIT(ctx);
    SHA256_UPDATE(ctx, left, HASH_SIZE);
    SHA256_UPDATE(ctx, right, HASH_SIZE);
    SHA256_FINAL(ctx, left);
    SHA256_INIT(ctx);
    SHA256_UPDATE(ctx, left, HASH_SIZE);
    SHA256_FINAL(ctx, left);
    REV_HASH(left);
}
