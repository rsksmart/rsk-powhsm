/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2021 RSK Labs Ltd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef __HAL_HASH_H
#define __HAL_HASH_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define HASH_SIZE 32

// BEGINNING of platform-dependent code
#if defined(HSM_PLATFORM_LEDGER)

#include "os.h"
#include "sha256.h"

typedef cx_sha256_t hash_sha256_ctx_t;
typedef cx_sha3_t hash_keccak256_ctx_t;
typedef SHA256_CTX hash_sha256_ms_ctx_t;

#elif defined(HSM_PLATFORM_X86)

#include "sha256.h"
#include "keccak256.h"

typedef SHA256_CTX hash_sha256_ctx_t;
typedef SHA3_CTX hash_keccak256_ctx_t;
typedef SHA256_CTX hash_sha256_ms_ctx_t;

#else
    #error "HSM Platform undefined"
#endif
// END of platform-dependent code

// *** sha256 ***

/**
 * @brief Initialize a sha256 hash context
 * 
 * @param[inout] ctx the context to initialize
 * 
 * @returns whether the initialisation succeeded
 */
bool hash_sha256_init(hash_sha256_ctx_t* ctx);

/**
 * @brief Update a sha256 hash context with given data
 * 
 * @param[inout] ctx the context to update
 * @param[in] data  pointer to message to hash
 * @param[in] len   length of message in bytes
 *
 * @returns whether the update succeeded
 */
bool hash_sha256_update(hash_sha256_ctx_t* ctx, const uint8_t *data, size_t len);

/**
 * @brief Compute the final sha256 hash for the given context
 * 
 * @param[inout] ctx the context to finalise
 * @param[out] out_hash The final hash obtained from the incremental hash
 * 
 * @returns whether the finalisation succeeded
 */
bool hash_sha256_final(hash_sha256_ctx_t* ctx, uint8_t *out_hash);

// *** sha256 with midstate support ***

/**
 * @brief Initialize a sha256 ms hash context
 * 
 * @param[inout] ctx the context to initialize
 * 
 * @returns whether the initialisation succeeded
 */
bool hash_sha256_ms_init(hash_sha256_ms_ctx_t* ctx);

/**
 * @brief Set sha256 ms hash context to the given mid state
 *
 * @details
 * Mid state must be 52 bytes long:
 *   - midstate[0:8]: ignore
 *   - midstate[8:16]: counter, as a big-endian uint64_t
 *   - midstate[16:48]: current hash, as 8 big-endian uint32_t integers
 *   - midstate[48:52]: ignore
 * 
 * @param[inout] ctx the context to set
 * @param[in] midstate  pointer to midstate buffer
 *
 * @returns whether the midstate succeeded
 */
bool hash_sha256_ms_midstate(hash_sha256_ms_ctx_t* ctx, uint8_t *midstate);

/**
 * @brief Update a sha256 ms hash context with given data
 * 
 * @param[inout] ctx the context to update
 * @param[in] data  pointer to message to hash
 * @param[in] len   length of message in bytes
 *
 * @returns whether the update succeeded
 */
bool hash_sha256_ms_update(hash_sha256_ms_ctx_t* ctx, const uint8_t *data, size_t len);

/**
 * @brief Compute the final sha256 ms hash for the given context
 * 
 * @param[inout] ctx the context to finalise
 * @param[out] out_hash The final hash obtained from the incremental hash
 * 
 * @returns whether the finalisation succeeded
 */
bool hash_sha256_ms_final(hash_sha256_ms_ctx_t* ctx, uint8_t *out_hash);

// *** keccak256 ***

/**
 * @brief Initialize a keccak256 hash context
 * 
 * @param[inout] ctx the context to initialize
 * 
 * @returns whether the initialisation succeeded
 */
bool hash_keccak256_init(hash_keccak256_ctx_t* ctx);

/**
 * @brief Update a keccak256 hash context with given data
 * 
 * @param[inout] ctx the context to update
 * @param[in] data  pointer to message to hash
 * @param[in] len   length of message in bytes
 *
 * @returns whether the update succeeded
 */
bool hash_keccak256_update(hash_keccak256_ctx_t* ctx, const uint8_t *data, size_t len);

/**
 * @brief Compute the final keccak256 hash for the given context
 * 
 * @param[inout] ctx the context to finalise
 * @param[out] out_hash The final hash obtained from the incremental hash
 * 
 * @returns whether the finalisation succeeded
 */
bool hash_keccak256_final(hash_keccak256_ctx_t* ctx, uint8_t *out_hash);

#endif // __HAL_HASH_H
