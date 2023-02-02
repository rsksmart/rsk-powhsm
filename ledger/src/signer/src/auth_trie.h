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

#ifndef __AUTH_TRIE_H
#define __AUTH_TRIE_H

#include <stdint.h>

#include "trie.h"
#include "keccak256.h"
#include "defs.h"

#define AUTH_TRIE_STATE_NODE_LENGTH (0)
#define AUTH_TRIE_STATE_NODE (1)

#define AUTH_TRIE_NODE_VERSION (1)

typedef struct {
    uint8_t total_nodes;
    uint8_t current_node;
    uint8_t state;

    trie_ctx_t ctx;
    SHA3_CTX hash_ctx;
    SHA3_CTX aux_hash_ctx;

    uint8_t num_linked;
    uint8_t offset;
    union {
        uint8_t value_hash[HASH_LENGTH];
        uint8_t child_hash[HASH_LENGTH];
    };
    uint8_t node_hash[HASH_LENGTH];
} trie_auth_ctx_t;

/*
 * Implement the partial merkle trie parsing portion
 * of the signing authorization protocol.
 *
 * @arg[in] rx      number of received bytes from the host
 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign_handle_merkleproof(volatile unsigned int rx);

#endif // __AUTH_TRIE_H
