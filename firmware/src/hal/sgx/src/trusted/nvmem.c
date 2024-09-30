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

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "hal/nvmem.h"
#include "hal/log.h"

#include "secret_store.h"

#define MAX_NVM_BLOCKS 5

typedef struct {
    char* key;
    void* addr;
    uint8_t size;
} nvm_block_t;

static nvm_block_t nvm_blocks[MAX_NVM_BLOCKS];
static unsigned int nvm_blocks_count;

#define STORE_PREFIX "nvmem-"

static char* store_key_for(char* key) {
    size_t key_size = strlen(STORE_PREFIX) + strlen(key);
    char* store_key = malloc(key_size + 1);
    strcpy(store_key, "");
    strcat(store_key, STORE_PREFIX);
    strcat(store_key, key);
    return store_key;
}

void nvmem_init() {
    memset(nvm_blocks, 0, sizeof(nvm_blocks));
    nvm_blocks_count = 0;
}

bool nvmem_register_block(char* key, void* addr, uint8_t size) {
    if (nvm_blocks_count >= MAX_NVM_BLOCKS) {
        LOG("Error registering NVM block <%s>: too many blocks\n", key);
        return false;
    }

    nvm_blocks[nvm_blocks_count].key = key;
    nvm_blocks[nvm_blocks_count].addr = addr;
    nvm_blocks[nvm_blocks_count].size = size;
    nvm_blocks_count++;

    return true;
}

static void clear_blocks() {
    for (unsigned int i = 0; i < nvm_blocks_count; i++) {
        memset((uint8_t*)nvm_blocks[i].addr, 0, nvm_blocks[i].size);
    }
}

bool nvmem_load() {
    LOG("Loading NVM blocks...\n");
    for (unsigned int i = 0; i < nvm_blocks_count; i++) {
        char* key = store_key_for(nvm_blocks[i].key);
        if (sest_exists(key)) {
            uint8_t* tmp = malloc(nvm_blocks[i].size);
            if (sest_read(key, tmp, nvm_blocks[i].size) == nvm_blocks[i].size) {
                memcpy((uint8_t*)nvm_blocks[i].addr, tmp, nvm_blocks[i].size);
            } else {
                LOG("Error loading NVM block <%s>\n", nvm_blocks[i].key);
                clear_blocks();
                free(key);
                return false;
            }
            free(tmp);
        } else {
            LOG("No record found for NVM block <%s>\n", nvm_blocks[i].key);
            memset((uint8_t*)nvm_blocks[i].addr, 0, nvm_blocks[i].size);
        }
        free(key);
    }
    return true;
}

static bool nvmem_flush() {
    LOG("Flushing NVM blocks...\n");
    for (unsigned int i = 0; i < nvm_blocks_count; i++) {
        char* key = store_key_for(nvm_blocks[i].key);
        if (!sest_write(
                key, (uint8_t*)nvm_blocks[i].addr, nvm_blocks[i].size)) {
            LOG("Error flushing NVM block <%s>\n", nvm_blocks[i].key);
            free(key);
            return false;
        }
        free(key);
    }
    return true;
}

bool nvmem_write(void* dst, void* src, unsigned int length) {
    if (src == NULL) {
        // Treat as memory reset
        memset(dst, 0, length);
    } else {
        // Treat as normal copy
        memmove(dst, src, length);
    }
    // Flush to disk
    return nvmem_flush();
}