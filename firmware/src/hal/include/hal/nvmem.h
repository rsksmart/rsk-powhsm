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

#ifndef __HAL_NVMEM_H
#define __HAL_NVMEM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Write to non volatile memory
 *
 * @param dst The destination address in (non volatile) memory
 * @param src The source address to write from
 * @param length The amount of bytes to write
 *
 * @returns whether the write succeeded
 */
bool nvmem_write(void *dst, void *src, unsigned int length);

// BEGINNING of platform-dependent code
#if defined(HSM_PLATFORM_X86)

typedef struct nvmmem_stats_s {
    unsigned int write_count;
} nvmmem_stats_t;

/**
 * @brief Resets the non volatile memory statistics
 */
void nvmem_stats_reset();

/**
 * @brief Returns the current non volatile memory statistics
 *
 * @returns the statistics
 */
nvmmem_stats_t nvmem_get_stats();

#elif defined(HSM_PLATFORM_SGX)

/**
 * @brief Initializes the nvmem module
 */
void nvmem_init();

/**
 * @brief Registers a memory block as non volatile
 *
 * @param key a string key to uniquely identify the block
 * @param addr the base address of the block
 * @param size the size of the block in bytes
 *
 * @return whether the block was successfully registered
 */
bool nvmem_register_block(char* key, void* addr, size_t size);

/**
 * @brief Loads registered blocks into memory
 *
 * @returns whether loading was successful
 */
bool nvmem_load();

#endif
// END of platform-dependent code

#endif // __HAL_NVMEM_H