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

#include "hal/nvmem.h"
#include "hal/log.h"

#include <stdbool.h>
#include <string.h>

static nvmmem_stats_t nvmmem_stats;

void nvmem_stats_reset() {
    memset(&nvmmem_stats, 0, sizeof(nvmmem_stats));
    LOG("NVM stats reset OK.\n");
}

nvmmem_stats_t nvmem_get_stats() {
    return nvmmem_stats;
}

bool nvmem_write(void *dst, void *src, unsigned int length) {
    if (src == NULL) {
        // Treat as memory reset
        memset(dst, 0, length);
    } else {
        // Treat as normal copy
        memmove(dst, src, length);
    }
    // Log the write
    nvmmem_stats.write_count++;
}