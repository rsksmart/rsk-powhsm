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

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "hal/nvmem.h"

// Mocks and globals
struct {
    bool nvm_write_called;
    void *dst;
    void *src;
    unsigned int length;
} G_nvmem;

void nvm_write(void *dst, void *src, unsigned int src_len) {
    G_nvmem.nvm_write_called = true;
    G_nvmem.dst = dst;
    G_nvmem.src = src;
    G_nvmem.length = src_len;
}

void setup() {
    memset(&G_nvmem, 0, sizeof(G_nvmem));
}

void test_nvmem_write_ok() {
    printf("Testing nvmem_write succeeds...\n");
    setup();
    char dst[10], src[10] = "123456789";
    unsigned int len = sizeof(src);

    assert(nvmem_write(dst, src, len));

    assert(G_nvmem.nvm_write_called);
    assert(G_nvmem.dst == dst);
    assert(G_nvmem.src == src);
    assert(G_nvmem.length == len);
}

int main() {
    test_nvmem_write_ok();
    printf("All Ledger HAL nvmem tests passed!\n");
    return 0;
}
