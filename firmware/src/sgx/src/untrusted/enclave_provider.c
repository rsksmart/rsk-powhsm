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


#include <unistd.h>

#include "hsm_u.h"
#include "enclave_provider.h"
#include "log.h"

// Global pointer to the enclave. This should be the only global pointer to the enclave
static char* G_enclave_path = NULL;
static oe_enclave_t* G_enclave = NULL;

bool ep_init(char* enclave_path) {
    G_enclave_path = enclave_path;
    if (access(G_enclave_path, F_OK) != 0) {
        LOG("Invalid enclave path given: %s\n", G_enclave_path);
        return false;
    }
    return true;
}

oe_enclave_t* ep_get_enclave() {
    if (NULL == G_enclave) {
        oe_enclave_t *enclave = NULL;
        LOG("Creating HSM enclave...\n");
        oe_result_t result = oe_create_hsm_enclave(G_enclave_path,
                                                   OE_ENCLAVE_TYPE_AUTO,
                                                   0, NULL, 0, &enclave);
        if (OE_OK != result) {
            LOG("Failed to create enclave: oe_result=%u (%s)\n", result, oe_result_str(result));
            return NULL;
        }

        LOG("HSM enclave created\n");
        G_enclave = enclave;
    }

    return G_enclave;
}

void ep_finalize_enclave() {
    if (NULL != G_enclave) {
        oe_terminate_enclave(G_enclave);
        LOG("HSM enclave terminated\n");
        G_enclave = NULL;
    }
}
