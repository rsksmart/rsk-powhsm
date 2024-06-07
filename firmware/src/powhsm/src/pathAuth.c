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

#include <string.h>
#include <stdbool.h>
#include "memutil.h"
#include "pathAuth.h"

/* Paths that require authorization
    m/44'/0'/0'/0/0 (BTC)
    m/44'/1'/0'/0/0 (tBTC)
*/
const char authPaths[][SINGLE_PATH_SIZE_BYTES] = {
    "\x05\x2c\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00"
    "\x00\x00\x00", // BTC
    "\x05\x2c\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00"
    "\x00\x00\x00" // tBTC
};

/* Paths that don't require authorization
    m/44'/137'/0'/0/0 (RSK)
    m/44'/137'/1'/0/0 (MST)
    m/44'/1'/1'/0/0 (tRSK)
    m/44'/1'/2'/0/0 (tMST)
*/
const char noAuthPaths[][SINGLE_PATH_SIZE_BYTES] = {
    "\x05\x2c\x00\x00\x80\x89\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00"
    "\x00\x00\x00", // RSK
    "\x05\x2c\x00\x00\x80\x89\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x00\x00"
    "\x00\x00\x00", // MST
    "\x05\x2c\x00\x00\x80\x01\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x00\x00"
    "\x00\x00\x00", // tRSK
    "\x05\x2c\x00\x00\x80\x01\x00\x00\x80\x02\x00\x00\x80\x00\x00\x00\x00\x00"
    "\x00\x00\x00", // tMST
};

// Derivation-path-lexicographically (and statically) ordered binary paths
// These need to be updated if paths change
// Each element indexes paths on the above arrays as follows:
// Most significant byte indicates authPaths (0) or noAuthPaths (1)
// Least significant byte indicates index on the array in question
const int ordered_paths[TOTAL_AUTHORIZED_PATHS] = {
    0x0000, // BTC
    0x0001, // tBTC
    0x0102, // tRSK
    0x0103, // tMST
    0x0100, // RSK
    0x0101, // MST
};

// Return true if the *path is inside the authPaths array, false otherwhise
// this means this path require authorization and validations.
bool pathRequireAuth(unsigned char *path) {
    char cmpbuf[sizeof(authPaths[0])];
    for (unsigned int i = 0; i < sizeof(authPaths) / sizeof(authPaths[0]);
         i++) {
        // Dont memcmp flash to RAM
        SAFE_MEMMOVE(cmpbuf,
                     sizeof(cmpbuf),
                     MEMMOVE_ZERO_OFFSET,
                     authPaths[i],
                     sizeof(authPaths[i]),
                     MEMMOVE_ZERO_OFFSET,
                     sizeof(cmpbuf),
                     { return false; });
        if (!memcmp(path, cmpbuf, sizeof(cmpbuf)))
            return true;
    }
    return false;
}

// Return true if the *path is inside the noAuthPaths array, false otherwhise
// This means this path can be used to sign any hash, and does not require
// authorization
bool pathDontRequireAuth(unsigned char *path) {
    char cmpbuf[sizeof(noAuthPaths[0])];
    for (unsigned int i = 0; i < sizeof(noAuthPaths) / sizeof(noAuthPaths[0]);
         i++) {
        // Dont memcmp flash to RAM
        SAFE_MEMMOVE(cmpbuf,
                     sizeof(cmpbuf),
                     MEMMOVE_ZERO_OFFSET,
                     noAuthPaths[i],
                     sizeof(noAuthPaths[i]),
                     MEMMOVE_ZERO_OFFSET,
                     sizeof(cmpbuf),
                     { return false; });
        if (!memcmp(path, cmpbuf, sizeof(cmpbuf)))
            return true;
    }
    return false;
}

const char *get_ordered_path(unsigned int index) {
    if (ordered_paths[index] & 0xFF00) {
        // No auth path
        return noAuthPaths[ordered_paths[index] & 0xFF];
    } else {
        // Auth path
        return authPaths[ordered_paths[index] & 0xFF];
    }
}
