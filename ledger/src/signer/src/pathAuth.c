/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   Hardcoded path authorization
 ********************************************************************************/

#include <string.h>
#include <stdbool.h>
#include "pathAuth.h"

/* Paths that require authorization
    m/44'/0'/0'/0/0 (BTC)
    m/44'/1'/0'/0/0 (tBTC)
*/
const char authPaths[][21] = {
    "\x05\x2c\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00", // BTC
    "\x05\x2c\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00"  // tBTC
};

/* Paths that don't require authorization
    m/44'/137'/0'/0/0 (RSK)
    m/44'/137'/1'/0/0 (MST)
    m/44'/137'/0'/0/1 (deprecated MST)
    m/44'/1'/1'/0/0 (tRSK)
    m/44'/1'/0'/0/1 (deprecated tRSK)
    m/44'/1'/2'/0/0 (tMST)
    m/44'/1'/0'/0/2 (deprecated tMST)
*/
const char noAuthPaths[][21] = {
    "\x05\x2c\x00\x00\x80\x89\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00", // RSK
    "\x05\x2c\x00\x00\x80\x89\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00", // MST
    "\x05\x2c\x00\x00\x80\x89\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00", // deprecated MST
    "\x05\x2c\x00\x00\x80\x01\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00", // tRSK
    "\x05\x2c\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x01\x00\x00\x00", // deprecated tRSK
    "\x05\x2c\x00\x00\x80\x01\x00\x00\x80\x02\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00", // tMST
    "\x05\x2c\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x02\x00\x00\x00"  // deprecated tMST
};

// Return true if the *path is inside the authPaths array, false otherwhise
// this means this path require authorization and validations.
bool pathRequireAuth(char *path) {
    char cmpbuf[sizeof(authPaths[0])];
    int i;
    for (i = 0; i < sizeof(authPaths) / sizeof(authPaths[0]); i++) {
        // Dont memcmp flash to RAM
        memmove(cmpbuf, authPaths[i], sizeof(cmpbuf));
        if (!memcmp(path, cmpbuf, sizeof(cmpbuf)))
            return true;
    }
    return false;
}

// Return true if the *path is inside the noAuthPaths array, false otherwhise
// This means this path can be used to sign any hash, and does not require
// authorization
bool pathDontRequireAuth(char *path) {
    char cmpbuf[sizeof(noAuthPaths[0])];
    int i;
    for (i = 0; i < sizeof(noAuthPaths) / sizeof(noAuthPaths[0]); i++) {
        // Dont memcmp flash to RAM
        memmove(cmpbuf, noAuthPaths[i], sizeof(cmpbuf));
        if (!memcmp(path, cmpbuf, sizeof(cmpbuf)))
            return true;
    }
    return false;
}
