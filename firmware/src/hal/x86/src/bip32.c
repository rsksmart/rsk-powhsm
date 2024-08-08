#include "bip32.h"
#include "hal/constants.h"
#include "hal/log.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define BIP32_PREFIX "m/"
#define MIN_PATH_LENGTH (strlen("m/0/0/0/0/0"))
#define MAX_PART_DECIMAL_DIGITS 10
#define EXPECTED_PARTS BIP32_PATH_NUMPARTS

#ifdef DEBUG_BIP32
#define DEBUG_LOG(...) LOG(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

size_t bip32_parse_path(const char* path, uint8_t* out) {
    size_t pos, start, pathlen;
    int parts;
    int index;
    bool number;
    char indexstr[MAX_PART_DECIMAL_DIGITS + 1];
    uint32_t indexint;

    if (strlen(path) < MIN_PATH_LENGTH) {
        DEBUG_LOG("BIP32 path too short: %s\n", path);
        return 0;
    }

    if (strncmp(path, BIP32_PREFIX, strlen(BIP32_PREFIX))) {
        DEBUG_LOG("Bad prefix for path: %s\n", path);
        return 0;
    }

    parts = 0;
    pathlen = strlen(path);
    pos = strlen(BIP32_PREFIX);
    start = pos;
    index = 0;
    number = true;
    while (pos < pathlen) {
        if (number && path[pos] >= '0' && path[pos] <= '9') {
            pos++;
            if (pos - start > MAX_PART_DECIMAL_DIGITS) {
                DEBUG_LOG("Path part %d too long for path: %s\n", parts, path);
                return 0;
            }
        } else if (number && path[pos] == '\'') {
            number = false;
            index = 0x80000000;
            pos++;
        } else if (path[pos] != '/') {
            DEBUG_LOG(
                "Unexpected path character: %c for path %s\n", path[pos], path);
            return 0;
        }

        if (pos == pathlen || path[pos] == '/') {
            // Compute the index
            memcpy(indexstr, path + start, pos - start);
            indexstr[pos - start] = '\0';
            indexint = (uint32_t)atol(indexstr);
            if (indexint >= 0x80000000) {
                DEBUG_LOG("Path part %d needs to be between 0 and 2^31-1 for "
                          "path: %s\n",
                          parts,
                          path);
                return 0;
            }
            index += indexint;
            // Output the index in LE
            for (int i = 0; i < sizeof(uint32_t); i++) {
                out[1 + (parts * sizeof(uint32_t)) + i] =
                    (index >> (8 * i)) & 0xFF;
            }
            // Next!
            parts++;
            index = 0;
            number = true;
            start = ++pos;
            if (parts == EXPECTED_PARTS) {
                if (pos < pathlen) {
                    DEBUG_LOG("Path has too many parts: %s\n", path);
                    return 0;
                }
                out[0] = (char)parts;
                return 1 + parts * sizeof(uint32_t);
            }
        }
    }

    DEBUG_LOG("Unexpected code path reached for path: %s\n", path);
    return 0;
}
