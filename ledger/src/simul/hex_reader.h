#ifndef __HEX_READER
#define __HEX_READER

#include <stdint.h>

/*
 * Read bytes bytes from the text-based stream, decoding hex (2 bytes -> 1 byte)
 * Return the number of bytes actually read
 */
size_t read_hex(FILE* stream, void* dest, size_t bytes);

#endif
