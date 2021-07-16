#ifndef __HEX_READER
#define __HEX_READER

#include <stdint.h>

/*
 * Read src_length hex bytes from the src string
 * Return the number of bytes actually read or
 * -1 in case of error
 */
int read_hex(char* src, size_t src_length, void* dest);

#endif
