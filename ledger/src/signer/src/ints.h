#ifndef __INTS
#define __INTS

// -----------------------------------------------------------------------
// Utility macros for integer manipulation.
// -----------------------------------------------------------------------

// Read an integer in big endian order from memory.
// Initializes the number to set to zero before reading.
//
// @arg buf buffer to read
// @arg n integer to be assigned with extracted number
//
// NOTE: Avoid buffer overflow: buffer length must be >= sizeof(n)
#define BIGENDIAN_FROM(buf, n) VAR_BIGENDIAN_FROM(buf, n, sizeof(n))

// Read an variable size integer in big endian order from memory.
// Initializes the number to set to zero before reading.
//
// @arg buf buffer to read
// @arg n integer to be assigned with extracted number
// @arg size number of bytes to read
//
// NOTE 1: Avoid lossy conversions: sizeof(n) must be >= size
// NOTE 2: Avoid buffer overflow: buffer length must be >= size
#define VAR_BIGENDIAN_FROM(buf, n, size)                \
    {                                                   \
        n = 0;                                          \
        for (unsigned int __i = 0; __i < size; __i++) { \
            n = (n << 8) | (buf)[__i];                  \
        }                                               \
    }

// Write a variable size integer in big endian order to memory.
//
// @arg buf buffer to write
// @arg n integer to be assigned with extracted number
// @arg size number of bytes to write
//
// NOTE 1: Avoid lossy conversions: sizeof(n) must be <= size
// NOTE 2: Avoid buffer overflow: buffer length must be >= size
#define VAR_BIGENDIAN_TO(buf, n, size)                         \
    {                                                          \
        memset(buf, 0, size);                                  \
        for (unsigned int __i = 0; __i < size; __i++) {        \
            (buf)[__i] = (n >> (8 * (size - __i - 1))) & 0xFF; \
        }                                                      \
    }

#endif
