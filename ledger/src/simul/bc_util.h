#ifndef __BC_UTIL
#define __BC_UTIL

/* Dump bytes from n in bigendian to the given buffer */
void dump_bigendian(uint8_t* buffer, size_t bytes, uint64_t n);

#endif
