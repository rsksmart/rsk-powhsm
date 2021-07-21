#ifndef __DBG
#define __DBG

#ifdef FEDHM_EMULATOR

#include <stdio.h>
#include <stdlib.h>

#define LOG(...) fprintf(stderr, __VA_ARGS__);
void LOG_HEX(const char *name, unsigned char *hash, size_t size);

#else

#define LOG(...)
#define LOG_HEX(name, hash, size)

#endif

#endif