#ifndef __DBG
#define __DBG

#ifdef HSM_SIMULATOR

#include <stdio.h>
#include <stdlib.h>

#include "bigdigits.h"
#include "srlp.h"

#define LOG(...) printf(__VA_ARGS__);

/** Print buffer in hex format with prefix */
void LOG_HEX(const char *prefix, void *buffer, size_t size);

/** Print big integer in hex format with optional prefix and suffix strings */
void LOG_BIGD_HEX(const char *prefix, const DIGIT_T *a, size_t len, const char *suffix);

/** Print N copies of a given char */
void LOG_N_CHARS(const char c, unsigned int times);

/** Print the given SRLP context (see srlp.h) */
void LOG_SRLP_CTX(rlp_ctx_t ctx[], uint8_t ptr);

#else

#define LOG(...)
#define LOG_HEX(...)
#define LOG_BIGD_HEX(...)
#define LOG_N_CHARS(...)
#define LOG_SRLP_CTX(...)

#endif

#endif