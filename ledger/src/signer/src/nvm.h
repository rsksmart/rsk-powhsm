#ifndef __NVM
#define __NVM

// -----------------------------------------------------------------------
// Portable non-volatile memory access.
// -----------------------------------------------------------------------

#ifdef FEDHM_EMULATOR
#include <stddef.h>
#include <string.h>

// Emulator: non-volatile reset/write reduces to memset/memcpy
#define NVM_RESET(dst, size) memset((void*)(dst), 0, size)
#define NVM_WRITE(dst, src, size) memcpy((void*)(dst), (void*)(src), size)

#else

// Ledger: use Nano SDK nvm_write function
#include "os.h"
#define NVM_RESET(dst, size) nvm_write((void*)(dst), NULL, size)
#define NVM_WRITE(dst, src, size) nvm_write((void*)(dst), (void*)(src), size)
#endif

#endif
