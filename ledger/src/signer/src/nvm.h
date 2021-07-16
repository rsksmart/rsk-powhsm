#ifndef __NVM
#define __NVM

// -----------------------------------------------------------------------
// Portable non-volatile memory access.
// -----------------------------------------------------------------------

#include "os.h"
#define NVM_RESET(dst, size) nvm_write((void*)(dst), NULL, size)
#define NVM_WRITE(dst, src, size) nvm_write((void*)(dst), (void*)(src), size)
#endif
