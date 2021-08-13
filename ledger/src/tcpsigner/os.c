/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 ********************************************************************************/

#include <string.h>

#include "os.h"

void os_memmove(void *dst, const void *src, unsigned int length) {
    memmove(dst, src, length);
}

#define OS_PERSO_ISONBOARDED_YES 1

unsigned int os_perso_isonboarded() {
    return OS_PERSO_ISONBOARDED_YES;
}

void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len) {
    if (src_adr == NULL) {
        // Treat as memory reset
        memset(dst_adr, 0, src_len);
    } else {
        // Treat as normal copy
        memmove(dst_adr, src_adr, src_len);
    }
}