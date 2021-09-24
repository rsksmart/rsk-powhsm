/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 *
 *   getrandom syscall wrapper
 ********************************************************************************/

#include "hsmsim_random.h"

#include <stddef.h>
#include <unistd.h>
#include <syscall.h>

void getrandom(void *buffer, size_t length, unsigned int flags) {
    syscall(SYS_getrandom, buffer, length, 0);
}