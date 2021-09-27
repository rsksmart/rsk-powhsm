/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 *
 *   getrandom syscall wrapper
 ********************************************************************************/

#include <stddef.h>

void getrandom(void *buffer, size_t length, unsigned int flags);