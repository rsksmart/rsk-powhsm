/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 ********************************************************************************/

#ifndef __SIMULATOR_OS
#define __SIMULATOR_OS

#include "os_hash.h"
#include "os_attestation.h"
#include "os_ecdsa.h"
#include "os_exceptions.h"
#include "os_io.h"

#include "hsmsim_explicit_bzero.h"

/**
 * Miscellaneous 
 */
#define PIC(x) (x)

void os_memmove(void *dst, const void *src, unsigned int length);

unsigned int os_perso_isonboarded();

void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len);

#endif // __SIMULATOR_OS