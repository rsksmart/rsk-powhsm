/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 * 
 *   HSM simulator layer specific exceptions
 ********************************************************************************/

#ifndef __SIMULATOR_HSMSIM_EXCEPTIONS
#define __SIMULATOR_HSMSIM_EXCEPTIONS

#include <stdbool.h>
#include "os_exceptions.h"

/* ----------------------------------------------------------------------- */
/* -                 HSM SIMULATOR SPECIFIC EXCEPTIONS                   - */
/* ----------------------------------------------------------------------- */
#define HSMSIM_EXC_INVALID_PATH 0xbb01
#define HSMSIM_EXC_SECP_ERROR 0xbb02

#endif // __SIMULATOR_HSMSIM_EXCEPTIONS