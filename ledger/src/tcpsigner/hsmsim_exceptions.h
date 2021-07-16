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
bool is_hsmsim_exception(exception_t e);

#define HSMSIM_EXC_BASE 0xbb00

#define HSMSIM_EXC_SOCKET 0xbb01
#define HSMSIM_EXC_INVALID_PATH 0xbb02
#define HSMSIM_EXC_SECP_ERROR 0xbb03

#endif // __SIMULATOR_HSMSIM_EXCEPTIONS