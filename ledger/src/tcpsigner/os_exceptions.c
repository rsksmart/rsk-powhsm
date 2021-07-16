/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 *   Try...catch exception implementation (taken from nanos-secure-sdk)
 *   (https://github.com/LedgerHQ/nanos-secure-sdk/blob/nanos-1314/include/os.h)
 ********************************************************************************/

#include "os_exceptions.h"

static try_context_t G_try_last_open_context_var;

try_context_t* G_try_last_open_context = &G_try_last_open_context_var;