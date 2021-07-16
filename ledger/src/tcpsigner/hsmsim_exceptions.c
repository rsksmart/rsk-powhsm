/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 * 
 *   HSM simulator layer specific exceptions
 ********************************************************************************/

#include "hsmsim_exceptions.h"

bool is_hsmsim_exception(exception_t e) {
    return e >= HSMSIM_EXC_BASE;
}
