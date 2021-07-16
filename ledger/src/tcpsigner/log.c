/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 * 
 *   Generic logging to screen functions
 ********************************************************************************/

#include <stddef.h>
#include <stdarg.h>

#include "log.h"
#include "dbg.h"

#define PREFIX "[TCPSIGNER] "

void info(const char *format, ...) {
    va_list args;
    va_start(args, format);

    LOG(PREFIX);    
    vprintf(format, args);

    va_end(args);
}

void info_hex(const char *prefix, void *buffer, size_t size) {
    LOG(PREFIX);
    LOG_HEX(prefix, buffer, size);
}
