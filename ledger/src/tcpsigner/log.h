/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 *
 *   Generic logging to screen functions
 ********************************************************************************/

#ifndef __SIMULATOR_LOG
#define __SIMULATOR_LOG

void info(const char *format, ...);
void info_hex(const char *prefix, void *buffer, size_t size);

#endif // __SIMULATOR_LOG