/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 *
 *   ECDSA logic for private key keeping
 ********************************************************************************/

#ifndef __SIMULATOR_HSMSIM_ECDSA
#define __SIMULATOR_HSMSIM_ECDSA

#include <stdbool.h>

bool hsmsim_ecdsa_initialize(char* key_file_path);

bool hsmsim_ecdsa_get_key(unsigned char* path, unsigned char* dst_key);

#endif // __SIMULATOR_HSMSIM_ECDSA