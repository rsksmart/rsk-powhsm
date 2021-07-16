/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 * 
 *   Network-upgrade related functions
 ********************************************************************************/

#ifndef __SIMULATOR_NU
#define __SIMULATOR_NU

#include <stdint.h>

#include "bc_nu.h"

void hsmsim_set_network_upgrade(uint32_t block_number, uint8_t* dst_network_upgrade);

uint8_t hsmsim_get_network_identifier();

const char* get_network_name(uint8_t netid);

uint8_t get_network_identifier_by_name(char* name);

bool hsmsim_set_network(uint8_t netid);

#endif // __SIMULATOR_NU