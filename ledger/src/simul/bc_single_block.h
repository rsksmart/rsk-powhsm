#ifndef __BC_SINGLE_BLOCK
#define __BC_SINGLE_BLOCK

#include <stdint.h>

/*
 * Setup single block validation host.
 *
 * @arg[in] block_file file that contains the block information
 */
void setup_bc_single_block(char* block_file);

/*
 * Emulate a host interacting w/a ledger via the advance blockchain protocol
 * sending a single block.
 *
 * @ret number of bytes written to APDU buffer
 */
uint16_t bc_single_block();

#endif
