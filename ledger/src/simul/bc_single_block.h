#ifndef __BC_SINGLE_BLOCK
#define __BC_SINGLE_BLOCK

#include <stdint.h>

/*
 * Setup single block validation host.
 *
 * @arg[in] block_file file that contains the block information
 * @arg[in] update_ancestor whether to setup advance blockchain or update ancestor
 */
void setup_bc_single_block(char* block_file, bool update_ancestor);

/*
 * Emulate a host interacting w/a ledger via the advance blockchain protocol
 * sending a single block.
 *
 * @arg[in] update_ancestor whether to setup advance blockchain or update ancestor
 * @ret number of bytes written to APDU buffer
 */
uint16_t bc_single_block(bool update_ancestor);

#endif
