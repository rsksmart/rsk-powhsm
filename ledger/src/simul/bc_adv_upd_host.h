#ifndef __BC_ADV_UPD_HOST
#define __BC_ADV_UPD_HOST

#include <stdbool.h>
#include <stdint.h>

/*
 * Setup blockchain advance protocol host.
 *
 * @arg[in] num_splits number of block splits to process
 * @arg[in] should_upd_ancestor whether to update ancestor after advancing
 */
void setup_bc_advance_host(int num_splits, bool should_upd_ancestor);

/*
 * Emulate a host interacting w/ a ledger via the advance blockchain protocol.
 *
 * @ret number of bytes written to APDU buffer
 */
uint16_t bc_advance_host();

/*
 * Emulate a host interacting w/ a ledger via the update ancestor protocol.
 *
 * @ret number of bytes written to APDU buffer
 */
uint16_t bc_upd_ancestor_host();

#endif
