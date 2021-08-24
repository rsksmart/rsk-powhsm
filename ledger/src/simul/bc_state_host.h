#ifndef __BC_STATE_HOST
#define __BC_STATE_HOST

#include <stdint.h>

/*
 * Emulate a host interacting with a ledger via the
 * get blockchain state protocol.
 *
 * @arg[in] tx number of transmitted bytes
 * @ret number of bytes written to APDU buffer
 */
uint16_t bc_get_state_host(uint8_t tx);

/*
 * Emulate a host interacting with a ledger via the
 * reset blockchain state protocol.
 *
 * @arg[in] tx number of transmitted bytes
 * @ret number of bytes written to APDU buffer
 */
uint16_t bc_reset_state_host(uint8_t tx);

/*
 * Dump blockchain state.
 */
void dump_bc_state();

#endif
