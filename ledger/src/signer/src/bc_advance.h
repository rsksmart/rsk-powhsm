#ifndef __BC_ADVANCE
#define __BC_ADVANCE

/*
 * Blockchain advance protocol definitions. These messages
 * define the protocol for advancing a blockchain over a
 * bunch of blocks.
 */

// Command code for advancing blockchain
#define INS_ADVANCE 0x10

// Command code for reading the advance blockchain precompiled parameters
#define INS_ADVANCE_PARAMS 0x11

// Operations for advancing blockchain protocol
#define OP_ADVANCE_INIT 0x02
#define OP_ADVANCE_HEADER_META 0x03
#define OP_ADVANCE_HEADER_CHUNK 0x04
#define OP_ADVANCE_PARTIAL 0x05
#define OP_ADVANCE_SUCCESS 0x06

#ifndef PARAM_MIN_REQUIRED_DIFFICULTY
#include "bc.h"
#include "bigdigits.h"
extern DIGIT_T MIN_REQUIRED_DIFFICULTY[BIGINT_LEN];
#endif

/*
 * Initialize Blockchain advance protocol state.
 */
void bc_init_advance();

/*
 * Advance blockchain state.
 *
 * @arg[in] rx number of received bytes from the Host
 * @ret     number of transmited bytes to the host
 */
unsigned int bc_advance(volatile unsigned int rx);

/*
 * Get advance blockchain protocol precompiled parameters.
 *
 * @ret number of transmited bytes to the host
 */
unsigned int bc_advance_get_params();

#endif
