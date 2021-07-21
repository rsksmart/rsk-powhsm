#ifndef __BC_ANCESTOR
#define __BC_ANCESTOR

/*
 * Blockchain update ancestor protocol definitions. These messages
 * define the protocol for updating the ancestor block.
 */

// Command code for advancing blockchain
#define INS_UPD_ANCESTOR 0x30

// Operations for advancing blockchain protocol
#define OP_UPD_ANCESTOR_IDLE 0x01
#define OP_UPD_ANCESTOR_INIT 0x02
#define OP_UPD_ANCESTOR_HEADER_META 0x03
#define OP_UPD_ANCESTOR_HEADER_CHUNK 0x04
#define OP_UPD_ANCESTOR_SUCCESS 0x05

/*
 * Initialize Blockchain update ancestor protocol state.
 */
void bc_init_upd_ancestor();

/*
 * Update blockchain ancestor.
 *
 * @arg[in] rx number of received bytes from the Host
 * @ret     number of transmited bytes to the host
 */
unsigned int bc_upd_ancestor(volatile unsigned int rx);

#endif
