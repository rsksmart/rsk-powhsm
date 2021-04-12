#ifndef __ATTESTATION
#define __ATTESTATION

#ifdef FEDHM_EMULATOR
#include "usb.h"
#endif

#include "bc_hash.h"
#include "mem.h"

// -----------------------------------------------------------------------
// Keys attestation
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// Protocol
// -----------------------------------------------------------------------

#define INS_ATTESTATION 0x50
#define OP_GET 0x01
#define OP_GET_MESSAGE 0x02
#define OP_APP_HASH 0x03

typedef enum {
    ATT_PROT_INVALID = 0x6b00, // Host not respecting protocol
    ATT_INTERNAL = 0x6b01, // Internal error while generating attestation
} err_code_attestation_t;

/*
 * Implement the attestation protocol.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @arg[in] att_ctx attestation context
 * @ret             number of transmited bytes to the host
 */
unsigned int get_attestation(volatile unsigned int rx, att_t* att_ctx);

#endif
