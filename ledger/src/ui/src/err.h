#ifndef __ERR
#define __ERR

// Error codes for RSK operations
typedef enum {
    PROT_INVALID = 0x6a01, // Ledger got invalid or unexpected message
    CA_MISMATCH  = 0x6a02, // Public key doesn't match the device's custom CA public key
} err_code_rsk_t;

#endif