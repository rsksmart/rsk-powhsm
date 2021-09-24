/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 *
 *   Endorsement (attestation) functions
 ********************************************************************************/

#include "os_attestation.h"

// XXX: We are returning zero out of pure hope, as we do not know exactly what
// these functions return.
// XXX:
// https://github.com/LedgerHQ/ledger-nanos-sdk/blob/master/nanos-secure-sdk/include/os_endorsement.h#L25

unsigned int os_endorsement_key2_derive_sign_data(unsigned char *src,
                                                  unsigned int srcLength,
                                                  unsigned char *signature) {
    return 0;
}

unsigned int os_endorsement_get_code_hash(unsigned char *buffer) {
    return 0;
}
