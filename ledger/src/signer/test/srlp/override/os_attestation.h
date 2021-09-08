/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 *   
 *   Endorsement (attestation) functions
 ********************************************************************************/

#ifndef __SIMULATOR_OS_ATTESTATION
#define __SIMULATOR_OS_ATTESTATION

unsigned int os_endorsement_key2_derive_sign_data(
    unsigned char *src, unsigned int srcLength, unsigned char *signature);

unsigned int os_endorsement_get_code_hash(unsigned char *buffer);

#endif // __SIMULATOR_OS_ATTESTATION