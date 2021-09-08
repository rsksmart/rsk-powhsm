/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 * 
 *   ECDSA functions
 ********************************************************************************/

#ifndef __SIMULATOR_OS_ECDSA
#define __SIMULATOR_OS_ECDSA

#include <stddef.h>

// TODO: in the future, actual enum definitions for these
// two types could be copied from the nanos SDK and used
// to e.g. verify calls are made with expected parameters.
// Ignore for now, define as char.
#define CX_CURVE_256K1 0
#define CX_RND_RFC6979 0
#define CX_LAST 0
#define CX_SHA256 0
typedef char cx_md_t;
typedef char cx_curve_t;

typedef struct cx_ecfp_private_key_s {
    unsigned char K[32];
} cx_ecfp_private_key_t;

typedef struct cx_ecfp_public_key_s {
    unsigned int W_len;
    unsigned char W[65];
} cx_ecfp_public_key_t;

void os_ecdsa_initialize();

void os_perso_derive_node_bip32(cx_curve_t curve, unsigned int *path,
    unsigned int pathLength, unsigned char *privateKey,
    unsigned char *chain);

int cx_ecdsa_init_private_key(cx_curve_t curve, unsigned char *rawkey,
    unsigned int key_len, cx_ecfp_private_key_t *key);

int cx_ecfp_generate_pair(
    cx_curve_t curve, cx_ecfp_public_key_t *pubkey,
    cx_ecfp_private_key_t *privkey, int keepprivate);

int cx_ecdsa_sign(
    cx_ecfp_private_key_t *key,
    int mode, cx_md_t hashID, unsigned char *hash,
    unsigned int hash_len,
    unsigned char *sig);

size_t hsmsim_helper_getpubkey_compressed(const unsigned char* key, unsigned char* dest, size_t dest_size);

#endif // __SIMULATOR_OS_ECDSA