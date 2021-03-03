/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   USB simulator layer
 ********************************************************************************/

// the global apdu buffer simulation
#define IO_APDU_BUFFER_SIZE (5 + 80)
extern unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

// Reset data pointers to start a new transfter
void resetTransfer();

// This function emulates the HOST device
unsigned short io_exchange(unsigned char channel_and_flags,
                           unsigned char tx_len);

// Mocking assorted OS functions, constants and types
#define PIC(x) (x)
#define CX_CURVE_256K1 0

typedef char cx_curve_t;

typedef char cx_ecfp_private_key_t;

typedef struct cx_ecfp_public_key_s {
    unsigned int W_len;
    unsigned char W[65];
} cx_ecfp_public_key_t;

unsigned int os_endorsement_key2_derive_sign_data(
    unsigned char src, unsigned int srcLength, unsigned char *signature);

unsigned int os_endorsement_get_code_hash(unsigned char *buffer);

void moxie_swi_crypto_cleanup(void);

void os_perso_derive_node_bip32(cx_curve_t curve, unsigned int *path,
    unsigned int pathLength, unsigned char *privateKey,
    unsigned char *chain);

int cx_ecdsa_init_private_key(cx_curve_t curve, unsigned char *rawkey,
    unsigned int key_len, cx_ecfp_private_key_t *key);

void os_memmove(void *dst, const void *src, unsigned int length);

int cx_ecfp_generate_pair(
    cx_curve_t curve, cx_ecfp_public_key_t *pubkey,
    cx_ecfp_private_key_t *privkey, int keepprivate);