#ifndef FEDHM_EMULATOR
#include "os.h"
#endif

#include "attestation.h"
#include "defs.h"
#include "pathAuth.h"
#include "bc_hash.h"
#include "mem.h"

// Attestation message prefix
#define ATT_MSG_PREFIX_LENGTH 15
const char ATT_MSG_PREFIX[ATT_MSG_PREFIX_LENGTH] = "RSK:HSM:SIGNER:";

// -----------------------------------------------------------------------
// Protocol implementation
// -----------------------------------------------------------------------

static void hash_public_key(const char* path, att_t* att_ctx) {
    // Derive public key
    moxie_swi_crypto_cleanup();
    os_memmove(att_ctx->path, (unsigned int*) (&path[1]), sizeof(att_ctx->path)); // Skip first byte of path (size)
    os_perso_derive_node_bip32(CX_CURVE_256K1, att_ctx->path, RSK_PATH_LEN, att_ctx->priv_key_data, NULL);
    cx_ecdsa_init_private_key(CX_CURVE_256K1, att_ctx->priv_key_data, KEYLEN, &att_ctx->priv_key);
    cx_ecfp_generate_pair(CX_CURVE_256K1, &att_ctx->pub_key, &att_ctx->priv_key, 1);

    // Hash
    SHA256_UPDATE(&att_ctx->hash_ctx, att_ctx->pub_key.W, att_ctx->pub_key.W_len);
}

/*
 * Generate the attestation message.
 * 
 * @arg[in] att_ctx attestation context
 * @ret             generated message size
 */
static unsigned int generate_message_to_sign(att_t* att_ctx) {
    // Copy the message prefix
    memcpy(att_ctx->msg, PIC(ATT_MSG_PREFIX), ATT_MSG_PREFIX_LENGTH);

    // Prepare the digest
    SHA256_INIT(&att_ctx->hash_ctx);

    // Retrieve and hash the public keys in order
    for (int i = 0; i < KEY_PATH_COUNT(); i++) {
        hash_public_key(get_ordered_path(i), att_ctx);
    }

    SHA256_FINAL(&att_ctx->hash_ctx, &att_ctx->msg[ATT_MSG_PREFIX_LENGTH]);

    // Keys cleanup
    for (int i=0;i<sizeof(att_ctx->priv_key_data);i++) att_ctx->priv_key_data[i]=0;
    for (int i=0;i<sizeof(att_ctx->priv_key);i++) ((char *)(&att_ctx->priv_key))[i]=0;
    for (int i=0;i<sizeof(att_ctx->pub_key);i++) ((char *)(&att_ctx->pub_key))[i]=0;
    
    return ATT_MSG_PREFIX_LENGTH + HASH_SIZE;
}

/*
 * Implement the attestation protocol.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @arg[in] att_ctx attestation context
 * @ret             number of transmited bytes to the host
 */
unsigned int get_attestation(volatile unsigned int rx, att_t* att_ctx) {
    unsigned int message_size;

    switch (APDU_OP()) {
        case OP_GET:
            // Generate the message to sign
            message_size = generate_message_to_sign(att_ctx);

            // Sign message
            int endorsement_size = os_endorsement_key2_derive_sign_data(
                att_ctx->msg, message_size, APDU_DATA_PTR);
            
            return TX_FOR_DATA_SIZE(endorsement_size);
        case OP_GET_MESSAGE:
            // Generate and output the message to sign
            message_size = generate_message_to_sign(att_ctx);
            memcpy(APDU_DATA_PTR, att_ctx->msg, message_size);

            return TX_FOR_DATA_SIZE(message_size);
        case OP_APP_HASH:
            return TX_FOR_DATA_SIZE(os_endorsement_get_code_hash(APDU_DATA_PTR));
        default:
            THROW(ATT_PROT_INVALID);
            break;
    }
}