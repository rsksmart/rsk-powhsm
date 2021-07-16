#include "os.h"
#include "attestation.h"
#include "defs.h"
#include "pathAuth.h"
#include "bc_hash.h"
#include "mem.h"

// Attestation message prefix
#define ATT_MSG_PREFIX_LENGTH 14
const char ATT_MSG_PREFIX[ATT_MSG_PREFIX_LENGTH] = "HSM:SIGNER:2.1";

// -----------------------------------------------------------------------
// Protocol implementation
// -----------------------------------------------------------------------

static void hash_public_key(const char* path, att_t* att_ctx) {
    BEGIN_TRY {
        TRY {
            // Derive public key
            os_memmove(att_ctx->path, (unsigned int*) (&path[1]), sizeof(att_ctx->path)); // Skip first byte of path (size)
            // Derive and init private key
            os_perso_derive_node_bip32(CX_CURVE_256K1, att_ctx->path, RSK_PATH_LEN, att_ctx->priv_key_data, NULL);
            cx_ecdsa_init_private_key(CX_CURVE_256K1, att_ctx->priv_key_data, KEYLEN, &att_ctx->priv_key);
            // Cleanup private key data
            explicit_bzero(att_ctx->priv_key_data, sizeof(att_ctx->priv_key_data));
            // Derive public key
            cx_ecfp_generate_pair(CX_CURVE_256K1, &att_ctx->pub_key, &att_ctx->priv_key, 1);
            // Cleanup private key
            explicit_bzero(&att_ctx->priv_key, sizeof(att_ctx->priv_key));

            // Hash
            SHA256_UPDATE(&att_ctx->hash_ctx, att_ctx->pub_key.W, att_ctx->pub_key.W_len);

            // Cleanup public key
            explicit_bzero(&att_ctx->pub_key, sizeof(att_ctx->pub_key));
        }
        CATCH_OTHER(e) {
            // Cleanup key data and fail
            explicit_bzero(att_ctx->priv_key_data, sizeof(att_ctx->priv_key_data));
            explicit_bzero(&att_ctx->priv_key, sizeof(att_ctx->priv_key));
            explicit_bzero(&att_ctx->pub_key, sizeof(att_ctx->pub_key));
            THROW(ATT_INTERNAL);
        }
        FINALLY {
        }
    }
    END_TRY;
}

/*
 * Generate the attestation message.
 * 
 * @arg[in] att_ctx attestation context
 * @ret             generated message size
 */
static unsigned int generate_message_to_sign(att_t* att_ctx) {
    // Initialize message
    explicit_bzero(att_ctx->msg, sizeof(att_ctx->msg));
    
    // Copy the message prefix
    memcpy(att_ctx->msg, PIC(ATT_MSG_PREFIX), ATT_MSG_PREFIX_LENGTH);

    // Prepare the digest
    SHA256_INIT(&att_ctx->hash_ctx);

    // Retrieve and hash the public keys in order
    for (int i = 0; i < KEY_PATH_COUNT(); i++) {
        hash_public_key(get_ordered_path(i), att_ctx);
    }

    SHA256_FINAL(&att_ctx->hash_ctx, &att_ctx->msg[ATT_MSG_PREFIX_LENGTH]);

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