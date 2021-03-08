#include "os.h"
#include "cx.h"
#include "attestation.h"
#include "defs.h"
#include "err.h"

// Global onboarding flag
extern const unsigned char* N_onboarded_ui[1];

// Attestation message prefix
#define ATT_MSG_PREFIX_LENGTH 10
const char ATT_MSG_PREFIX[ATT_MSG_PREFIX_LENGTH] = "HSM:UI:2.1";

/*
 * Assuming the custom CA public key is loaded in att_ctx->ca_pubkey,
 * generate the attestation message.
 * 
 * @arg[in] att_ctx attestation context
 * @ret             generated message size
 */
static unsigned int generate_message_to_sign(att_t* att_ctx) {
    // Generate the message to sign
    memcpy(att_ctx->msg, PIC(ATT_MSG_PREFIX), sizeof(ATT_MSG_PREFIX));
    // Avoid overflowing when copying the CA public key
    size_t max_pubkey_size = sizeof(att_ctx->msg) - sizeof(ATT_MSG_PREFIX);
    size_t to_copy = max_pubkey_size < att_ctx->ca_pubkey.W_len ? max_pubkey_size : att_ctx->ca_pubkey.W_len;
    memcpy(&att_ctx->msg[sizeof(ATT_MSG_PREFIX)], att_ctx->ca_pubkey.W, to_copy);

    return sizeof(ATT_MSG_PREFIX) + att_ctx->ca_pubkey.W_len;
}

// -----------------------------------------------------------------------
// Protocol implementation
// -----------------------------------------------------------------------
/*
 * Implement the attestation protocol.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @arg[in] att_ctx attestation context
 * @ret             number of transmited bytes to the host
 */
unsigned int get_attestation(volatile unsigned int rx, att_t* att_ctx) {
    unsigned int message_size;

    // Verify that the device has been onboarded
    unsigned char onboarded = *((unsigned char*)PIC(N_onboarded_ui));
    if (!onboarded) {
        THROW(NO_ONBOARD);
        return 0;
    }

    switch (APDU_OP()) {
        case ATT_OP_PUBKEY:
            // Should receive an uncompressed public key. Store it.
            if (APDU_DATA_SIZE(rx) != PUBKEYSIZE)
                THROW(PROT_INVALID);
            // Clear public key memory region first just in case initialization fails
            memset(&att_ctx->ca_pubkey, 0, sizeof(att_ctx->ca_pubkey));
            // Init public key
            cx_ecfp_init_public_key(CX_CURVE_256K1, G_apdu_data, PUBKEYSIZE, &att_ctx->ca_pubkey);
            att_ctx->flags |= ATT_PUBKEY_RECV;

            // Generate and output the message to sign
            message_size = generate_message_to_sign(att_ctx);
            memcpy(G_apdu_data, att_ctx->msg, message_size);

            return TX_FOR_DATA_SIZE(message_size);
        case ATT_OP_HASH:
            // Should receive a hash. Store it.
            if (APDU_DATA_SIZE(rx) != HASHSIZE)
                THROW(PROT_INVALID);
            memcpy(att_ctx->ca_signed_hash, G_apdu_data, HASHSIZE);
            att_ctx->flags |= ATT_HASH_RECV;
            return TX_FOR_DATA_SIZE(0);
        case ATT_OP_SIGNATURE:
            // Should receive a length and length bytes
            if (APDU_DATA_SIZE(rx) < 2 || APDU_DATA_SIZE(rx) != G_apdu_data[0]+1)
                THROW(PROT_INVALID);
            // Respect maximum signature size
            if (G_apdu_data[0] > MAX_SIGNATURE_LENGTH)
                THROW(PROT_INVALID);
            // Clear signature memory area first just in case something else fails
            att_ctx->ca_signature_length = 0;
            memset(att_ctx->ca_signature, 0, sizeof(att_ctx->ca_signature));
            // Store signature and length
            att_ctx->ca_signature_length = G_apdu_data[0];
            memcpy(att_ctx->ca_signature, &G_apdu_data[1], att_ctx->ca_signature_length);
            att_ctx->flags |= ATT_SIGNATURE_RECV;
            return TX_FOR_DATA_SIZE(0);
        case ATT_OP_GET:
            if ((att_ctx->flags & (ATT_PUBKEY_RECV | ATT_HASH_RECV | ATT_SIGNATURE_RECV)) != 
                (ATT_PUBKEY_RECV | ATT_HASH_RECV | ATT_SIGNATURE_RECV))
                THROW(PROT_INVALID);

            // Keypoint: only generate the attestation if the given public key
            // is the same as the device's custom CA public key.
            if (!cx_ecdsa_verify(
                                &att_ctx->ca_pubkey, 0, 
                                CX_SHA256, att_ctx->ca_signed_hash, HASHSIZE,
                                att_ctx->ca_signature, att_ctx->ca_signature_length) || 
                !os_customca_verify(
                                att_ctx->ca_signed_hash, att_ctx->ca_signature, 
                                att_ctx->ca_signature_length))
                THROW(CA_MISMATCH);

            message_size = generate_message_to_sign(att_ctx);

            // Clear flags (data would be inconsistent next time)
            att_ctx->flags = 0;

            // Sign and output            
            return TX_FOR_DATA_SIZE(os_endorsement_key2_derive_sign_data(
                att_ctx->msg, message_size, G_apdu_data));
        case ATT_OP_APP_HASH:
            return TX_FOR_DATA_SIZE(os_endorsement_get_code_hash(G_apdu_data));
        default:
            att_ctx->flags = 0;
            THROW(PROT_INVALID);
            break;
    }
}