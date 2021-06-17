#ifndef FEDHM_EMULATOR
#include "os.h"
#include "cx.h"
#endif
#include "strings.h"

#include "sign.h"
#include "defs.h"

/*
 * Derive the public key for a given path.
 * Store the public key into the given destination buffer.
 *
 * @arg[in] path derivation path
 * @arg[in] path_length length of the derivation path
 * @arg[in] dest destination buffer
 * @arg[in] dest destination buffer size
 * @ret     size of the public key derived, 
 *          or DO_PUBKEY_ERROR in case of error
 */
int do_pubkey(
    unsigned int* path, unsigned char path_length, 
    unsigned char* dest, size_t dest_size) {

#ifndef FEDHM_EMULATOR
    unsigned char private_key_data[KEYLEN];
    cx_ecfp_private_key_t private_key;
    cx_ecfp_public_key_t public_key;

    int pubkey_size;


    BEGIN_TRY {
        TRY {
            // Derive and init private key
            os_perso_derive_node_bip32(CX_CURVE_256K1, path, path_length, private_key_data, NULL);
            cx_ecdsa_init_private_key(CX_CURVE_256K1, private_key_data, KEYLEN, &private_key);
            // Cleanup private key data
            explicit_bzero(private_key_data, sizeof(private_key_data));
            // Derive public key
            cx_ecfp_generate_pair(CX_CURVE_256K1, &public_key, &private_key, 1);
            // Cleanup private key
            explicit_bzero(&private_key, sizeof(private_key));
            // Check the destination buffer won't be overflowed by the public key
            if (dest_size < public_key.W_len) {
                pubkey_size = DO_PUBKEY_ERROR;
            } else {
                // Output public key
                memcpy(dest, public_key.W, public_key.W_len);
                pubkey_size = public_key.W_len;
            }
            // Cleanup public key
            explicit_bzero(&public_key, sizeof(public_key));
        }
        CATCH_OTHER(e) {
            // Cleanup key data and fail
            explicit_bzero(private_key_data, sizeof(private_key_data));
            explicit_bzero(&private_key, sizeof(private_key));
            explicit_bzero(&public_key, sizeof(public_key));
            // Signal error deriving public key
            pubkey_size = DO_PUBKEY_ERROR;
        }
        FINALLY {
        }
    }
    END_TRY;
    // Return public key size
    return pubkey_size;
#else
    return DO_PUBKEY_ERROR;
#endif
}

/*
 * Sign a message with a given path.
 * Store the signature into the given destination buffer.
 *
 * @arg[in] path derivation path
 * @arg[in] path_length length of the derivation path
 * @arg[in] message message buffer
 * @arg[in] message_size message size
 * @arg[in] dest destination buffer
 * @arg[in] dest destination buffer size
 * @ret     size of the signature produced, 
 *          or DO_SIGN_ERROR in case of error
 */
int do_sign(
    unsigned int* path, unsigned char path_length, 
    unsigned char* message, size_t message_size,
    unsigned char* dest, size_t dest_size) {

#ifndef FEDHM_EMULATOR
    unsigned char private_key_data[KEYLEN];
    cx_ecfp_private_key_t private_key;

    int sig_size;

    // Check the destination buffer won't be overflowed by the signature
    if (dest_size < MAX_SIGNATURE_LENGTH) {
        return DO_SIGN_ERROR;
    }

    BEGIN_TRY {
        TRY {
            // Derive and init private key
            os_perso_derive_node_bip32(CX_CURVE_256K1, path, path_length, private_key_data, NULL);
            cx_ecdsa_init_private_key(CX_CURVE_256K1, private_key_data, KEYLEN, &private_key);
            // Cleanup private key data
            explicit_bzero(private_key_data, sizeof(private_key_data));
            sig_size = cx_ecdsa_sign((void *)&private_key,
                CX_RND_RFC6979 | CX_LAST,
                CX_SHA256,
                message,
                message_size,
                dest);
            // Cleanup private key
            explicit_bzero(&private_key, sizeof(private_key));
        }
        CATCH_OTHER(e) {
            // Cleanup key data and fail
            explicit_bzero(private_key_data, sizeof(private_key_data));
            explicit_bzero(&private_key, sizeof(private_key));
            // Signal error signing
            sig_size = DO_SIGN_ERROR;
        }
        FINALLY {
        }
    }
    END_TRY;
    // Return signature size
    return sig_size;
#else
    return DO_SIGN_ERROR;
#endif
}