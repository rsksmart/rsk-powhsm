#ifndef __SIGN
#define __SIGN

#define DO_SIGN_ERROR (0)
#define DO_PUBKEY_ERROR (0)

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
    unsigned char* dest, size_t dest_size);

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
    unsigned char* dest, size_t dest_size);

#endif