#include <stdlib.h>
#include <stdint.h>

/*
 * Returns 0 on success.
 * On success, *pt is malloc'd and must be freed by caller with secure_free(*pt, *pt_len) or free().
 */
int decrypt_kms_ct_for_recipient(const uint8_t *ct, size_t ct_len,
                                 const uint8_t *key_data, size_t key_len,
                                 uint8_t **pt, size_t *pt_len);