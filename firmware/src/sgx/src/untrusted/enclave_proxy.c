#include <openenclave/host.h>
#include <stdio.h>
#include <stdbool.h>

#include "enclave_proxy.h"

#include "hsm_u.h"
#include "enclave_provider.h"
#include "keyvalue_store.h"
#include "log.h"

#define CHECK_ECALL_RESULT(oe_result, error_msg, ret)                          \
    {                                                                          \
        if (OE_OK != oe_result) {                                              \
            LOG(error_msg);                                                    \
            LOG(": oe_result=%u (%s)\n", oe_result, oe_result_str(oe_result)); \
            return (ret);                                                      \
        }                                                                      \
    }

/**
 * ECALLS
 */

bool eprx_system_init(unsigned char *msg_buffer, size_t msg_buffer_size) {
    oe_enclave_t *enclave = epro_get_enclave();
    if (enclave == NULL) {
        LOG("Failed to retrieve the enclave. "
            "Unable to call system_init().\n");
        return false;
    }

    bool result;
    oe_result_t oe_result = ecall_system_init(enclave, &result,
                                              msg_buffer, msg_buffer_size);
    CHECK_ECALL_RESULT(oe_result, "Failed to call system_init()", false);
    return result;
}

unsigned int eprx_system_process_apdu(unsigned int rx) {
    oe_enclave_t *enclave = epro_get_enclave();
    if (enclave == NULL) {
        LOG("Failed to retrieve the enclave. "
            "Unable to call system_process_command().\n");
        return false;
    }

    unsigned int result;
    oe_result_t oe_result = ecall_system_process_apdu(enclave, &result, rx);

    CHECK_ECALL_RESULT(oe_result, "Failed to call ecall_system_process_apdu()", false);
    return result;
}

/**
 * OCALLS
 */

#define OCALL_PREFIX "[Ocall] "

bool ocall_kvstore_save(char* key, uint8_t* data, size_t data_size) {
    log_set_prefix(OCALL_PREFIX);
    bool retval = kvstore_save(key, data, data_size);
    log_clear_prefix();
    return retval;
}

bool ocall_kvstore_exists(char* key) {
    log_set_prefix(OCALL_PREFIX);
    bool retval = kvstore_exists(key);
    log_clear_prefix();
    return retval;
}

size_t ocall_kvstore_get(char* key, uint8_t* data_buf, size_t buffer_size) {
    log_set_prefix(OCALL_PREFIX);
    size_t retval = kvstore_get(key, data_buf, buffer_size);
    log_clear_prefix();
    return retval;
}

bool ocall_kvstore_remove(char* key) {
    log_set_prefix(OCALL_PREFIX);
    bool retval = kvstore_remove(key);
    log_clear_prefix();
    return retval;
}

