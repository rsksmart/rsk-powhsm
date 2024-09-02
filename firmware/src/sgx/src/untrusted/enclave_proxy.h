#ifndef __HSM_PROXY
#define __HSM_PROXY

#include <stdbool.h>

/**
 * @brief See system_init in system.h within the trusted sources
 */
bool eprx_system_init(unsigned char *msg_buffer, size_t msg_buffer_size);

/**
 * @brief See system_process_apdu in system.h within the trusted sources
 */
unsigned int eprx_system_process_apdu(unsigned int rx);

#endif // __HSM_PROXY