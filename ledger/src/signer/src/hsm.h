#ifndef __HSM
#define __HSM

void hsm_init();

unsigned int hsm_process_apdu(volatile unsigned int rx);

unsigned int hsm_process_exception(unsigned short code, unsigned int tx);

#endif // __HSM