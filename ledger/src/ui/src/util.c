
#include "defs.h"
#include "os.h"
#include "util.h"

unsigned char do_rsk_is_onboarded(unsigned char is_onboarded) {
    unsigned char output_index = CMDPOS;
    SET_APDU_AT(output_index++, is_onboarded);
    SET_APDU_AT(output_index++, VERSION_MAJOR);
    SET_APDU_AT(output_index++, VERSION_MINOR);
    SET_APDU_AT(output_index++, VERSION_PATCH);
    return output_index;
}

unsigned char do_rsk_echo(unsigned int rx) {
    return rx;
}

unsigned char do_rsk_mode_cmd() {
    unsigned char output_index = CMDPOS;
    SET_APDU_AT(output_index++, RSK_MODE_BOOTLOADER);
    return output_index;
}

unsigned char do_rsk_retries(unsigned char retries) {
    unsigned char output_index = OP;
    SET_APDU_AT(output_index++, retries);
    return output_index;
}