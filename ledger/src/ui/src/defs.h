#ifndef __DEFS
#define __DEFS

#include "apdu.h"

// Version and patchlevel
#define VERSION_MAJOR 0x02
#define VERSION_MINOR 0x03
#define VERSION_PATCH 0x00

// Instructions
#define RSK_PIN_CMD 0x41
#define RSK_SEED_CMD 0x44
#define RSK_ECHO_CMD 0x02
#define RSK_IS_ONBOARD 0x06
#define RSK_WIPE 0x7
#define RSK_NEWPIN 0x8
#define RSK_END_CMD 0xff
#define RSK_END_CMD_NOSIG 0xfa
#define RSK_UNLOCK_CMD 0xfe
#define RSK_RETRIES 0x45
#define RSK_MODE_CMD 0x43
#define RSK_META_CMD_UIOP 0x66

// Bootloader mode response for the mode command
#define RSK_MODE_BOOTLOADER 0x02

// Sizes
#define HASHSIZE 32
#define SEEDSIZE 32
#define KEYLEN 32
#define COMPRESSEDHASHSIZE 16
#define PUBKEYSIZE 65
#define PUBKEYCOMPRESSEDSIZE 33
#define MAX_SIGNATURE_LENGTH 72

#endif