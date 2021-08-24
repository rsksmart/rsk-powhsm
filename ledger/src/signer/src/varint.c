/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   Varint utils
 ********************************************************************************/

// Varint decoder
// Returns true if the buffer is big enough to decode the containing varint
#include "varint.h"

bool varintCanDecode(uint8_t *buffer, uint32_t bufferLength) {
    unsigned char firstByte;
    firstByte = buffer[0];
    if (firstByte < 0xFD) {
        return true;
    } else if (firstByte == 0xFD) {
        if (bufferLength >= 3)
            return true;
        else
            return false;
    } else if (firstByte == 0xFE) {
        if (bufferLength >= 5)
            return true;
        else
            return false;
    } else
        return false;
}

// Returns length in bytes of the body, given a hdr value
int varintLen(uint8_t firstByte) {
    if (firstByte < 0xFD)
        return 1;
    else
        return (1 << (firstByte - 0xFC));
}

// Encode number 'value' into 'buffer', returns lenght in 'len'
void createVarint(unsigned int value,
                  unsigned char *buffer,
                  unsigned char *len) {
    if (value < 0xFD) {
        buffer[0] = (unsigned char)(value);
        *len = 1;
        return;
    }
    buffer[1] = (unsigned char)(value & 0xFF);
    buffer[2] = (unsigned char)((value >> 8) & 0xFF);
    if (value < 0xffff) {
        buffer[0] = 0xFD;
        *len = 3;
        return;
    }
    buffer[3] = (unsigned char)((value >> 16) & 0xFF);
    if (value < 0xffffff) {
        buffer[0] = 0xFE;
        *len = 4;
        return;
    }
    buffer[4] = (unsigned char)((value >> 24) & 0xFF);
    buffer[0] = 0xFF;
    *len = 5;
}
