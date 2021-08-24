/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   Varint utils
 ********************************************************************************/

#ifndef VARINT_H
#define VARINT_H
#include <stdint.h>
#include <stdbool.h>

bool varintCanDecode(uint8_t *buffer, uint32_t bufferLength);

void createVarint(unsigned int value,
                  unsigned char *buffer,
                  unsigned char *len);

int varintLen(uint8_t firstByte);

#endif // VARINT_H
