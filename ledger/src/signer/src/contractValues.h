/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   Hardcoded check values
 ********************************************************************************/

#ifndef CONTRACTVALUES_H
#define CONTRACTVALUES_H

// Real values
#define CONTRACTADDRESS_LEN 20
const char ContractAddress[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                               "\x00\x00\x00\x00\x00\x01\x00\x00\x06";
#define CONTRACTSIGNATURE_LEN 32
const char ContractSignature[] =
    "\x7a\x7c\x29\x48\x15\x28\xac\x8c\x2b\x2e\x93\xae\xe6\x58\xfd\xdd\x4d\xc1"
    "\x53\x04\xfa\x72\x3a\x5c\x2b\x88\x51\x45\x57\xbc\xc7\x90";

const char ReceiptsRootConst[] =
    "\x57\x0c\x3b\x2d\x73\xe2\x9e\xb0\xe1\x1a\x93\x67\xbe\x94\x2e\x05\x0e\x88"
    "\x64\xf7\x57\x00\x8a\x09\xba\x82\x97\x4a\xfa\x37\xa0\x5a";
#endif
