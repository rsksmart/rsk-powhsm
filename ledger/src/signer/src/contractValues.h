/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2021 RSK Labs Ltd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

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
