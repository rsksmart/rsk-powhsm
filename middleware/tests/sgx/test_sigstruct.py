# The MIT License (MIT)
#
# Copyright (c) 2021 RSK Labs Ltd
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from unittest import TestCase
from admin.misc import AdminError
from sgx.sgxtypes.sgx_sigstruct import SGXSigstruct

import logging
import struct

logging.disable(logging.CRITICAL)


class TestSigstruct(TestCase):
    def setUp(self):
        self.header = b'HEADER123456'
        self.type = 0x12345678
        self.vendor = 0x9ABCDEF0
        self.date = 0x11223344
        self.header2 = b'HEADER2_DATA____'
        self.swdefined = 0x55667788
        self.reserved = bytes([0x00]*84)
        self.modulus = bytes([0x11]*384)
        self.exponent = bytes([0x22]*4)
        self.signature = bytes([0x33]*384)
        self.miscselect = 0x99AABBCC
        self.miscmask = 0xDDEEFF00
        self.reserved2 = bytes([0x44]*4)
        self.isvfamilyid = bytes([0x55]*16)
        self.attributes = bytes([0x66]*16)
        self.attributemask = bytes([0x77]*16)
        self.enclavehash = bytes([0x88]*32)
        self.reserved3 = bytes([0x99]*16)
        self.isvextprodid = bytes([0xAA]*16)
        self.isvprodid = 0x6677
        self.isvsvn = 0x8899
        self.reserved4 = bytes([0xBB]*12)
        self.q1 = bytes([0xCC]*384)
        self.q2 = bytes([0xDD]*384)

        self.sigstruct_bytes = struct.pack(
            "<12sIII16sI84s384s4s384sII4s16s16s16s32s16s16sHH12s384s384s",
            self.header,
            self.type,
            self.vendor,
            self.date,
            self.header2,
            self.swdefined,
            self.reserved,
            self.modulus,
            self.exponent,
            self.signature,
            self.miscselect,
            self.miscmask,
            self.reserved2,
            self.isvfamilyid,
            self.attributes,
            self.attributemask,
            self.enclavehash,
            self.reserved3,
            self.isvextprodid,
            self.isvprodid,
            self.isvsvn,
            self.reserved4,
            self.q1,
            self.q2
        )

    def test_valid_input(self):
        sigstruct = SGXSigstruct(self.sigstruct_bytes)
        self.assertEqual(sigstruct.header, self.header)
        self.assertEqual(sigstruct.type, self.type)
        self.assertEqual(sigstruct.vendor, self.vendor)
        self.assertEqual(sigstruct.date, self.date)
        self.assertEqual(sigstruct.header2, self.header2)
        self.assertEqual(sigstruct.swdefined, self.swdefined)
        self.assertEqual(sigstruct.reserved, self.reserved)
        self.assertEqual(sigstruct.modulus, self.modulus)
        self.assertEqual(sigstruct.exponent, self.exponent)
        self.assertEqual(sigstruct.signature, self.signature)
        self.assertEqual(sigstruct.miscselect, self.miscselect)
        self.assertEqual(sigstruct.miscmask, self.miscmask)
        self.assertEqual(sigstruct.reserved2, self.reserved2)
        self.assertEqual(sigstruct.isvfamilyid, self.isvfamilyid)
        self.assertEqual(sigstruct.attributes, self.attributes)
        self.assertEqual(sigstruct.attributemask, self.attributemask)
        self.assertEqual(sigstruct.enclavehash, self.enclavehash)
        self.assertEqual(sigstruct.reserved3, self.reserved3)
        self.assertEqual(sigstruct.isvextprodid, self.isvextprodid)
        self.assertEqual(sigstruct.isvprodid, self.isvprodid)
        self.assertEqual(sigstruct.isvsvn, self.isvsvn)
        self.assertEqual(sigstruct.reserved4, self.reserved4)
        self.assertEqual(sigstruct.q1, self.q1)
        self.assertEqual(sigstruct.q2, self.q2)

    def test_get_mrenclave(self):
        sigstruct = SGXSigstruct(self.sigstruct_bytes)
        self.assertEqual(sigstruct.get_mrenclave(), self.enclavehash.hex())

    def test_empty_input(self):
        data = b''
        with self.assertRaises(AdminError):
            SGXSigstruct(data)

    def test_invalid_input_size(self):
        data = bytearray(100)
        with self.assertRaises(AdminError):
            SGXSigstruct(data)

    def test_invalid_input(self):
        data = 'not a byte array'
        with self.assertRaises(AdminError):
            SGXSigstruct(data)
