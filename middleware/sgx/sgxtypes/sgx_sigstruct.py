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

from enum import IntEnum
from admin.misc import AdminError


class SGXSigstruct:
    class _Offset(IntEnum):
        HEADER = 0
        TYPE = 12
        VENDOR = 16
        DATE = 20
        HEADER2 = 24
        SWDEFINED = 40
        RESERVED = 44
        MODULUS = 128
        EXPONENT = 512
        SIGNATURE = 516
        MISCSELECT = 900
        MISCMASK = 904
        RESERVED2 = 908
        ISVFAMILYID = 912
        ATTRIBUTES = 928
        ATTRIBUTEMASK = 944
        ENCLAVEHASH = 960
        RESERVED3 = 992
        ISVEXTPRODID = 1008
        ISVPRODID = 1024
        ISVSVN = 1026
        RESERVED4 = 1028
        Q1 = 1040
        Q2 = 1424
        END_MARKER = 1808

    def __init__(self, data):
        if len(data) < self._Offset.END_MARKER:
            raise AdminError("Invalid data length")

        self.header = data[self._Offset.HEADER:self._Offset.TYPE]
        self.type = int.from_bytes(
            data[self._Offset.TYPE:self._Offset.VENDOR],
            byteorder="little"
        )
        self.vendor = int.from_bytes(
            data[self._Offset.VENDOR:self._Offset.DATE],
            byteorder="little"
        )
        self.date = int.from_bytes(
            data[self._Offset.DATE:self._Offset.HEADER2],
            byteorder="little"
        )
        self.header2 = data[self._Offset.HEADER2:self._Offset.SWDEFINED]
        self.swdefined = int.from_bytes(
            data[self._Offset.SWDEFINED:self._Offset.RESERVED],
            byteorder="little"
        )
        self.reserved = data[self._Offset.RESERVED:self._Offset.MODULUS]
        self.modulus = data[self._Offset.MODULUS:self._Offset.EXPONENT]
        self.exponent = data[self._Offset.EXPONENT:self._Offset.SIGNATURE]
        self.signature = data[self._Offset.SIGNATURE:self._Offset.MISCSELECT]
        self.miscselect = int.from_bytes(
            data[self._Offset.MISCSELECT:self._Offset.MISCMASK],
            byteorder="little"
        )
        self.miscmask = int.from_bytes(
            data[self._Offset.MISCMASK:self._Offset.RESERVED2],
            byteorder="little"
        )
        self.reserved2 = data[self._Offset.RESERVED2:self._Offset.ISVFAMILYID]
        self.isvfamilyid = data[self._Offset.ISVFAMILYID:self._Offset.ATTRIBUTES]
        self.attributes = data[self._Offset.ATTRIBUTES:self._Offset.ATTRIBUTEMASK]
        self.attributemask = data[self._Offset.ATTRIBUTEMASK:self._Offset.ENCLAVEHASH]
        self.enclavehash = data[self._Offset.ENCLAVEHASH:self._Offset.RESERVED3]
        self.reserved3 = data[self._Offset.RESERVED3:self._Offset.ISVEXTPRODID]
        self.isvextprodid = data[self._Offset.ISVEXTPRODID:self._Offset.ISVPRODID]
        self.isvprodid = int.from_bytes(
            data[self._Offset.ISVPRODID:self._Offset.ISVSVN],
            byteorder="little"
        )
        self.isvsvn = int.from_bytes(
            data[self._Offset.ISVSVN:self._Offset.RESERVED4],
            byteorder="little"
        )
        self.reserved4 = data[self._Offset.RESERVED4:self._Offset.Q1]
        self.q1 = data[self._Offset.Q1:self._Offset.Q2]
        self.q2 = data[self._Offset.Q2:self._Offset.END_MARKER]

    def get_mrenclave(self):
        return self.enclavehash.hex()

    def to_dict(self):
        return {
            "header": self.header.hex(),
            "type": self.type,
            "vendor": self.vendor,
            "date": self.date,
            "header2": self.header2.hex(),
            "swdefined": self.swdefined,
            "reserved": self.reserved.hex(),
            "modulus": self.modulus.hex(),
            "exponent": self.exponent.hex(),
            "signature": self.signature.hex(),
            "miscselect": self.miscselect,
            "miscmask": self.miscmask,
            "reserved2": self.reserved2.hex(),
            "isvfamilyid": self.isvfamilyid.hex(),
            "attributes": self.attributes.hex(),
            "attributemask": self.attributemask.hex(),
            "enclavehash": self.enclavehash.hex(),
            "reserved3": self.reserved3.hex(),
            "isvextprodid": self.isvextprodid.hex(),
            "isvprodid": self.isvprodid,
            "isvsvn": self.isvsvn,
            "reserved4": self.reserved4.hex(),
            "q1": self.q1.hex(),
            "q2": self.q2.hex(),
        }
