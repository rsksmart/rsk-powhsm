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

from argparse import ArgumentParser
from admin.misc import AdminError
from elftools.elf.elffile import ELFFile
from enum import IntEnum
import json


class EnclaveSizeSettings:

    class _Offset(IntEnum):
        NUM_HEAP_PAGES = 0
        NUM_STACK_PAGES = 8
        NUM_TCS = 16
        END_MARKER = 24

    def __init__(self, data):
        self.num_heap_pages = int.from_bytes(
            data[self._Offset.NUM_HEAP_PAGES:self._Offset.NUM_STACK_PAGES],
            byteorder="little"
        )
        self.num_stack_pages = int.from_bytes(
            data[self._Offset.NUM_STACK_PAGES:self._Offset.NUM_TCS],
            byteorder="little"
        )
        self.num_tcs = int.from_bytes(
            data[self._Offset.NUM_TCS:self._Offset.END_MARKER],
            byteorder="little"
        )

    def to_dict(self):
        return {
            "num_heap_pages": self.num_heap_pages,
            "num_stack_pages": self.num_stack_pages,
            "num_tcs": self.num_tcs
        }


class EnclavePropertiesHeader:

    class _Offset(IntEnum):
        SIZE = 0
        TYPE = 4
        SIZE_SETTINGS = 8
        END_MARKER = 32

    def __init__(self, data):
        self.size = int.from_bytes(
            data[self._Offset.SIZE:self._Offset.TYPE],
            byteorder="little"
        )
        self.enclave_type = int.from_bytes(
            data[self._Offset.TYPE:self._Offset.SIZE_SETTINGS],
            byteorder="little"
        )
        self.size_settings = EnclaveSizeSettings(
            data[self._Offset.SIZE_SETTINGS:self._Offset.END_MARKER]
        )

    def to_dict(self):
        return {
            "size": self.size,
            "enclave_type": self.enclave_type,
            "size_settings": self.size_settings.to_dict()
        }


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
            "modulus": self.modulus.hex(),
            "exponent": self.exponent.hex(),
            "signature": self.signature.hex(),
            "miscselect": self.miscselect,
            "miscmask": self.miscmask,
            "isvfamilyid": self.isvfamilyid.hex(),
            "attributes": self.attributes.hex(),
            "attributemask": self.attributemask.hex(),
            "enclavehash": self.enclavehash.hex(),
            "isvextprodid": self.isvextprodid.hex(),
            "isvprodid": self.isvprodid,
            "isvsvn": self.isvsvn,
            "q1": self.q1.hex(),
            "q2": self.q2.hex(),
        }


class EnclaveProperties:

    class _Offset(IntEnum):
        HEADER = 0
        CONFIG = 32
        IMAGE_INFO = 96
        SIGSTRUCT = 144
        END_MARKER = 1960

    def __init__(self, data):
        self.header = EnclavePropertiesHeader(
            data[self._Offset.HEADER:self._Offset.CONFIG]
        )
        self.sigstruct = SGXSigstruct(
            data[self._Offset.SIGSTRUCT:self._Offset.END_MARKER]
        )

    def get_mrenclave(self):
        return self.sigstruct.get_mrenclave()

    def to_dict(self):
        return {"header": self.header.to_dict(), "sigstruct": self.sigstruct.to_dict()}


class EnclaveBinary:

    def __init__(self, enclave_path):
        self.enclave_path = enclave_path

    def load_binary(self):
        self.enclave_properties = None
        try:
            with open(self.enclave_path, "rb") as f:
                elf = ELFFile(f)
                oeinfo = elf.get_section_by_name(".oeinfo")
                if oeinfo is not None:
                    self.enclave_properties = EnclaveProperties(oeinfo.data())
        except Exception as e:
            raise AdminError(f"Failed to load enclave binary: {e}")
        if self.enclave_properties is None:
            raise AdminError("Enclave binary does not contain .oeinfo section")

    def get_mrenclave(self):
        return self.enclave_properties.get_mrenclave()


def main():
    parser = ArgumentParser(description="powHSM MRENCLAVE extractor")
    parser.add_argument(
        "-e",
        "--enclave",
        dest="enclave_path",
        help="Path to the signed enclave binary",
        required=True,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        help="Print verbose output",
        action="store_true",
    )
    args = parser.parse_args()
    enclave_binary = EnclaveBinary(args.enclave_path)
    try:
        enclave_binary.load_binary()
        mrenclave = enclave_binary.get_mrenclave()
        if args.verbose:
            print(json.dumps(enclave_binary.enclave_properties.to_dict(), indent=4))
        print(f"MRENCLAVE: {mrenclave}")
    except AdminError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
