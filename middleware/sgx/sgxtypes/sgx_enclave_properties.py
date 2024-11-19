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
from sgx.sgxtypes.sgx_sigstruct import SGXSigstruct


class _SizeSettings:
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


class _Header:
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
        self.size_settings = _SizeSettings(
            data[self._Offset.SIZE_SETTINGS:self._Offset.END_MARKER]
        )

    def to_dict(self):
        return {
            "size": self.size,
            "enclave_type": self.enclave_type,
            "size_settings": self.size_settings.to_dict()
        }


class EnclaveProperties:
    class _Offset(IntEnum):
        HEADER = 0
        CONFIG = 32
        IMAGE_INFO = 96
        SIGSTRUCT = 144
        END_MARKER = 1960

    def __init__(self, data):
        if len(data) < self._Offset.END_MARKER:
            raise AdminError("Invalid data length")

        self.header = _Header(
            data[self._Offset.HEADER:self._Offset.CONFIG]
        )
        self.sigstruct = SGXSigstruct(
            data[self._Offset.SIGSTRUCT:self._Offset.END_MARKER]
        )

    def get_mrenclave(self):
        return self.sigstruct.get_mrenclave()

    def to_dict(self):
        return {"header": self.header.to_dict(), "sigstruct": self.sigstruct.to_dict()}
