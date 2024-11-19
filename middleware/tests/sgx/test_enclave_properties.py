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
from unittest.mock import patch
from admin.misc import AdminError
from sgx.sgxtypes.sgx_enclave_properties import EnclaveProperties, _Header

import logging
import struct

logging.disable(logging.CRITICAL)


class TestEnclaveProperties(TestCase):
    def setUp(self):
        self.size_num_heap_pages = 0x123456789ABCDEF0
        self.size_num_stack_pages = 0x9ABCDEF012345678
        self.size_num_tcs = 0x1122334455667788
        self.header_size = 0x12345678
        self.header_type = 0x9ABCDEF0

        size_settings_bytes = struct.pack(
            "<QQQ",
            self.size_num_heap_pages,
            self.size_num_stack_pages,
            self.size_num_tcs
        )

        header_bytes = struct.pack(
            "<II24s",
            self.header_size,
            self.header_type,
            size_settings_bytes
        )

        self.header = _Header(header_bytes)
        self.config = bytes([0x22]*64)
        self.image_info = bytes([0x33]*48)
        self.sigstruct = bytes([0x22]*1816)

        self.enclave_properties_bytes = struct.pack(
            "<32s64s48s1816s",
            header_bytes,
            self.config,
            self.image_info,
            self.sigstruct
        )

    def assert_header(self, header):
        self.assertEqual(header.size, self.header_size)
        self.assertEqual(header.enclave_type, self.header_type)
        self.assertEqual(header.size_settings.num_heap_pages, self.size_num_heap_pages)
        self.assertEqual(header.size_settings.num_stack_pages, self.size_num_stack_pages)
        self.assertEqual(header.size_settings.num_tcs, self.size_num_tcs)

    @patch("sgx.sgxtypes.sgx_enclave_properties.SGXSigstruct")
    def test_valid_input(self, SGXSigstructMock):
        SGXSigstructMock.return_value = self.sigstruct
        enc_properties = EnclaveProperties(self.enclave_properties_bytes)
        SGXSigstructMock.assert_called_with(self.sigstruct)
        self.assert_header(enc_properties.header)
        self.assertEqual(enc_properties.sigstruct, self.sigstruct)

    @patch("sgx.sgxtypes.sgx_sigstruct.SGXSigstruct.get_mrenclave")
    def test_get_mrenclave(self, get_mrencalve_mock):
        mock_mrenclave = bytes([0x44]*32)
        get_mrencalve_mock.return_value = mock_mrenclave

        enc_properties = EnclaveProperties(self.enclave_properties_bytes)
        self.assertEqual(enc_properties.get_mrenclave(), mock_mrenclave)
        get_mrencalve_mock.assert_called()

    def test_empty_input(self):
        data = b''
        with self.assertRaises(AdminError):
            EnclaveProperties(data)

    def test_invalid_input_size(self):
        data = bytearray(100)
        with self.assertRaises(AdminError):
            EnclaveProperties(data)

    def test_invalid_input(self):
        data = 'not a byte array'
        with self.assertRaises(AdminError):
            EnclaveProperties(data)
