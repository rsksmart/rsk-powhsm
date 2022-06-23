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
from unittest.mock import patch, call, Mock
from admin.ledger_utils import compute_app_hash, encode_eth_message
from hashlib import sha256

import logging

logging.disable(logging.CRITICAL)


class TestComputeAppHash(TestCase):
    @patch("admin.ledger_utils.IntelHexParser")
    def test_multiple_areas(self, ihp_mock):
        ihp_mock.return_value.getAreas.return_value = [
            Mock(data=b"123"), Mock(data=b"456"), Mock(data=b"789")]

        hash = compute_app_hash("/a/path")

        self.assertEqual([call("/a/path")], ihp_mock.call_args_list)
        self.assertEqual(hash, sha256(b"123456789").digest())

    @patch("admin.ledger_utils.IntelHexParser")
    def test_no_areas(self, ihp_mock):
        ihp_mock.return_value.getAreas.return_value = []

        hash = compute_app_hash("/a/path")

        self.assertEqual([call("/a/path")], ihp_mock.call_args_list)
        self.assertEqual(hash, sha256().digest())


class TestEncodeEthMessage(TestCase):
    def test_str(self):
        self.assertEqual(b"\x19Ethereum Signed Message:\n5hello",
                         encode_eth_message("hello"))

    def test_hash(self):
        self.assertEqual(
            b"\x19Ethereum Signed Message:\n660xbe5fd059b11047155e6e8018ab2f4337c84a347e"
            b"015d29cc1ab8e6dde8250395",
            encode_eth_message("0xbe5fd059b11047155e6e8018ab2f4337c84a347e015d29cc1a"
                               "b8e6dde8250395"))
