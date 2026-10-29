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
from admin.ledger_utils import compute_app_hash, encode_eth_message, \
    format_message_to_sign, pubkey_to_address, to_checksum_address
import secp256k1 as ec
from .ecdsa_utils import WEB3_PRIVATE_KEY, WEB3_ADDRESS
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


class TestFormatMessageToSign(TestCase):
    def test_format(self):
        formatted = format_message_to_sign(
            "a-message",
            encode_eth_message("a-message"),
            bytes.fromhex("aabbccdd"))
        lines = formatted.split("\n")

        self.assertIn("    a-message", lines)
        self.assertIn("    Full message: "
                      "\\x19Ethereum Signed Message:\\n9a-message", lines)
        self.assertIn("    Digest (keccak256):        0xaabbccdd", lines)
        # The message to paste must appear before any reference information
        self.assertLess(lines.index("    a-message"),
                        min(i for i, l in enumerate(lines) if "reference" in l))


class TestPubkeyToAddress(TestCase):
    def test_compressed_and_uncompressed(self):
        # Derive the public key with secp256k1, independently of pubkey_to_address
        pubkey = ec.PrivateKey(bytes.fromhex(WEB3_PRIVATE_KEY), raw=True).pubkey
        for compressed in [True, False]:
            self.assertEqual(
                WEB3_ADDRESS.lower(),
                pubkey_to_address(pubkey.serialize(compressed=compressed)))

    def test_invalid_pubkey(self):
        with self.assertRaises(Exception):
            pubkey_to_address(bytes.fromhex("04" + "00"*64))


class TestToChecksumAddress(TestCase):
    def test_eip55_vectors(self):
        for address in ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
                        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"]:
            self.assertEqual(address, to_checksum_address(address.lower()))
            self.assertEqual(address, to_checksum_address(address.lower()[2:]))
