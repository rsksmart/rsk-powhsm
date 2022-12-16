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

import ecdsa
from admin.bip32 import BIP32Path
from admin.dongle_eth import DongleEth, DongleEthError
from ledgerblue.commException import CommException
import struct
from unittest import TestCase
from unittest.mock import call, Mock, patch


class TestDongleEth(TestCase):
    @classmethod
    def setUpClass(cls):
        privkey = ecdsa.SigningKey.from_string(
            bytes.fromhex("aa"*32), curve=ecdsa.SECP256k1)
        cls.pubkey = privkey.get_verifying_key().to_string("uncompressed")

    @patch("admin.dongle_eth.getDongle")
    def setUp(self, getDongleMock):
        dongle_mock = Mock()
        getDongleMock.return_value = dongle_mock
        self.exchange_mock = dongle_mock.exchange
        self.eth = DongleEth(True)
        self.eth.connect()

    def tearDown(self):
        self.eth.disconnect()

    def test_get_pubkey_ok(self):
        self.exchange_mock.side_effect = [bytes([0x41]) + self.pubkey]

        eth_path = BIP32Path("m/44'/60'/0'/0/0")
        self.assertEqual(self.pubkey, self.eth.get_pubkey(eth_path))

        encoded_path = bytes.fromhex('8000002c8000003c800000000000000000000000')
        self.assertEqual([call(bytes([0xE0, 0x02, 0x00, 0x00, len(encoded_path) + 1,
                               len(eth_path.elements)]) + encoded_path)],
                         self.exchange_mock.call_args_list)

    def test_get_pubkey_invalid_path(self):
        self.exchange_mock.side_effect = CommException("msg", 0x6a15)

        eth_path = BIP32Path("m/44'/137'/0'/0/0")
        with self.assertRaises(DongleEthError):
            self.eth.get_pubkey(eth_path)

        encoded_path = bytes.fromhex('8000002c80000089800000000000000000000000')
        self.assertEqual([call(bytes([0xE0, 0x02, 0x00, 0x00, len(encoded_path) + 1,
                               len(eth_path.elements)]) + encoded_path)],
                         self.exchange_mock.call_args_list)

    def test_get_pubkey_wrong_app(self):
        self.exchange_mock.side_effect = CommException("msg", 0x6511)

        eth_path = BIP32Path("m/44'/60'/0'/0/0")
        with self.assertRaises(DongleEthError):
            self.eth.get_pubkey(eth_path)

        encoded_path = bytes.fromhex('8000002c8000003c800000000000000000000000')
        self.assertEqual([call(bytes([0xE0, 0x02, 0x00, 0x00, len(encoded_path) + 1,
                               len(eth_path.elements)]) + encoded_path)],
                         self.exchange_mock.call_args_list)

    def test_get_pubkey_device_locked(self):
        self.exchange_mock.side_effect = CommException("msg", 0x6b0c)

        eth_path = BIP32Path("m/44'/60'/0'/0/0")
        with self.assertRaises(DongleEthError):
            self.eth.get_pubkey(eth_path)

        encoded_path = bytes.fromhex('8000002c8000003c800000000000000000000000')
        self.assertEqual([call(bytes([0xE0, 0x02, 0x00, 0x00, len(encoded_path) + 1,
                               len(eth_path.elements)]) + encoded_path)],
                         self.exchange_mock.call_args_list)

    def test_get_pubkey_dongle_error(self):
        self.exchange_mock.side_effect = Exception('error-msg')

        eth_path = BIP32Path("m/44'/60'/0'/0/0")
        with self.assertRaises(DongleEthError):
            self.eth.get_pubkey(eth_path)

        encoded_path = bytes.fromhex('8000002c8000003c800000000000000000000000')
        self.assertEqual([call(bytes([0xE0, 0x02, 0x00, 0x00, len(encoded_path) + 1,
                               len(eth_path.elements)]) + encoded_path)],
                         self.exchange_mock.call_args_list)

    def test_sign_message_ok(self):
        v = 'aa'
        r = 'bb' * 32
        s = 'cc' * 32
        self.exchange_mock.side_effect = [bytes.fromhex(v + r + s)]

        expected_signature = ecdsa.util.sigencode_der(int(r, 16), int(s, 16), 0)
        eth_path = BIP32Path("m/44'/60'/0'/0/0")
        msg = ('aa' * 72).encode()
        self.assertEqual(expected_signature, self.eth.sign(eth_path, msg))

        encoded_path = bytes.fromhex('8000002c8000003c800000000000000000000000')
        encoded_tx = struct.pack(">I", len(msg)) + msg
        self.assertEqual([call(bytes([0xE0, 0x08, 0x00, 0x00,
                               len(encoded_path) + 1 + len(encoded_tx),
                               len(eth_path.elements)]) + encoded_path + encoded_tx)],
                         self.exchange_mock.call_args_list)

    def test_sign_message_invalid_path(self):
        self.exchange_mock.side_effect = CommException("msg", 0x6a15)

        eth_path = BIP32Path("m/44'/137'/0'/0/0")
        msg = ('aa' * 72).encode()
        with self.assertRaises(DongleEthError):
            self.eth.sign(eth_path, msg)

        encoded_path = bytes.fromhex('8000002c80000089800000000000000000000000')
        encoded_tx = struct.pack(">I", len(msg)) + msg
        self.assertEqual([call(bytes([0xE0, 0x08, 0x00, 0x00,
                               len(encoded_path) + 1 + len(encoded_tx),
                               len(eth_path.elements)]) + encoded_path + encoded_tx)],
                         self.exchange_mock.call_args_list)

    def test_sign_message_wrong_app(self):
        self.exchange_mock.side_effect = CommException("msg", 0x6511)

        eth_path = BIP32Path("m/44'/60'/0'/0/0")
        msg = ('aa' * 72).encode()
        with self.assertRaises(DongleEthError):
            self.eth.sign(eth_path, msg)

        encoded_path = bytes.fromhex('8000002c8000003c800000000000000000000000')
        encoded_tx = struct.pack(">I", len(msg)) + msg
        self.assertEqual([call(bytes([0xE0, 0x08, 0x00, 0x00,
                               len(encoded_path) + 1 + len(encoded_tx),
                               len(eth_path.elements)]) + encoded_path + encoded_tx)],
                         self.exchange_mock.call_args_list)

    def test_sign_message_device_locked(self):
        self.exchange_mock.side_effect = CommException("msg", 0x6b0c)

        eth_path = BIP32Path("m/44'/60'/0'/0/0")
        msg = ('aa' * 72).encode()
        with self.assertRaises(DongleEthError):
            self.eth.sign(eth_path, msg)

        encoded_path = bytes.fromhex('8000002c8000003c800000000000000000000000')
        encoded_tx = struct.pack(">I", len(msg)) + msg
        self.assertEqual([call(bytes([0xE0, 0x08, 0x00, 0x00,
                               len(encoded_path) + 1 + len(encoded_tx),
                               len(eth_path.elements)]) + encoded_path + encoded_tx)],
                         self.exchange_mock.call_args_list)

    def test_sign_message_dongle_error(self):
        self.exchange_mock.side_effect = Exception('error-msg')

        eth_path = BIP32Path("m/44'/60'/0'/0/0")
        msg = ('aa' * 72).encode()
        with self.assertRaises(DongleEthError):
            self.eth.sign(eth_path, msg)

        encoded_path = bytes.fromhex('8000002c8000003c800000000000000000000000')
        encoded_tx = struct.pack(">I", len(msg)) + msg
        self.assertEqual([call(bytes([0xE0, 0x08, 0x00, 0x00,
                               len(encoded_path) + 1 + len(encoded_tx),
                               len(eth_path.elements)]) + encoded_path + encoded_tx)],
                         self.exchange_mock.call_args_list)

    def test_sign_msg_too_big(self):
        ethpath = BIP32Path("m/44'/60'/0'/0/0")
        msg = ('aa' * 300).encode()
        with self.assertRaises(DongleEthError):
            self.eth.sign(ethpath, msg)

        self.assertFalse(self.exchange_mock.called)
