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
from unittest.mock import call, Mock, patch
from admin.dongle_admin import DongleAdmin, DongleAdminError, DongleAdminTimeout
import secp256k1 as ec
from ledgerblue.commException import CommException

import os
import struct


class TestDongleAdmin(TestCase):
    RANDOM_MOCK = os.urandom(8)
    PRIVATE_KEY = ec.PrivateKey()
    GENERIC_ERROR_MSG = 'error-msg'

    @patch("admin.dongle_admin.getDongle")
    def setUp(self, getDongleMock):
        self.dongle = Mock()
        self.getDongleMock = getDongleMock
        self.getDongleMock.return_value = self.dongle
        self.dongleAdmin = DongleAdmin(True)
        self.dongleAdmin.connect()

    @patch("admin.dongle_admin.getDongle")
    def test_connect_error(self, getDongleMock):
        getDongleMock.side_effect = CommException(self.GENERIC_ERROR_MSG)
        with self.assertRaises(DongleAdminError) as e:
            self.dongleAdmin.connect()
        self.assertTrue(getDongleMock.called)
        self.assertEqual(f'Error connecting: {self.GENERIC_ERROR_MSG}', str(e.exception))

    def test_disconnect(self):
        self.dongle.close = Mock()
        self.dongleAdmin.disconnect()
        self.assertTrue(self.dongle.close.called)

    def test_disconnect_error(self):
        self.dongle.close = Mock(side_effect=DongleAdminError(self.GENERIC_ERROR_MSG))
        with self.assertRaises(DongleAdminError) as e:
            self.dongleAdmin.disconnect()
        self.assertTrue(self.dongle.close.called)
        self.assertEqual(self.GENERIC_ERROR_MSG, str(e.exception))

    @patch("secp256k1.PrivateKey", return_value=PRIVATE_KEY)
    @patch("os.urandom", return_value=RANDOM_MOCK)
    def test_handshake(self, *_):
        device_nonce = os.urandom(8)
        self.dongle.exchange = Mock(return_value=bytes.fromhex('00' * 4) + device_nonce)
        ephemeral_key = self.dongleAdmin.handshake()

        exchange_calls = []
        exchange_calls.append(call(bytes([
            0xe0, 0x04, 0x00, 0x00, 0x04, 0x31, 0x10, 0x00, 0x02
        ]), timeout=10))

        nonce = self.RANDOM_MOCK
        exchange_calls.append(call(bytes([0xe0, 0x50, 0x00, 0x00, 0x08]) + nonce,
                                   timeout=10))

        pub_key = self.PRIVATE_KEY.pubkey.serialize(compressed=False)
        to_sign = bytes([0x01]) + pub_key
        signature = self.PRIVATE_KEY.ecdsa_serialize(
            self.PRIVATE_KEY.ecdsa_sign(bytes(to_sign)))
        certificate = (bytes([len(pub_key)]) + pub_key +
                       bytes([len(signature)]) + signature)
        exchange_calls.append(call(bytes([0xe0, 0x51, 0x00, 0x00, len(certificate)]) +
                                   certificate, timeout=10))

        ephemeral_key_pub = ephemeral_key.pubkey.serialize(compressed=False)
        to_sign = (bytes([0x11]) + nonce + device_nonce + ephemeral_key_pub)
        signature = ephemeral_key.ecdsa_serialize(
            ephemeral_key.ecdsa_sign(bytes(to_sign)))
        certificate = (bytes([len(ephemeral_key_pub)]) +
                       ephemeral_key_pub + bytes([len(signature)]) + signature)
        exchange_calls.append(call(bytes([0xe0, 0x51, 0x80, 0x00, len(certificate)]) +
                                   certificate, timeout=10))

        self.assertEqual(exchange_calls, self.dongle.exchange.call_args_list)
        self.assertEqual(self.PRIVATE_KEY, ephemeral_key)

    def test_handshake_not_connected(self):
        self.dongle.opened = False
        with self.assertRaises(DongleAdminError) as e:
            self.dongleAdmin.handshake()
        self.assertEqual('Connect to dongle first', str(e.exception))

    def test_handshake_timeout(self):
        self.dongle.exchange = Mock(side_effect=CommException('Timeout'))
        with self.assertRaises(DongleAdminTimeout):
            self.dongleAdmin.handshake()
        self.assertTrue(self.dongle.exchange.called)

    def test_get_device_key(self):
        nonce = bytes.fromhex('aa' * 8)
        cert_header = 'cert-header'.encode()
        priv_key = ec.PrivateKey()
        dev_pub_key = priv_key.pubkey.serialize(compressed=False)
        signature = priv_key.ecdsa_serialize(priv_key.ecdsa_sign('a-message'.encode()))

        self.dongle.exchange = Mock(return_value=bytes(bytes([len(cert_header)]) +
                                                       cert_header +
                                                       bytes([len(dev_pub_key)]) +
                                                       dev_pub_key +
                                                       bytes([len(signature)]) +
                                                       signature) + nonce)

        expected_return = {
            "pubkey": dev_pub_key.hex(),
            "message": (bytes([0x02]) + cert_header + dev_pub_key).hex(),
            "signature": signature.hex(),
        }

        self.assertEqual(expected_return, self.dongleAdmin.get_device_key())
        exchange_calls = []
        data = bytes([0x00, 0x00, 0x00])
        exchange_calls.append(
            call(
                struct.pack("BB%ds" % len(data), 0xE0, 0x52, data),
                timeout=10
            )
        )
        data = bytes([0x80, 0x00, 0x00])
        exchange_calls.append(
            call(
                struct.pack("BB%ds" % len(data), 0xE0, 0x52, data),
                timeout=10
            )
        )
        self.assertEqual(exchange_calls, self.dongle.exchange.call_args_list)

    def test_get_device_key_timeout(self):
        self.dongle.exchange = Mock(side_effect=CommException('Timeout'))
        with self.assertRaises(DongleAdminTimeout):
            self.dongleAdmin.get_device_key()
        self.assertTrue(self.dongle.exchange.called)

    def test_get_device_key_comm_error(self):
        self.dongle.exchange = Mock(side_effect=CommException(self.GENERIC_ERROR_MSG))
        with self.assertRaises(DongleAdminError) as e:
            self.dongleAdmin.get_device_key()
        self.assertTrue(self.dongle.exchange.called)
        self.assertEqual('Error sending command: '
                         f'{str(CommException(self.GENERIC_ERROR_MSG))}',
                         str(e.exception))

    def test_setup_endorsement_key(self):
        priv_key = ec.PrivateKey()
        scheme = 1
        endorsement_key_pub = priv_key.pubkey.serialize(compressed=False)
        signed_data = bytes([0xff]) + endorsement_key_pub
        signature = 'the-signature'.encode()
        certificate = 'the-certificate'.encode()

        self.dongle.exchange = Mock()

        # response for SETUP_ENDO command, we don't use the response of SETUP_ENDO_ACK
        self.dongle.exchange.return_value = bytes(endorsement_key_pub + signature)

        self.assertEqual(
            {
                "pubkey": endorsement_key_pub.hex(),
                "message": signed_data.hex(),
                "signature": signature.hex(),
            },
            self.dongleAdmin.setup_endorsement_key(scheme, certificate))

        exchange_calls = []
        data = bytes([scheme, 0x00, 0x00])
        exchange_calls.append(
            call(
                struct.pack("BB%ds" % len(data), 0xE0, 0xC0, data),
                timeout=10
            )
        )
        data = bytes([0x00, 0x00, len(certificate)]) + certificate
        exchange_calls.append(
            call(
                struct.pack("BB%ds" % len(data), 0xE0, 0xC2, data),
                timeout=10
            )
        )
        self.assertEqual(exchange_calls, self.dongle.exchange.call_args_list)

    def test_setup_endorsement_key_timeout(self):
        self.dongle.exchange = Mock(side_effect=CommException('Timeout'))
        with self.assertRaises(DongleAdminTimeout):
            self.dongleAdmin.setup_endorsement_key(1, 'certificate'.encode())
        self.assertTrue(self.dongle.exchange.called)

    def test_setup_endorsement_key_comm_error(self):
        self.dongle.exchange = Mock(side_effect=CommException(self.GENERIC_ERROR_MSG))
        with self.assertRaises(DongleAdminError) as e:
            self.dongleAdmin.setup_endorsement_key(1, 'certificate'.encode())
        self.assertTrue(self.dongle.exchange.called)
        self.assertEqual('Error sending command: '
                         f'{str(CommException(self.GENERIC_ERROR_MSG))}',
                         str(e.exception))
