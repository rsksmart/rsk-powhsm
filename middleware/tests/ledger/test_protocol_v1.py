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
from unittest.mock import Mock, call, patch
from parameterized import parameterized
from comm.protocol import HSM2ProtocolError
from ledger.protocol_v1 import HSM1ProtocolLedger
from ledger.hsm2dongle import (
    HSM2Dongle,
    HSM2FirmwareVersion,
    HSM2DongleError,
    HSM2DongleErrorResult,
    HSM2DongleTimeoutError,
    HSM2DongleCommError,
)

import logging

logging.disable(logging.CRITICAL)


class TestHSM1ProtocolLedger(TestCase):
    def setUp(self):
        self.pin = Mock()
        self.dongle = Mock()
        self.dongle.connect = Mock()
        self.dongle.disconnect = Mock()
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.SIGNER)
        self.dongle.get_version = Mock(return_value=HSM2FirmwareVersion(4, 0, 0))
        self.dongle.get_signer_parameters = Mock(return_value=Mock(
            min_required_difficulty=123))
        self.protocol = HSM1ProtocolLedger(self.pin, self.dongle)
        self.protocol.initialize_device()

    @patch("comm.protocol.BIP32Path")
    def test_get_pubkey_ok(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.get_public_key.return_value = "this-is-the-public-key"

        self.assertEqual(
            {
                "errorcode": 0,
                "pubKey": "this-is-the-public-key"
            },
            self.protocol.handle_request({
                "version": 1,
                "command": "getPubKey",
                "keyId": "m/44'/1'/2'/3/4"
            }),
        )
        self.assertEqual([call("the-key-id")], self.dongle.get_public_key.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

    @patch("comm.protocol.BIP32Path")
    def test_get_pubkey_error(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.get_public_key.side_effect = HSM2DongleErrorResult()

        self.assertEqual(
            {"errorcode": -2},
            self.protocol.handle_request({
                "version": 1,
                "command": "getPubKey",
                "keyId": "m/44'/1'/2'/3/4"
            }),
        )
        self.assertEqual([call("the-key-id")], self.dongle.get_public_key.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

    @patch("comm.protocol.BIP32Path")
    def test_get_pubkey_timeout(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.get_public_key.side_effect = HSM2DongleTimeoutError()

        self.assertEqual(
            {"errorcode": -2},
            self.protocol.handle_request({
                "version": 1,
                "command": "getPubKey",
                "keyId": "m/44'/1'/2'/3/4"
            }),
        )
        self.assertEqual([call("the-key-id")], self.dongle.get_public_key.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

    @patch("comm.protocol.BIP32Path")
    def test_get_pubkey_commerror_reconnection(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.get_public_key.side_effect = HSM2DongleCommError()

        self.assertEqual(
            {"errorcode": -2},
            self.protocol.handle_request({
                "version": 1,
                "command": "getPubKey",
                "keyId": "m/44'/1'/2'/3/4"
            }),
        )
        self.assertEqual([call("the-key-id")], self.dongle.get_public_key.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

        # Reconnection logic
        self.dongle.get_public_key.side_effect = None
        self.dongle.get_public_key.return_value = "this-is-the-public-key"

        self.assertEqual(
            {
                "errorcode": 0,
                "pubKey": "this-is-the-public-key"
            },
            self.protocol.handle_request({
                "version": 1,
                "command": "getPubKey",
                "keyId": "m/44'/1'/2'/3/4"
            }),
        )

        self._assert_reconnected()

    @patch("comm.protocol.BIP32Path")
    def test_get_pubkey_unexpected_error(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.get_public_key.side_effect = HSM2DongleError()

        with self.assertRaises(HSM2ProtocolError):
            self.protocol.handle_request({
                "version": 1,
                "command": "getPubKey",
                "keyId": "m/44'/1'/2'/3/4"
            })

        self.assertEqual([call("the-key-id")], self.dongle.get_public_key.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

    @patch("comm.protocol.BIP32Path")
    def test_sign_ok(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        signature = Mock(r="this-is-r", s="this-is-s")
        self.dongle.sign_unauthorized.return_value = (True, signature)

        self.assertEqual(
            {
                "errorcode": 0,
                "signature": {
                    "r": "this-is-r",
                    "s": "this-is-s"
                }
            },
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "message": "aa"*32,
            }),
        )

        self.assertEqual(
            [call(key_id="the-key-id", hash="aa"*32)],
            self.dongle.sign_unauthorized.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    @parameterized.expand([
        ("path", -1, -2),
        ("hash", -5, -2),
        ("unexpected", -10, -2),
        ("unknown", -100, -2),
    ])
    @patch("comm.protocol.BIP32Path")
    def test_sign_error(self, _, dongle_error_code, protocol_error_code, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.sign_unauthorized.return_value = (False, dongle_error_code)

        self.assertEqual(
            {"errorcode": protocol_error_code},
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "message": "aa"*32,
            }),
        )

        self.assertEqual(
            [call(key_id="the-key-id", hash="aa"*32)],
            self.dongle.sign_unauthorized.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    @patch("comm.protocol.BIP32Path")
    def test_sign_timeout(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.sign_unauthorized.side_effect = HSM2DongleTimeoutError()

        self.assertEqual(
            {"errorcode": -2},
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "message": "aa"*32,
            }),
        )

        self.assertEqual(
            [call(key_id="the-key-id", hash="aa"*32)],
            self.dongle.sign_unauthorized.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    @patch("comm.protocol.BIP32Path")
    def test_sign_commerror_reconnection(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.sign_unauthorized.side_effect = HSM2DongleCommError()

        self.assertEqual(
            {"errorcode": -2},
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "message": "aa"*32,
            }),
        )

        self.assertEqual(
            [call(key_id="the-key-id", hash="aa"*32)],
            self.dongle.sign_unauthorized.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

        # Reconnection logic
        self.dongle.sign_unauthorized.side_effect = None
        signature = Mock(r="this-is-r", s="this-is-s")
        self.dongle.sign_unauthorized.return_value = (True, signature)

        self.assertEqual(
            {
                "errorcode": 0,
                "signature": {
                    "r": "this-is-r",
                    "s": "this-is-s"
                }
            },
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "message": "aa"*32,
            }),
        )

        self._assert_reconnected()

    @patch("comm.protocol.BIP32Path")
    def test_sign_exception(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.sign_unauthorized.side_effect = HSM2DongleError()

        with self.assertRaises(HSM2ProtocolError):
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "message": "aa"*32,
            })

        self.assertEqual(
            [call(key_id="the-key-id", hash="aa"*32)],
            self.dongle.sign_unauthorized.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    @patch("comm.protocol.BIP32Path")
    def test_sign_message_invalid(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"

        self.assertEqual(
            {"errorcode": -2},
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "message": "not-a-hexadecimal-string",
            }),
        )

        self.assertFalse(self.dongle.sign_unauthorized.called)
        self.assertFalse(self.dongle.disconnect.called)

    def _assert_reconnected(self):
        self.assertTrue(self.dongle.disconnect.called)
        self.assertEqual(2, self.dongle.connect.call_count)
