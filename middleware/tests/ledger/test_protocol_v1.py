from unittest import TestCase
from unittest.mock import Mock, call, patch
from parameterized import parameterized
from comm.bip32 import BIP32Path
from comm.protocol import HSM2ProtocolError
from ledger.protocol_v1 import HSM1ProtocolLedger
from ledger.hsm2dongle import HSM2DongleError, HSM2DongleErrorResult, HSM2DongleTimeout

import logging
logging.disable(logging.CRITICAL)

class TestHSM1ProtocolLedger(TestCase):
    def setUp(self):
        self.pin = Mock()
        self.dongle = Mock()
        self.protocol = HSM1ProtocolLedger(self.pin, self.dongle)

    @patch("comm.protocol.BIP32Path")
    def test_get_pubkey_ok(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.get_public_key.return_value = "this-is-the-public-key"

        self.assertEqual(
            { "errorcode": 0, "pubKey": "this-is-the-public-key" },
            self.protocol.handle_request({ "version": 1, "command": "getPubKey", "keyId": "m/44'/1'/2'/3/4" }))
        self.assertEqual([call("the-key-id")], self.dongle.get_public_key.call_args_list)

    @patch("comm.protocol.BIP32Path")
    def test_get_pubkey_error(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.get_public_key.side_effect = HSM2DongleErrorResult()

        self.assertEqual(
            { "errorcode": -2 },
            self.protocol.handle_request({ "version": 1, "command": "getPubKey", "keyId": "m/44'/1'/2'/3/4" }))
        self.assertEqual([call("the-key-id")], self.dongle.get_public_key.call_args_list)

    @patch("comm.protocol.BIP32Path")
    def test_get_pubkey_timeout(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.get_public_key.side_effect = HSM2DongleTimeout()

        self.assertEqual(
            { "errorcode": -2 },
            self.protocol.handle_request({ "version": 1, "command": "getPubKey", "keyId": "m/44'/1'/2'/3/4" }))
        self.assertEqual([call("the-key-id")], self.dongle.get_public_key.call_args_list)

    @patch("comm.protocol.BIP32Path")
    def test_get_pubkey_unexpected_error(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.get_public_key.side_effect = HSM2DongleError()

        with self.assertRaises(HSM2ProtocolError):
            self.protocol.handle_request({ "version": 1, "command": "getPubKey", "keyId": "m/44'/1'/2'/3/4" })

        self.assertEqual([call("the-key-id")], self.dongle.get_public_key.call_args_list)

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
            { "errorcode": protocol_error_code },
            self.protocol.handle_request({ \
                                          "version": 1, \
                                          "command": "sign", \
                                          "keyId": "m/44'/1'/2'/3/4", \
                                          "message": "aa"*32 }))

        self.assertEqual([call(key_id="the-key-id", hash="aa"*32)], \
            self.dongle.sign_unauthorized.call_args_list)

    @patch("comm.protocol.BIP32Path")
    def test_sign_timeout(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.sign_unauthorized.side_effect = HSM2DongleTimeout()

        self.assertEqual(
            { "errorcode": -2 },
            self.protocol.handle_request({ \
                                          "version": 1, \
                                          "command": "sign", \
                                          "keyId": "m/44'/1'/2'/3/4", \
                                          "message": "aa"*32 }))

        self.assertEqual([call(key_id="the-key-id", hash="aa"*32)], \
            self.dongle.sign_unauthorized.call_args_list)

    @patch("comm.protocol.BIP32Path")
    def test_sign_exception(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.sign_unauthorized.side_effect = HSM2DongleError()

        with self.assertRaises(HSM2ProtocolError):
            self.protocol.handle_request({ \
                                          "version": 1, \
                                          "command": "sign", \
                                          "keyId": "m/44'/1'/2'/3/4", \
                                          "message": "aa"*32 })

        self.assertEqual([call(key_id="the-key-id", hash="aa"*32)], \
            self.dongle.sign_unauthorized.call_args_list)

    @patch("comm.protocol.BIP32Path")
    def test_sign_message_invalid(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"

        self.assertEqual(
            { "errorcode": -2 },
            self.protocol.handle_request({ \
                                          "version": 1, \
                                          "command": "sign", \
                                          "keyId": "m/44'/1'/2'/3/4", \
                                          "message": "not-a-hexadecimal-string" }))

        self.assertFalse(self.dongle.sign_unauthorized.called)