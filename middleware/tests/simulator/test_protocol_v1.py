from unittest import TestCase
from unittest.mock import Mock, call, patch
from comm.bip32 import BIP32Path
from simulator.protocol_v1 import HSM1ProtocolSimulator

import logging

logging.disable(logging.CRITICAL)


class TestHSM1ProtocolSimulator(TestCase):
    def setUp(self):
        self.emitter_address = "33"*20
        self.wallet = Mock()
        self.protocol = HSM1ProtocolSimulator(
            self.wallet,
            999_999_999_999,  # Very fast so we don't need to mock 'time.sleep'
        )

    @patch("simulator.protocol_v1.is_authorized_signing_path")
    def test_get_pubkey(self, is_authorized_signing_path_mock):
        is_authorized_signing_path_mock.return_value = True
        the_key = Mock()
        self.wallet.get.return_value = the_key
        the_key.public_key.return_value = "this-is-the-public-key"

        self.assertEqual(
            {
                "errorcode": 0,
                "pubKey": "this-is-the-public-key"
            },
            self.protocol.handle_request({
                "version": 1,
                "command": "getPubKey",
                "keyId": "m/44'/0'/0'/0/0"
            }),
        )
        self.assertEqual(
            is_authorized_signing_path_mock.call_args_list,
            [call(BIP32Path("m/44'/0'/0'/0/0"))],
        )
        self.assertEqual(self.wallet.get.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertEqual(the_key.public_key.call_args_list, [call()])

    @patch("simulator.protocol_v1.is_authorized_signing_path")
    def test_get_pubkey_unauthorized_keyid(self, is_authorized_signing_path_mock):
        is_authorized_signing_path_mock.return_value = False

        self.assertEqual(
            {"errorcode": -2},
            self.protocol.handle_request({
                "version": 1,
                "command": "getPubKey",
                "keyId": "m/44'/0'/0'/0/0"
            }),
        )
        self.assertEqual(
            is_authorized_signing_path_mock.call_args_list,
            [call(BIP32Path("m/44'/0'/0'/0/0"))],
        )
        self.assertFalse(self.wallet.get.called)

    @patch("simulator.protocol_v1.is_auth_requiring_path")
    @patch("simulator.protocol_v1.is_authorized_signing_path")
    def test_sign_ok(self, is_authorized_signing_path_mock, is_auth_requiring_path_mock):
        is_authorized_signing_path_mock.return_value = True
        is_auth_requiring_path_mock.return_value = False
        the_key = Mock()
        self.wallet.get.return_value = the_key
        the_key.sign.return_value = {"r": "this-is-r", "s": "this-is-s"}

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
                "keyId": "m/44'/137'/0'/0/0",
                "message": "bb"*32,
            }),
        )

        self.assertEqual(is_authorized_signing_path_mock.call_args_list,
                         [call("m/44'/137'/0'/0/0")])
        self.assertEqual(is_auth_requiring_path_mock.call_args_list,
                         [call("m/44'/137'/0'/0/0")])
        self.assertEqual(self.wallet.get.call_args_list, [call("m/44'/137'/0'/0/0")])
        self.assertEqual(the_key.sign.call_args_list, [call("bb"*32)])

    @patch("simulator.protocol_v1.is_auth_requiring_path")
    @patch("simulator.protocol_v1.is_authorized_signing_path")
    def test_sign_signing_wallet_keyget_error(self, is_authorized_signing_path_mock,
                                              is_auth_requiring_path_mock):
        is_authorized_signing_path_mock.return_value = True
        is_auth_requiring_path_mock.return_value = False
        self.wallet.get.side_effect = ValueError()

        self.assertEqual(
            {"errorcode": -2},
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/44'/137'/0'/0/0",
                "message": "bb"*32,
            }),
        )
        self.assertEqual(is_authorized_signing_path_mock.call_args_list,
                         [call("m/44'/137'/0'/0/0")])
        self.assertEqual(is_auth_requiring_path_mock.call_args_list,
                         [call("m/44'/137'/0'/0/0")])
        self.assertEqual(self.wallet.get.call_args_list, [call("m/44'/137'/0'/0/0")])

    @patch("simulator.protocol_v1.is_auth_requiring_path")
    @patch("simulator.protocol_v1.is_authorized_signing_path")
    def test_sign_signing_wallet_sign_error(self, is_authorized_signing_path_mock,
                                            is_auth_requiring_path_mock):
        is_authorized_signing_path_mock.return_value = True
        is_auth_requiring_path_mock.return_value = False
        the_key = Mock()
        self.wallet.get.return_value = the_key
        the_key.sign.side_effect = ValueError()

        self.assertEqual(
            {"errorcode": -2},
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/44'/137'/0'/0/0",
                "message": "bb"*32,
            }),
        )
        self.assertEqual(is_authorized_signing_path_mock.call_args_list,
                         [call("m/44'/137'/0'/0/0")])
        self.assertEqual(is_auth_requiring_path_mock.call_args_list,
                         [call("m/44'/137'/0'/0/0")])
        self.assertEqual(self.wallet.get.call_args_list, [call("m/44'/137'/0'/0/0")])
        self.assertEqual(the_key.sign.call_args_list, [call("bb"*32)])

    @patch("simulator.protocol_v1.is_auth_requiring_path")
    @patch("simulator.protocol_v1.is_authorized_signing_path")
    def test_sign_authrequiring_keyid(self, is_authorized_signing_path_mock,
                                      is_auth_requiring_path_mock):
        is_authorized_signing_path_mock.return_value = True
        is_auth_requiring_path_mock.return_value = True

        self.assertEqual(
            {"errorcode": -2},
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/44'/0'/0'/0/0",
                "message": "aa"*32,
            }),
        )
        self.assertEqual(is_authorized_signing_path_mock.call_args_list,
                         [call("m/44'/0'/0'/0/0")])
        self.assertFalse(self.wallet.get.called)

    @patch("simulator.protocol_v1.is_authorized_signing_path")
    def test_sign_unauthorized_keyid(self, is_authorized_signing_path_mock):
        is_authorized_signing_path_mock.return_value = False

        self.assertEqual(
            {"errorcode": -2},
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/44'/0'/0'/0/0",
                "message": "aa"*32,
            }),
        )
        self.assertEqual(is_authorized_signing_path_mock.call_args_list,
                         [call("m/44'/0'/0'/0/0")])
        self.assertFalse(self.wallet.get.called)

    @patch("simulator.protocol_v1.is_auth_requiring_path")
    @patch("simulator.protocol_v1.is_authorized_signing_path")
    def test_sign_message_invalid(self, is_authorized_signing_path_mock,
                                  is_auth_requiring_path_mock):
        self.assertEqual(
            {"errorcode": -2},
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/44'/137'/0'/0/0",
                "message": 123,
            }),
        )

        self.assertFalse(is_authorized_signing_path_mock.called)
        self.assertFalse(is_auth_requiring_path_mock.called)
        self.assertFalse(self.wallet.get.called)
