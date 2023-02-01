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
from ledger.protocol import HSM2ProtocolLedger
from ledger.hsm2dongle import (
    HSM2Dongle,
    HSM2DongleError,
    HSM2DongleErrorResult,
    HSM2DongleTimeoutError,
    HSM2DongleCommError,
    HSM2FirmwareParameters
)
from ledger.version import HSM2FirmwareVersion

import logging

logging.disable(logging.CRITICAL)


class TestHSM2ProtocolLedger(TestCase):
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
        self.protocol = HSM2ProtocolLedger(self.pin, self.dongle)
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
                "version": 4,
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
            {"errorcode": -103},
            self.protocol.handle_request({
                "version": 4,
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
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
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
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "getPubKey",
                "keyId": "m/44'/1'/2'/3/4"
            }),
        )
        self.assertEqual([call("the-key-id")], self.dongle.get_public_key.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

        # Reconnection logic testing
        self.dongle.get_public_key.side_effect = None
        self.dongle.get_public_key.return_value = "this-is-the-public-key"

        self.assertEqual(
            {
                "errorcode": 0,
                "pubKey": "this-is-the-public-key"
            },
            self.protocol.handle_request({
                "version": 4,
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
                "version": 4,
                "command": "getPubKey",
                "keyId": "m/44'/1'/2'/3/4"
            })

        self.assertEqual([call("the-key-id")], self.dongle.get_public_key.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

    @patch("ledger.protocol.get_tx_hash")
    @patch("ledger.protocol.get_unsigned_tx")
    @patch("comm.protocol.BIP32Path")
    def test_sign_authorized_ok(self, BIP32PathMock, get_unsigned_tx_mock, _):
        BIP32PathMock.return_value = "the-key-id"
        signature = Mock(r="this-is-r", s="this-is-s")
        self.dongle.sign_authorized.return_value = (True, signature)
        get_unsigned_tx_mock.return_value = "the-unsigned-tx"

        self.assertEqual(
            {
                "errorcode": 0,
                "signature": {
                    "r": "this-is-r",
                    "s": "this-is-s"
                }
            },
            self.protocol.handle_request({
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "auth": {
                    "receipt": "aa",
                    "receipt_merkle_proof": ["cc", "dd"]
                },
                "message": {
                    "tx": "eeff",
                    "input": 12
                },
            }),
        )

        self.assertEqual(
            [
                call(
                    key_id="the-key-id",
                    rsk_tx_receipt="aa",
                    receipt_merkle_proof=["cc", "dd"],
                    btc_tx="the-unsigned-tx",
                    input_index=12,
                )
            ],
            self.dongle.sign_authorized.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    @parameterized.expand([
        ("path", -1, -103),
        ("btc_tx", -2, -102),
        ("receipt", -3, -101),
        ("merkle_proof", -4, -101),
        ("unexpected", -10, -905),
        ("unknown", -100, -906),
    ])
    @patch("ledger.protocol.get_tx_hash")
    @patch("ledger.protocol.get_unsigned_tx")
    @patch("comm.protocol.BIP32Path")
    def test_sign_authorized_error(
        self,
        _,
        dongle_error_code,
        protocol_error_code,
        BIP32PathMock,
        get_unsigned_tx_mock,
        __,
    ):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.sign_authorized.return_value = (False, dongle_error_code)
        get_unsigned_tx_mock.return_value = "the-unsigned-tx"

        self.assertEqual(
            {"errorcode": protocol_error_code},
            self.protocol.handle_request({
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "auth": {
                    "receipt": "aa",
                    "receipt_merkle_proof": ["cc", "dd"]
                },
                "message": {
                    "tx": "eeff",
                    "input": 12
                },
            }),
        )

        self.assertEqual(
            [
                call(
                    key_id="the-key-id",
                    rsk_tx_receipt="aa",
                    receipt_merkle_proof=["cc", "dd"],
                    btc_tx="the-unsigned-tx",
                    input_index=12,
                )
            ],
            self.dongle.sign_authorized.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    @patch("ledger.protocol.get_tx_hash")
    @patch("ledger.protocol.get_unsigned_tx")
    @patch("comm.protocol.BIP32Path")
    def test_sign_authorized_timeout(self, BIP32PathMock, get_unsigned_tx_mock, _):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.sign_authorized.side_effect = HSM2DongleTimeoutError()
        get_unsigned_tx_mock.return_value = "the-unsigned-tx"

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "auth": {
                    "receipt": "aa",
                    "receipt_merkle_proof": ["cc", "dd"]
                },
                "message": {
                    "tx": "eeff",
                    "input": 12
                },
            }),
        )

        self.assertEqual(
            [
                call(
                    key_id="the-key-id",
                    rsk_tx_receipt="aa",
                    receipt_merkle_proof=["cc", "dd"],
                    btc_tx="the-unsigned-tx",
                    input_index=12,
                )
            ],
            self.dongle.sign_authorized.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    @patch("ledger.protocol.get_tx_hash")
    @patch("ledger.protocol.get_unsigned_tx")
    @patch("comm.protocol.BIP32Path")
    def test_sign_authorized_commerror_reconnection(self, BIP32PathMock,
                                                    get_unsigned_tx_mock, _):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.sign_authorized.side_effect = HSM2DongleCommError()
        get_unsigned_tx_mock.return_value = "the-unsigned-tx"

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "auth": {
                    "receipt": "aa",
                    "receipt_merkle_proof": ["cc", "dd"]
                },
                "message": {
                    "tx": "eeff",
                    "input": 12
                },
            }),
        )

        self.assertEqual(
            [
                call(
                    key_id="the-key-id",
                    rsk_tx_receipt="aa",
                    receipt_merkle_proof=["cc", "dd"],
                    btc_tx="the-unsigned-tx",
                    input_index=12,
                )
            ],
            self.dongle.sign_authorized.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

        # Reconnection logic
        self.dongle.sign_authorized.side_effect = None
        signature = Mock(r="this-is-r", s="this-is-s")
        self.dongle.sign_authorized.return_value = (True, signature)

        self.assertEqual(
            {
                "errorcode": 0,
                "signature": {
                    "r": "this-is-r",
                    "s": "this-is-s"
                }
            },
            self.protocol.handle_request({
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "auth": {
                    "receipt": "aa",
                    "receipt_merkle_proof": ["cc", "dd"]
                },
                "message": {
                    "tx": "eeff",
                    "input": 12
                },
            }),
        )

        self._assert_reconnected()

    @patch("ledger.protocol.get_tx_hash")
    @patch("ledger.protocol.get_unsigned_tx")
    @patch("comm.protocol.BIP32Path")
    def test_sign_authorized_exception(self, BIP32PathMock, get_unsigned_tx_mock, _):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.sign_authorized.side_effect = HSM2DongleError()
        get_unsigned_tx_mock.return_value = "the-unsigned-tx"

        with self.assertRaises(HSM2ProtocolError):
            self.protocol.handle_request({
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "auth": {
                    "receipt": "aa",
                    "receipt_merkle_proof": ["cc", "dd"]
                },
                "message": {
                    "tx": "eeff",
                    "input": 12
                },
            })

        self.assertEqual(
            [
                call(
                    key_id="the-key-id",
                    rsk_tx_receipt="aa",
                    receipt_merkle_proof=["cc", "dd"],
                    btc_tx="the-unsigned-tx",
                    input_index=12,
                )
            ],
            self.dongle.sign_authorized.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    @patch("ledger.protocol.get_tx_hash")
    @patch("ledger.protocol.get_unsigned_tx")
    @patch("comm.protocol.BIP32Path")
    def test_sign_authorized_error_unsigning(self, BIP32PathMock, get_unsigned_tx_mock,
                                             _):
        BIP32PathMock.return_value = "the-key-id"
        get_unsigned_tx_mock.side_effect = RuntimeError()

        self.assertEqual(
            {"errorcode": -102},
            self.protocol.handle_request({
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "auth": {
                    "receipt": "aa",
                    "receipt_merkle_proof": ["cc", "dd"]
                },
                "message": {
                    "tx": "eeff",
                    "input": 12
                },
            }),
        )

        self.assertFalse(self.dongle.sign_authorized.called)
        self.assertFalse(self.dongle.disconnect.called)

    @patch("ledger.protocol.get_tx_hash")
    @patch("ledger.protocol.get_unsigned_tx")
    @patch("comm.protocol.BIP32Path")
    def test_sign_authorized_message_invalid(self, BIP32PathMock, get_unsigned_tx_mock,
                                             _):
        BIP32PathMock.return_value = "the-key-id"

        self.assertEqual(
            {"errorcode": -102},
            self.protocol.handle_request({
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "auth": {
                    "receipt": "aa",
                    "receipt_merkle_proof": ["cc", "dd"]
                },
                "message": {
                    "tx": "invalid",
                    "input": 12
                },
            }),
        )

        self.assertFalse(self.dongle.sign_authorized.called)
        self.assertFalse(get_unsigned_tx_mock.called)
        self.assertFalse(self.dongle.disconnect.called)

    @patch("ledger.protocol.get_tx_hash")
    @patch("ledger.protocol.get_unsigned_tx")
    @patch("comm.protocol.BIP32Path")
    def test_sign_authorized_auth_invalid(self, BIP32PathMock, get_unsigned_tx_mock, _):
        BIP32PathMock.return_value = "the-key-id"

        self.assertEqual(
            {"errorcode": -101},
            self.protocol.handle_request({
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "auth": {
                    "receipt": "not-a-hex",
                    "receipt_merkle_proof": ["cc", "dd"],
                },
                "message": {
                    "tx": "eeff",
                    "input": 12
                },
            }),
        )

        self.assertFalse(self.dongle.sign_authorized.called)
        self.assertFalse(get_unsigned_tx_mock.called)
        self.assertFalse(self.dongle.disconnect.called)

    @patch("comm.protocol.BIP32Path")
    def test_sign_unauthorized_ok(self, BIP32PathMock):
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
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "message": {
                    "hash": "aa"*32
                },
            }),
        )

        self.assertEqual(
            [call(key_id="the-key-id", hash="aa"*32)],
            self.dongle.sign_unauthorized.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    @parameterized.expand([
        ("path", -1, -103),
        ("hash", -5, -102),
        ("unexpected", -10, -905),
        ("unknown", -100, -906),
    ])
    @patch("comm.protocol.BIP32Path")
    def test_sign_unauthorized_error(self, _, dongle_error_code, protocol_error_code,
                                     BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.sign_unauthorized.return_value = (False, dongle_error_code)

        self.assertEqual(
            {"errorcode": protocol_error_code},
            self.protocol.handle_request({
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "message": {
                    "hash": "aa"*32
                },
            }),
        )

        self.assertEqual(
            [call(key_id="the-key-id", hash="aa"*32)],
            self.dongle.sign_unauthorized.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    @patch("comm.protocol.BIP32Path")
    def test_sign_unauthorized_timeout(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.sign_unauthorized.side_effect = HSM2DongleTimeoutError()

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "message": {
                    "hash": "aa"*32
                },
            }),
        )

        self.assertEqual(
            [call(key_id="the-key-id", hash="aa"*32)],
            self.dongle.sign_unauthorized.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    @patch("comm.protocol.BIP32Path")
    def test_sign_unauthorized_commerror_reconnection(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.sign_unauthorized.side_effect = HSM2DongleCommError()

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "message": {
                    "hash": "aa"*32
                },
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
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "message": {
                    "hash": "aa"*32
                },
            }),
        )

        self._assert_reconnected()

    @patch("comm.protocol.BIP32Path")
    def test_sign_unauthorized_exception(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"
        self.dongle.sign_unauthorized.side_effect = HSM2DongleError()

        with self.assertRaises(HSM2ProtocolError):
            self.protocol.handle_request({
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "message": {
                    "hash": "aa"*32
                },
            })

        self.assertEqual(
            [call(key_id="the-key-id", hash="aa"*32)],
            self.dongle.sign_unauthorized.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    @patch("comm.protocol.BIP32Path")
    def test_sign_unauthorized_message_invalid(self, BIP32PathMock):
        BIP32PathMock.return_value = "the-key-id"

        self.assertEqual(
            {"errorcode": -102},
            self.protocol.handle_request({
                "version": 4,
                "command": "sign",
                "keyId": "m/44'/1'/2'/3/4",
                "message": {
                    "hash": "not-a-hexadecimal-string"
                },
            }),
        )

        self.assertFalse(self.dongle.sign_unauthorized.called)
        self.assertFalse(self.dongle.disconnect.called)

    def test_blockchain_state_ok(self):
        self.dongle.get_blockchain_state.return_value = {
            "best_block": "the-best-block",
            "newest_valid_block": "the-newest_valid_block",
            "ancestor_block": "the-ancestor-block",
            "ancestor_receipts_root": "the-ancestor-receipts-root",
            "updating.best_block": "the-updating-best-block",
            "updating.newest_valid_block": "the-updating-newest-valid-block",
            "updating.next_expected_block": "the-updating-next-expected-block",
            "updating.total_difficulty": "total-difficulty",
            "updating.in_progress": "is-in-progress",
            "updating.already_validated": "is-already-validated",
            "updating.found_best_block": "have-found-best-block",
        }

        self.assertEqual(
            {
                "errorcode": 0,
                "state": {
                    "best_block": "the-best-block",
                    "newest_valid_block": "the-newest_valid_block",
                    "ancestor_block": "the-ancestor-block",
                    "ancestor_receipts_root": "the-ancestor-receipts-root",
                    "updating": {
                        "best_block": "the-updating-best-block",
                        "newest_valid_block": "the-updating-newest-valid-block",
                        "next_expected_block": "the-updating-next-expected-block",
                        "total_difficulty": "total-difficulty",
                        "in_progress": "is-in-progress",
                        "already_validated": "is-already-validated",
                        "found_best_block": "have-found-best-block",
                    },
                },
            },
            self.protocol.handle_request({
                "version": 4,
                "command": "blockchainState"
            }),
        )

        self.assertEqual([call()], self.dongle.get_blockchain_state.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

    def test_blockchain_state_dongle_exception(self):
        self.dongle.get_blockchain_state.side_effect = HSM2DongleError("an-error")

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "blockchainState"
            }),
        )

        self.assertEqual([call()], self.dongle.get_blockchain_state.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

    def test_blockchain_state_dongle_timeout(self):
        self.dongle.get_blockchain_state.side_effect = HSM2DongleTimeoutError()

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "blockchainState"
            }),
        )

        self.assertEqual([call()], self.dongle.get_blockchain_state.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

    def test_blockchain_state_dongle_commerror_reconnection(self):
        self.dongle.get_blockchain_state.side_effect = HSM2DongleCommError()

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "blockchainState"
            }),
        )

        self.assertEqual([call()], self.dongle.get_blockchain_state.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

        # Reconnection logic
        self.dongle.get_blockchain_state.side_effect = None
        self.dongle.get_blockchain_state.return_value = {
            "best_block": "the-best-block",
            "newest_valid_block": "the-newest_valid_block",
            "ancestor_block": "the-ancestor-block",
            "ancestor_receipts_root": "the-ancestor-receipts-root",
            "updating.best_block": "the-updating-best-block",
            "updating.newest_valid_block": "the-updating-newest-valid-block",
            "updating.next_expected_block": "the-updating-next-expected-block",
            "updating.total_difficulty": "total-difficulty",
            "updating.in_progress": "is-in-progress",
            "updating.already_validated": "is-already-validated",
            "updating.found_best_block": "have-found-best-block",
        }

        self.assertEqual(
            {
                "errorcode": 0,
                "state": {
                    "best_block": "the-best-block",
                    "newest_valid_block": "the-newest_valid_block",
                    "ancestor_block": "the-ancestor-block",
                    "ancestor_receipts_root": "the-ancestor-receipts-root",
                    "updating": {
                        "best_block": "the-updating-best-block",
                        "newest_valid_block": "the-updating-newest-valid-block",
                        "next_expected_block": "the-updating-next-expected-block",
                        "total_difficulty": "total-difficulty",
                        "in_progress": "is-in-progress",
                        "already_validated": "is-already-validated",
                        "found_best_block": "have-found-best-block",
                    },
                },
            },
            self.protocol.handle_request({
                "version": 4,
                "command": "blockchainState"
            }),
        )

        self._assert_reconnected()

    def test_reset_advance_blockchain_ok(self):
        self.assertEqual(
            {"errorcode": 0},
            self.protocol.handle_request({
                "version": 4,
                "command": "resetAdvanceBlockchain"
            }),
        )

        self.assertEqual([call()], self.dongle.reset_advance_blockchain.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

    def test_reset_advance_blockchain_dongle_timeout(self):
        self.dongle.reset_advance_blockchain.side_effect = HSM2DongleTimeoutError()

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "resetAdvanceBlockchain"
            }),
        )

        self.assertEqual([call()], self.dongle.reset_advance_blockchain.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

    def test_reset_advance_blockchain_dongle_commerror_reconnection(self):
        self.dongle.reset_advance_blockchain.side_effect = HSM2DongleCommError()

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "resetAdvanceBlockchain"
            }),
        )

        self.assertEqual([call()], self.dongle.reset_advance_blockchain.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

        # Reconnection logic
        self.dongle.reset_advance_blockchain.side_effect = None

        self.assertEqual(
            {"errorcode": 0},
            self.protocol.handle_request({
                "version": 4,
                "command": "resetAdvanceBlockchain"
            }),
        )

        self._assert_reconnected()

    def test_reset_advance_blockchain_dongle_exception(self):
        self.dongle.reset_advance_blockchain.side_effect = HSM2DongleError("an-error")

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "resetAdvanceBlockchain"
            }),
        )

        self.assertEqual([call()], self.dongle.reset_advance_blockchain.call_args_list)
        self.assertFalse(self.dongle.disconnect.called)

    @parameterized.expand([
        ("success", (True, 1), 0),
        ("partial_success", (True, 2), 1),
        ("init", (False, -1), -905),
        ("compute_metadata", (False, -2), -204),
        ("metadata", (False, -3), -905),
        ("block_data", (False, -4), -905),
        ("invalid_block", (False, -5), -204),
        ("pow_invalid", (False, -6), -202),
        ("chaining_mismatch", (False, -7), -201),
        ("unsupported_chain", (False, -8), -204),
        ("invalid_brothers", (False, -9), -205),
        ("unexpected", (False, -10), -906),
        ("unknown", (False, 999), -906),
    ])
    def test_advance_blockchain_mapping(self, _, response, expected_code):
        self.dongle.advance_blockchain.return_value = response
        self.assertEqual(
            {"errorcode": expected_code},
            self.protocol.handle_request({
                "version": 4,
                "command": "advanceBlockchain",
                "blocks": ["aabbcc", "ddeeff"],
                "brothers": [["b11"], ["b21", "b22"]],
            }),
        )

        self.assertEqual(
            [call(
                ["aabbcc", "ddeeff"],
                [["b11"], ["b21", "b22"]],
            )],
            self.dongle.advance_blockchain.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    def test_advance_blockchain_timeout(self):
        self.dongle.advance_blockchain.side_effect = HSM2DongleTimeoutError()

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "advanceBlockchain",
                "blocks": ["aabbcc", "ddeeff"],
                "brothers": [["b11", "b12", "b13"], ["b21", "b22"]],
            }),
        )

        self.assertEqual(
            [call(
                ["aabbcc", "ddeeff"],
                [["b11", "b12", "b13"], ["b21", "b22"]],
            )],
            self.dongle.advance_blockchain.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    def test_advance_blockchain_commerror_reconnection(self):
        self.dongle.advance_blockchain.side_effect = HSM2DongleCommError()

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "advanceBlockchain",
                "blocks": ["aabbcc", "ddeeff"],
                "brothers": [["b11", "b12", "b13"], ["b21", "b22"]],
            }),
        )

        self.assertEqual(
            [call(
                ["aabbcc", "ddeeff"],
                [["b11", "b12", "b13"], ["b21", "b22"]],
            )],
            self.dongle.advance_blockchain.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

        # Reconnection logic
        self.dongle.advance_blockchain.side_effect = None
        self.dongle.advance_blockchain.return_value = (True, 1)
        self.assertEqual(
            {"errorcode": 0},
            self.protocol.handle_request({
                "version": 4,
                "command": "advanceBlockchain",
                "blocks": ["aabbcc", "ddeeff"],
                "brothers": [["b11", "b12", "b13"], ["b21", "b22"]],
            }),
        )

        self._assert_reconnected()

    def test_advance_blockchain_exception(self):
        self.dongle.advance_blockchain.side_effect = HSM2DongleError("a-message")

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "advanceBlockchain",
                "blocks": ["aabbcc", "ddeeff"],
                "brothers": [["b11", "b12", "b13"], ["b21", "b22"]],
            }),
        )

        self.assertEqual(
            [call(
                ["aabbcc", "ddeeff"],
                [["b11", "b12", "b13"], ["b21", "b22"]],
            )],
            self.dongle.advance_blockchain.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    @parameterized.expand([
        ("success", (True, 1), 0),
        ("init", (False, -1), -905),
        ("compute_metadata", (False, -2), -204),
        ("metadata", (False, -3), -905),
        ("block_data", (False, -4), -905),
        ("invalid_block", (False, -5), -204),
        ("chaining_mismatch", (False, -6), -201),
        ("tip_mismatch", (False, -7), -203),
        ("remove_mm_fields", (False, -8), -204),
        ("unexpected", (False, -10), -906),
        ("unknown", (False, 999), -906),
    ])
    def test_update_ancestor_mapping(self, _, response, expected_code):
        self.dongle.update_ancestor.return_value = response
        self.assertEqual(
            {"errorcode": expected_code},
            self.protocol.handle_request({
                "version": 4,
                "command": "updateAncestorBlock",
                "blocks": ["aabbcc", "ddeeff"],
            }),
        )

        self.assertEqual(
            [call(["aabbcc", "ddeeff"])],
            self.dongle.update_ancestor.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    def test_update_ancestor_timeout(self):
        self.dongle.update_ancestor.side_effect = HSM2DongleTimeoutError()

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "updateAncestorBlock",
                "blocks": ["aabbcc", "ddeeff"],
            }),
        )

        self.assertEqual(
            [call(["aabbcc", "ddeeff"])],
            self.dongle.update_ancestor.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    def test_update_ancestor_commerror_reconnection(self):
        self.dongle.update_ancestor.side_effect = HSM2DongleCommError()

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "updateAncestorBlock",
                "blocks": ["aabbcc", "ddeeff"],
            }),
        )

        self.assertEqual(
            [call(["aabbcc", "ddeeff"])],
            self.dongle.update_ancestor.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

        # Reconnection logic
        self.dongle.update_ancestor.side_effect = None
        self.dongle.update_ancestor.return_value = (True, 1)
        self.assertEqual(
            {"errorcode": 0},
            self.protocol.handle_request({
                "version": 4,
                "command": "updateAncestorBlock",
                "blocks": ["aabbcc", "ddeeff"],
            }),
        )

        self._assert_reconnected()

    def test_update_ancestor_exception(self):
        self.dongle.update_ancestor.side_effect = HSM2DongleError("a-message")

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "updateAncestorBlock",
                "blocks": ["aabbcc", "ddeeff"],
            }),
        )

        self.assertEqual(
            [call(["aabbcc", "ddeeff"])],
            self.dongle.update_ancestor.call_args_list,
        )
        self.assertFalse(self.dongle.disconnect.called)

    def test_get_blockchain_parameters_ok(self):
        self.dongle.get_signer_parameters.return_value = HSM2FirmwareParameters(
            0x32,
            "the-checkpoint",
            HSM2FirmwareParameters.Network.MAINNET
        )

        self.assertEqual(
            {
                "errorcode": 0,
                "parameters": {
                    "checkpoint": "the-checkpoint",
                    "minimum_difficulty": 0x32,
                    "network": "mainnet",
                },
            },
            self.protocol.handle_request({
                "version": 4,
                "command": "blockchainParameters"
            }),
        )

    def test_get_blockchain_parameters_dongle_timeout(self):
        self.dongle.get_signer_parameters.side_effect = HSM2DongleTimeoutError()

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "blockchainParameters"
            }),
        )

    def test_get_blockchain_parameters_exception(self):
        self.dongle.get_signer_parameters.side_effect = HSM2DongleError("a-message")

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "blockchainParameters"
            }),
        )

    def test_signer_heartbeat_ok(self):
        self.dongle.get_signer_heartbeat.side_effect = lambda ud: (True, {
            "pubKey": "66778899",
            "message": "aabbccdd" + ud,
            "signature": Mock(r="this-is-r", s="this-is-s"),
            "tweak": "1122334455",
        })

        self.assertEqual(
            {
                "errorcode": 0,
                "pubKey": "66778899",
                "message": "aabbccdd" + "77"*16,
                "tweak": "1122334455",
                "signature": {
                    "r": "this-is-r",
                    "s": "this-is-s",
                },
            },
            self.protocol.handle_request({
                "version": 4,
                "command": "signerHeartbeat",
                "udValue": "77"*16,
            }),
        )

    def test_signer_heartbeat_dongle_error(self):
        self.dongle.get_signer_heartbeat.return_value = (False, )

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "signerHeartbeat",
                "udValue": "99"*16,
            }),
        )

    def test_signer_heartbeat_dongle_timeout(self):
        self.dongle.get_signer_heartbeat.side_effect = HSM2DongleTimeoutError()

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "signerHeartbeat",
                "udValue": "11"*16,
            }),
        )

    def test_signer_heartbeat_exception(self):
        self.dongle.get_signer_heartbeat.side_effect = HSM2DongleError("a-message")

        self.assertEqual(
            {"errorcode": -905},
            self.protocol.handle_request({
                "version": 4,
                "command": "signerHeartbeat",
                "udValue": "22"*16,
            }),
        )

    @patch("time.sleep")
    def test_ui_heartbeat_from_signer_ok(self, sleep_mock):
        self.dongle.get_current_mode.side_effect = [
            self.dongle.MODE.SIGNER,
            self.dongle.MODE.UI_HEARTBEAT,
            self.dongle.MODE.SIGNER,
        ]

        self.dongle.exit_app.side_effect = [
            HSM2DongleCommError(""),
            HSM2DongleCommError(""),
        ]

        self.dongle.get_ui_heartbeat.side_effect = lambda ud: (True, {
            "pubKey": "66778899",
            "message": "aabbccdd" + ud,
            "signature": Mock(r="this-is-r", s="this-is-s"),
            "tweak": "1122334455",
        })

        self.assertEqual(
            {
                "errorcode": 0,
                "pubKey": "66778899",
                "message": "aabbccdd" + "77"*32,
                "tweak": "1122334455",
                "signature": {
                    "r": "this-is-r",
                    "s": "this-is-s",
                },
            },
            self.protocol.handle_request({
                "version": 4,
                "command": "uiHeartbeat",
                "udValue": "77"*32,
            }),
        )

    @patch("time.sleep")
    def test_ui_heartbeat_exit_signer_error(self, sleep_mock):
        self.dongle.get_current_mode.return_value = self.dongle.MODE.SIGNER

        self.dongle.exit_app.side_effect = HSM2DongleError("")

        self.assertEqual({"errorcode": -905},
                         self.protocol.handle_request({
                             "version": 4,
                             "command": "uiHeartbeat",
                             "udValue": "77"*32,
                         }))

    @patch("time.sleep")
    def test_ui_heartbeat_from_signer_no_ui_heartbeat(self, sleep_mock):
        self.dongle.get_current_mode.side_effect = [
            self.dongle.MODE.SIGNER,
            self.dongle.MODE.BOOTLOADER,
        ]

        self.dongle.exit_app.side_effect = HSM2DongleCommError("")

        self.assertEqual({"errorcode": -905},
                         self.protocol.handle_request({
                             "version": 4,
                             "command": "uiHeartbeat",
                             "udValue": "77"*32,
                         }))

    @patch("time.sleep")
    def test_ui_heartbeat_from_signer_hb_error(self, sleep_mock):
        self.dongle.get_current_mode.side_effect = [
            self.dongle.MODE.SIGNER,
            self.dongle.MODE.UI_HEARTBEAT,
        ]

        self.dongle.exit_app.side_effect = HSM2DongleCommError("")
        self.dongle.get_ui_heartbeat.side_effect = HSM2DongleError("")

        self.assertEqual({"errorcode": -905},
                         self.protocol.handle_request({
                             "version": 4,
                             "command": "uiHeartbeat",
                             "udValue": "77"*32,
                         }))

        self.assertTrue(self.dongle.get_ui_heartbeat.called)

    @patch("time.sleep")
    def test_ui_heartbeat_from_signer_hb_error_result(self, sleep_mock):
        self.dongle.get_current_mode.side_effect = [
            self.dongle.MODE.SIGNER,
            self.dongle.MODE.UI_HEARTBEAT,
            self.dongle.MODE.SIGNER,
        ]

        self.dongle.exit_app.side_effect = [
            HSM2DongleCommError(""),
            HSM2DongleCommError(""),
        ]

        self.dongle.get_ui_heartbeat.return_value = (False, )

        self.assertEqual({"errorcode": -905},
                         self.protocol.handle_request({
                             "version": 4,
                             "command": "uiHeartbeat",
                             "udValue": "77"*32,
                         }))

        self.assertTrue(self.dongle.get_ui_heartbeat.called)

    @patch("time.sleep")
    def test_ui_heartbeat_from_signer_back_to_signer_error(self, sleep_mock):
        self.dongle.get_current_mode.side_effect = [
            self.dongle.MODE.SIGNER,
            self.dongle.MODE.UI_HEARTBEAT,
        ]

        self.dongle.exit_app.side_effect = [
            HSM2DongleCommError(""),
            HSM2DongleError(""),
        ]

        self.dongle.get_ui_heartbeat.side_effect = lambda ud: (True, {
            "pubKey": "66778899",
            "message": "aabbccdd" + ud,
            "signature": Mock(r="this-is-r", s="this-is-s"),
            "tweak": "1122334455",
        })

        self.assertEqual({"errorcode": -905},
                         self.protocol.handle_request({
                             "version": 4,
                             "command": "uiHeartbeat",
                             "udValue": "77"*32,
                         }))

        self.assertTrue(self.dongle.get_ui_heartbeat.called)

    @patch("time.sleep")
    def test_ui_heartbeat_from_signer_no_back_to_signer(self, sleep_mock):
        self.dongle.get_current_mode.side_effect = [
            self.dongle.MODE.SIGNER,
            self.dongle.MODE.UI_HEARTBEAT,
            self.dongle.MODE.UI_HEARTBEAT,
        ]

        self.dongle.exit_app.side_effect = [
            HSM2DongleCommError(""),
            HSM2DongleCommError(""),
        ]

        self.dongle.get_ui_heartbeat.side_effect = lambda ud: (True, {
            "pubKey": "66778899",
            "message": "aabbccdd" + ud,
            "signature": Mock(r="this-is-r", s="this-is-s"),
            "tweak": "1122334455",
        })

        self.assertEqual({"errorcode": -905},
                         self.protocol.handle_request({
                             "version": 4,
                             "command": "uiHeartbeat",
                             "udValue": "77"*32,
                         }))

        self.assertTrue(self.dongle.get_ui_heartbeat.called)

    @patch("time.sleep")
    def test_ui_heartbeat_from_invalid_start_mode(self, sleep_mock):
        self.dongle.get_current_mode.return_value = self.dongle.MODE.BOOTLOADER

        self.assertEqual({"errorcode": -905},
                         self.protocol.handle_request({
                             "version": 4,
                             "command": "uiHeartbeat",
                             "udValue": "77"*32,
                         }))

    def test_ui_heartbeat_from_hb_ok(self):
        self.dongle.get_current_mode.return_value = self.dongle.MODE.UI_HEARTBEAT

        self.dongle.get_ui_heartbeat.side_effect = lambda ud: (True, {
            "pubKey": "66778899",
            "message": "aabbccdd" + ud,
            "signature": Mock(r="this-is-r", s="this-is-s"),
            "tweak": "1122334455",
        })

        self.assertEqual(
            {
                "errorcode": 0,
                "pubKey": "66778899",
                "message": "aabbccdd" + "77"*32,
                "tweak": "1122334455",
                "signature": {
                    "r": "this-is-r",
                    "s": "this-is-s",
                },
            },
            self.protocol.handle_request({
                "version": 4,
                "command": "uiHeartbeat",
                "udValue": "77"*32,
            }),
        )

        self.assertFalse(self.dongle.exit_app.called)

    def test_ui_heartbeat_from_hb_hb_error(self):
        self.dongle.get_current_mode.return_value = self.dongle.MODE.UI_HEARTBEAT

        self.dongle.get_ui_heartbeat.side_effect = HSM2DongleError()

        self.assertEqual({"errorcode": -905},
                         self.protocol.handle_request({
                             "version": 4,
                             "command": "uiHeartbeat",
                             "udValue": "77"*32,
                         }))

        self.assertFalse(self.dongle.exit_app.called)

    def test_ui_heartbeat_from_hb_hb_error_result(self):
        self.dongle.get_current_mode.return_value = self.dongle.MODE.UI_HEARTBEAT

        self.dongle.get_ui_heartbeat.return_value = (False, )

        self.assertEqual({"errorcode": -905},
                         self.protocol.handle_request({
                             "version": 4,
                             "command": "uiHeartbeat",
                             "udValue": "77"*32,
                         }))

        self.assertFalse(self.dongle.exit_app.called)

    def _assert_reconnected(self):
        self.assertTrue(self.dongle.disconnect.called)
        self.assertEqual(2, self.dongle.connect.call_count)
