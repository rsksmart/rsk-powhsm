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

from unittest.mock import Mock, patch, call
from parameterized import parameterized
from tests.ledger.test_hsm2dongle import TestHSM2DongleBase, HSM2DongleTestMode
from ledger.hsm2dongle import (
    HSM2DongleError,
    SighashComputationMode,
)
from ledgerblue.commException import CommException

import logging

logging.disable(logging.CRITICAL)


class TestHSM2DongleSignAuthorizedLegacy(TestHSM2DongleBase):
    def setUp(self):
        super().setUp()

        self.LEGACY_SPEC = {
            "exchanges": [
                "q-path >02 01 11223344 D2040000",
                "a-tx0  <02 02 0C",
                "q-tx0  >02 02 0F000000 00 0000 AABBCCDDEE",
                "a-tx1  <02 02 03",
                "q-tx1  >02 02 FF7788",
                "a-rc0  <02 04 04",
                "q-rc0  >02 04 00112233",
                "a-rc1  <02 04 06",
                "q-rc1  >02 04 445566778899",
                "a-mp0  <02 08 04",
                "q-mp0  >02 08 03 03 3344",
                "a-mp1  <02 08 03",
                "q-mp1  >02 08 55 02 66",
                "a-mp2  <02 08 07",
                "q-mp2  >02 08 77 05 aabbccddee",
                "a-sig  <02 81 AABBCCDD",
            ],
            "mode": SighashComputationMode.LEGACY,
            "tx": "aabbccddeeff7788",
            "input": 1234,
            "ws": None,
            "ov": None,
            "receipt": "00112233445566778899",
            "mp": ["334455", "6677", "aabbccddee"],
        }

    @patch("ledger.hsm2dongle.HSM2DongleSignature")
    def test_ok(self, HSM2DongleSignatureMock):
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        spec = self.process_sign_auth_spec({**self.LEGACY_SPEC, "keyid": key_id})
        HSM2DongleSignatureMock.return_value = "the-signature"

        self.assertEqual(
            (True, "the-signature"),
            self.do_sign_auth(spec)
        )
        self.assert_exchange(spec["requests"])
        self.assertEqual(
            [call(bytes.fromhex("aabbccdd"))],
            HSM2DongleSignatureMock.call_args_list,
        )

    @parameterized.expand([
        ("data_size", 0x6A87, -4),
        ("state", 0x6A89, -4),
        ("node_version", 0x6A92, -4),
        ("shared_prefix_too_big", 0x6A93, -4),
        ("receipt_hash_mismatch", 0x6A94, -4),
        ("node_chaining_mismatch", 0x6A95, -4),
        ("receipt_root_mismatch", 0x6A96, -4),
        ("unknown", 0x6AFF, -10),
        ("unexpected", [0, 0, 0xFF], -10),
    ])
    def test_mp_invalid(self, _, device_error, expected_response):
        if type(device_error) == int:
            last_response = CommException("msg", device_error)
        else:
            last_response = bytes(device_error)

        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        spec = self.process_sign_auth_spec(
            {**self.LEGACY_SPEC, "keyid": key_id},
            stop="a-mp2",
            replace=last_response
        )

        self.assertEqual(
            (False, expected_response),
            self.do_sign_auth(spec)
        )
        self.assert_exchange(spec["requests"])

    @parameterized.expand([
        ("too_many_nodes", ["aa"]*256),
        ("node_too_big", ["aa"]*100 + ["bb"*256]),
    ])
    def test_mp_too_big(self, _, receipt_merkle_proof):
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        spec = self.process_sign_auth_spec(
            {**self.LEGACY_SPEC, "keyid": key_id, "mp": receipt_merkle_proof},
            stop="q-mp0"
        )

        self.assertEqual(
            (False, -4),
            self.do_sign_auth(spec)
        )
        self.assert_exchange(spec["requests"])

    def test_mp_unexpected_exc(self):
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        spec = self.process_sign_auth_spec(
            {**self.LEGACY_SPEC, "keyid": key_id},
            stop="a-mp2",
            replace=CommException("msg", 0xFFFF),
        )

        with self.assertRaises(HSM2DongleError):
            self.do_sign_auth(spec)

        self.assert_exchange(spec["requests"])

    def test_mp_invalid_format(self):
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        spec = self.process_sign_auth_spec(
            {**self.LEGACY_SPEC, "keyid": key_id, "mp": ["334455", "6677", "not-a-hex"]},
            stop="q-mp0",
            replace=None,
        )

        self.assertEqual(
            (False, -4),
            self.do_sign_auth(spec)
        )

        self.assert_exchange(spec["requests"])

    @parameterized.expand([
        ("data_size", 0x6A87, -3),
        ("state", 0x6A89, -3),
        ("rlp", 0x6A8A, -3),
        ("rlp_int", 0x6A8B, -3),
        ("rlp_depth", 0x6A8C, -3),
        ("unknown", 0x6AFF, -10),
        ("unexpected", [0, 0, 0xFF], -10),
    ])
    def test_receipt_invalid(self, _, device_error, expected_response):
        if type(device_error) == int:
            last_response = CommException("msg", device_error)
        else:
            last_response = bytes(device_error)
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        spec = self.process_sign_auth_spec(
            {**self.LEGACY_SPEC, "keyid": key_id},
            stop="a-rc1",
            replace=last_response
        )

        self.assertEqual(
            (False, expected_response),
            self.do_sign_auth(spec)
        )
        self.assert_exchange(spec["requests"])

    def test_receipt_unexpected_error_exc(self):
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        spec = self.process_sign_auth_spec(
            {**self.LEGACY_SPEC, "keyid": key_id},
            stop="a-rc1",
            replace=CommException("", 0xFFFF)
        )

        with self.assertRaises(HSM2DongleError):
            self.do_sign_auth(spec)
        self.assert_exchange(spec["requests"])

    @parameterized.expand([
        ("input", 0x6A88, -2),
        ("tx_hash_mismatch", 0x6A8D, -2),
        ("tx_version", 0x6A8E, -2),
        ("invalid_sighash_computation_mode", 0x6A97, -2),
        ("unknown", 0x6AFF, -10),
        ("unexpected", [0, 0, 0xFF], -10),
    ])
    def test_btctx_invalid(self, _, device_error, expected_response):
        if type(device_error) == int:
            last_response = CommException("msg", device_error)
        else:
            last_response = bytes(device_error)

        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        spec = self.process_sign_auth_spec(
            {**self.LEGACY_SPEC, "keyid": key_id},
            stop="a-tx1",
            replace=last_response
        )

        self.assertEqual(
            (False, expected_response),
            self.do_sign_auth(spec)
        )
        self.assert_exchange(spec["requests"])

    def test_btctx_unexpected_error_exc(self):
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        spec = self.process_sign_auth_spec(
            {**self.LEGACY_SPEC, "keyid": key_id},
            stop="a-rc0",
            replace=CommException("", 0xFF)
        )

        with self.assertRaises(HSM2DongleError):
            self.do_sign_auth(spec)
        self.assert_exchange(spec["requests"])

    @parameterized.expand([
        ("data_size", 0x6A87, -1),
        ("data_size_auth", 0x6A90, -1),
        ("data_size_noauth", 0x6A91, -1),
        ("unknown", 0x6AFF, -10),
        ("unexpected", [0, 0, 0xFF], -10),
    ])
    def test_path_invalid(self, _, device_error, expected_response):
        if type(device_error) == int:
            last_response = CommException("msg", device_error)
        else:
            last_response = bytes(device_error)

        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        spec = self.process_sign_auth_spec(
            {**self.LEGACY_SPEC, "keyid": key_id},
            stop="a-tx0",
            replace=last_response
        )

        self.assertEqual(
            (False, expected_response),
            self.do_sign_auth(spec)
        )

    def test_path_unexpected_error_exc(self):
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        spec = self.process_sign_auth_spec(
            {**self.LEGACY_SPEC, "keyid": key_id},
            stop="a-tx0",
            replace=CommException("", 0xFFFF)
        )

        with self.assertRaises(HSM2DongleError):
            self.do_sign_auth(spec)


class TestHSM2DongleSGXSignAuthorizedLegacy(TestHSM2DongleSignAuthorizedLegacy):
    def get_test_mode(self):
        return HSM2DongleTestMode.SGX
