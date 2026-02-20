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
from ledger.hsm2dongle import HSM2DongleError
from ledgerblue.commException import CommException

import logging

logging.disable(logging.CRITICAL)


class TestHSM2DongleSignAuthorized(TestHSM2DongleBase):
    def setUp(self):
        super().setUp()

        self.SPEC = {
            "exchanges": [
                "q-path >02 01 11223344 D2040000",
                "a-tx0  <02 02 0B",
                "q-tx0  >02 02 0E000000 0E00 AABBCCDDEE",
                "a-tx1  <02 02 03",
                "q-tx1  >02 02 FF7788",
                "a-tx2  <02 02 05",
                "q-tx2  >02 02 0522446688",
                "a-tx3  <02 02 09",
                "q-tx3  >02 02 AA 992C0A0000000000",
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
            "tx": "aabbccddeeff7788",
            "input": 1234,
            "ws": "22446688aa",
            "ov": 666777,
            "receipt": "00112233445566778899",
            "mp": ["334455", "6677", "aabbccddee"],
        }

    @patch("ledger.hsm2dongle.HSM2DongleSignature")
    def test_ok(self, HSM2DongleSignatureMock):
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        spec = self.process_sign_auth_spec({**self.SPEC, "keyid": key_id})
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

    def test_long_witness_script_length(self):
        exchanges = [
                "q-path >02 01 11223344 D2040000",
                "a-tx0  <02 02 0B",
                "q-tx0  >02 02 0E000000 0D01 AABBCCDDEE",
                "a-tx1  <02 02 03",
                "q-tx1  >02 02 FF7788",
                "a-tx2  <02 02 08",
                "q-tx2  >02 02 FD0201 0001020304",
                "a-tx3  <FF",
        ]
        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        spec = self.process_sign_auth_spec({
                **self.SPEC, "exchanges": exchanges,
                "keyid": key_id, "ws": self.buf(258).hex()
            }, stop="a-tx3", replace=CommException("forced-stop", 0xFFFF)
        )

        with self.assertRaises(HSM2DongleError):
            self.do_sign_auth(spec)
        self.assert_exchange(spec["requests"])

    @parameterized.expand([
        ("input", "a-tx1", 0x6A88, -2),
        ("tx_hash_mismatch", "a-tx3", 0x6A8D, -2),
        ("tx_version", "a-tx2", 0x6A8E, -2),
        ("invalid_extradata_size", "a-tx1", 0x6A97, -2),
        ("unknown", "a-tx2", 0x6AFF, -10),
        ("unexpected", "a-tx3", [0, 0, 0xFF], -10),
    ])
    def test_btctx_invalid(self, _, stop, device_error, expected_response):
        if type(device_error) == int:
            last_response = CommException("msg", device_error)
        else:
            last_response = bytes(device_error)

        key_id = Mock(**{"to_binary.return_value": bytes.fromhex("11223344")})
        spec = self.process_sign_auth_spec(
            {**self.SPEC, "keyid": key_id},
            stop=stop,
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
            {**self.SPEC, "keyid": key_id},
            stop="a-tx2",
            replace=CommException("", 0xFF)
        )

        with self.assertRaises(HSM2DongleError):
            self.do_sign_auth(spec)
        self.assert_exchange(spec["requests"])


class TestHSM2DongleSGXSignAuthorized(TestHSM2DongleSignAuthorized):
    def get_test_mode(self):
        return HSM2DongleTestMode.SGX
