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

from ..test_hsm2dongle import TestHSM2DongleBase
from ledger.hsm2dongle import HSM2DongleErrorResult, HSM2DongleError
from ledgerblue.commException import CommException

import logging

logging.disable(logging.CRITICAL)


class TestPowHsmAttestation(TestHSM2DongleBase):
    SIG = "3046022100e4c30ef37a1228a2faf2a88c8fb52a1dfe006a222d0961" \
          "c43792018481d0d5e2022100b206abd9c8a46336f9684a84083613fb" \
          "e4d31c34f7c023e5716545a00a709318"

    def test_ok(self):
        self.dongle.exchange.side_effect = [
            bytes.fromhex("aabbcc" + self.SIG),
            bytes.fromhex("aabbcc01112233445566778899"),
            bytes.fromhex("aabbcc00aabbccddeeff"),
            bytes.fromhex("aabbcc0112345678"),
            bytes.fromhex("aabbcc019abcdef0"),
            bytes.fromhex("aabbcc001122334455"),
            bytes.fromhex("aabbcc334455667788aabbccdd"),
        ]

        self.assertEqual({
            "message": "112233445566778899aabbccddeeff",
            "envelope": "123456789abcdef01122334455",
            "app_hash": "334455667788aabbccdd",
            "signature": self.SIG,
        }, self.hsm2dongle.get_powhsm_attestation("aa" + "bb"*30 + "cc"))

        self.assert_exchange([
            bytes.fromhex("5001aa" + "bb"*30 + "cc"),
            bytes.fromhex("500200"),
            bytes.fromhex("500201"),
            bytes.fromhex("500400"),
            bytes.fromhex("500401"),
            bytes.fromhex("500402"),
            bytes.fromhex("5003"),
        ])

    def test_legacy_ok(self):
        self.dongle.exchange.side_effect = [
            bytes.fromhex("aabbcc" + self.SIG),
            bytes.fromhex("aabbcc") + b"HSM:SIGNER:5.0morestuff",
            bytes.fromhex("aabbcc334455667788aabbccdd"),
        ]

        self.assertEqual({
            "message": b"HSM:SIGNER:5.0morestuff".hex(),
            "envelope": b"HSM:SIGNER:5.0morestuff".hex(),
            "app_hash": "334455667788aabbccdd",
            "signature": self.SIG,
        }, self.hsm2dongle.get_powhsm_attestation("aa" + "bb"*30 + "cc"))

        self.assert_exchange([
            bytes.fromhex("5001aa" + "bb"*30 + "cc"),
            bytes.fromhex("500200"),
            bytes.fromhex("5003"),
        ])

    def test_error_result(self):
        self.dongle.exchange.side_effect = [
            bytes.fromhex("aabbcc" + self.SIG),
            bytes.fromhex("aabbcc01112233445566778899"),
            bytes.fromhex("aabbcc00aabbccddeeff"),
            CommException("an-error-result", 0x6b01)
        ]

        with self.assertRaises(HSM2DongleErrorResult) as e:
            self.hsm2dongle.get_powhsm_attestation("aa" + "bb"*30 + "cc")
        self.assertEqual(e.exception.error_code, 0x6b01)

        self.assert_exchange([
            bytes.fromhex("5001aa" + "bb"*30 + "cc"),
            bytes.fromhex("500200"),
            bytes.fromhex("500201"),
            bytes.fromhex("500400"),
        ])

    def test_exception(self):
        self.dongle.exchange.side_effect = [
            bytes.fromhex("aabbcc" + self.SIG),
            bytes.fromhex("aabbcc01112233445566778899"),
            bytes.fromhex("aabbcc00aabbccddeeff"),
            CommException("an-exception")
        ]

        with self.assertRaises(HSM2DongleError) as e:
            self.hsm2dongle.get_powhsm_attestation("aa" + "bb"*30 + "cc")
        self.assertIn("an-exception", e.exception.message)

        self.assert_exchange([
            bytes.fromhex("5001aa" + "bb"*30 + "cc"),
            bytes.fromhex("500200"),
            bytes.fromhex("500201"),
            bytes.fromhex("500400"),
        ])
