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

from ..test_hsm2dongle import _TestHSM2DongleBase
from ledger.hsm2dongle import HSM2DongleBaseError
from ledger.signature import HSM2DongleSignature
from ledgerblue.commException import CommException

import logging

logging.disable(logging.CRITICAL)


class TestHSM2SignerHeartbeat(_TestHSM2DongleBase):
    SIG = "3046022100e4c30ef37a1228a2faf2a88c8fb52a1dfe006a222d0961" \
          "c43792018481d0d5e2022100b206abd9c8a46336f9684a84083613fb" \
          "e4d31c34f7c023e5716545a00a709318"

    def test_ok(self):
        self.dongle.exchange.side_effect = [
            b"",
            bytes.fromhex("aabbcc" + self.SIG),
            bytes.fromhex("ddeeff00112233445566778899"),
            bytes.fromhex("001122aabbccddeeff"),
            bytes.fromhex("ffffffddddddccccbb"),
        ]

        self.assertEqual((True, {
            "pubKey": "ddddddccccbb",
            "message": "00112233445566778899",
            "tweak": "aabbccddeeff",
            "signature": HSM2DongleSignature(bytes.fromhex(self.SIG))
        }), self.hsm2dongle.get_signer_heartbeat("1133557799aa"))

        self.assert_exchange([
            bytes.fromhex("60011133557799aa"),
            bytes.fromhex("6002"),
            bytes.fromhex("6003"),
            bytes.fromhex("6004"),
            bytes.fromhex("6005"),
        ])

    def test_error_result(self):
        self.dongle.exchange.side_effect = [
            b"",
            bytes.fromhex("aabbcc" + self.SIG),
            CommException("an-error-result", 0x6b01)
        ]

        self.assertEqual((False,), self.hsm2dongle.get_signer_heartbeat("1133557799aa"))

        self.assert_exchange([
            bytes.fromhex("60011133557799aa"),
            bytes.fromhex("6002"),
            bytes.fromhex("6003"),
        ])

    def test_exception(self):
        self.dongle.exchange.side_effect = [
            b"",
            CommException("an-exception")
        ]

        with self.assertRaises(HSM2DongleBaseError):
            self.hsm2dongle.get_signer_heartbeat("1133557799aa")

        self.assert_exchange([
            bytes.fromhex("60011133557799aa"),
            bytes.fromhex("6002"),
        ])
