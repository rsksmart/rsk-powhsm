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
from ledger.signature import HSM2DongleSignature

import logging

logging.disable(logging.CRITICAL)


class TestHSM2DongleSignature(TestCase):
    def test_signature_1(self):
        bs = bytes.fromhex(
            "3045022100e719a1a379143ee7b598390305f4f1a991d6e26f175545c739f89728e270671"
            "402207fcc41e525508a27bdcf9bd82f4b75709e8771dde714d0cf3d362056ed1bb07c9000"
        )
        expected_r = "00e719a1a379143ee7b598390305f4f1a991d6e26f175545c739f89728e2706714"
        expected_s = "7fcc41e525508a27bdcf9bd82f4b75709e8771dde714d0cf3d362056ed1bb07c"
        signature = HSM2DongleSignature(bs)
        self.assertEqual(expected_r, signature.r)
        self.assertEqual(expected_s, signature.s)

    def test_signature_2(self):
        bs = bytes.fromhex(
            "3145022100f48d30ae4f01925939116c6b74c1c9afefc6d1a0b7109307a68126f3683308f"
            "502206cec3ea71687eaf367885b44ec58daab06ff43c68a0817eb2177193218573cae9000"
        )
        expected_r = "00f48d30ae4f01925939116c6b74c1c9afefc6d1a0b7109307a68126f3683308f5"
        expected_s = "6cec3ea71687eaf367885b44ec58daab06ff43c68a0817eb2177193218573cae"
        signature = HSM2DongleSignature(bs)
        self.assertEqual(expected_r, signature.r)
        self.assertEqual(expected_s, signature.s)

    def test_signature_invalid(self):
        cases = list(
            map(
                lambda h: bytes.fromhex(h),
                [
                    "",
                    "21",  # Not long enough
                    "302230",  # Length invalid
                    "300d0205aabbccddee0203112233",  # Invalid total length
                    "300c0305aabbccddee0203112233",  # Invalid R number prefix
                    "300c0205aabbccddee0303112233",  # Invalid S number prefix
                    "ff0c0205aabbccddee0203112233",  # Invalid DER prefix
                ],
            ))
        for bs in cases:
            with self.assertRaises(ValueError):
                HSM2DongleSignature(bs)

    def test_equal(self):
        bs = bytes.fromhex(
            "3145022100f48d30ae4f01925939116c6b74c1c9afefc6d1a0b7109307a68126f3683308f"
            "502206cec3ea71687eaf367885b44ec58daab06ff43c68a0817eb2177193218573cae9000"
        )
        sig1 = HSM2DongleSignature(bs)
        sig2 = HSM2DongleSignature(bs)
        self.assertEqual(sig1, sig2)

    def test_not_equal(self):
        bs1 = bytes.fromhex(
            "3145022100f48d30ae4f01925939116c6b74c1c9afefc6d1a0b7109307a68126f3683308f"
            "502206cec3ea71687eaf367885b44ec58daab06ff43c68a0817eb2177193218573cae9000"
        )
        bs2 = bytes.fromhex(
            "3045022100e719a1a379143ee7b598390305f4f1a991d6e26f175545c739f89728e270671"
            "402207fcc41e525508a27bdcf9bd82f4b75709e8771dde714d0cf3d362056ed1bb07c9000"
        )
        sig1 = HSM2DongleSignature(bs1)
        sig2 = HSM2DongleSignature(bs2)
        self.assertNotEqual(sig1, sig2)
