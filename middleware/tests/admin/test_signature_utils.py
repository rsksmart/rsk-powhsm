# The MIT License (MIT)
#
# Copyright (c) 2026 RSK Labs Ltd
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
import ecdsa
from admin.signature_utils import ECDSASignature, assert_signer_not_present
from .ecdsa_utils import (
    SECP256K1_N,
    WEB3_ADDRESS,
    WEB3_DIGEST,
    WEB3_R,
    WEB3_S,
    WEB3_RECOVERY_ID,
    sign,
    unrecoverable_r
)

import logging

logging.disable(logging.CRITICAL)

# Short names for the web3.js test vector signature components
R, S = WEB3_R, WEB3_S
# Recovered addresses are lowercase
ADDRESS = WEB3_ADDRESS.lower()

DER = ecdsa.util.sigencode_der(R, S, SECP256K1_N)
HIGH_S_DER = ecdsa.util.sigencode_der(R, SECP256K1_N - S, SECP256K1_N)
COMPACT = ecdsa.util.sigencode_string(R, S, SECP256K1_N)
HIGH_S_COMPACT = ecdsa.util.sigencode_string(R, SECP256K1_N - S, SECP256K1_N)


def unrecoverable_ecdsa_signature():
    return ECDSASignature.from_compact(
        ecdsa.util.sigencode_string(unrecoverable_r(), 1, SECP256K1_N))


class TestSignatureParsing(TestCase):
    def test_from_der(self):
        signature = ECDSASignature.from_der(DER)
        self.assertEqual(DER, signature.to_der())
        self.assertEqual(COMPACT, signature.to_compact())

    def test_from_der_high_s_kept_as_is(self):
        signature = ECDSASignature.from_der(HIGH_S_DER)
        self.assertEqual(HIGH_S_DER, signature.to_der())
        self.assertEqual(HIGH_S_COMPACT, signature.to_compact())

    def test_from_der_invalid(self):
        for value in [b"", bytes.fromhex("aabbcc"), DER + b"\x00", DER[:-1]]:
            with self.assertRaises(ValueError) as e:
                ECDSASignature.from_der(value)
            self.assertIn("Invalid DER signature", str(e.exception))

    def test_from_compact(self):
        signature = ECDSASignature.from_compact(COMPACT)
        self.assertEqual(COMPACT, signature.to_compact())
        self.assertEqual(DER, signature.to_der())

    def test_from_compact_invalid(self):
        for value in [b"\x01" * 63, b"\x01" * 65,
                      SECP256K1_N.to_bytes(32, "big") + S.to_bytes(32, "big")]:
            with self.assertRaises(ValueError) as e:
                ECDSASignature.from_compact(value)
            self.assertIn("Invalid compact signature", str(e.exception))

    def test_equality(self):
        self.assertEqual(ECDSASignature.from_der(DER),
                         ECDSASignature.from_compact(COMPACT))
        self.assertNotEqual(ECDSASignature.from_der(DER),
                            ECDSASignature.from_der(HIGH_S_DER))
        self.assertEqual(1, len({ECDSASignature.from_der(DER),
                                 ECDSASignature.from_compact(COMPACT)}))


class TestSignatureNormalized(TestCase):
    def test_low_s_unchanged(self):
        signature = ECDSASignature.from_der(DER)
        self.assertEqual(signature, signature.normalized())

    def test_high_s_normalized(self):
        self.assertEqual(ECDSASignature.from_der(DER),
                         ECDSASignature.from_der(HIGH_S_DER).normalized())

    def test_does_not_modify_original(self):
        signature = ECDSASignature.from_der(HIGH_S_DER)
        signature.normalized()
        self.assertEqual(HIGH_S_DER, signature.to_der())


class TestSignatureRecoverSignerAddress(TestCase):
    def test_ok(self):
        self.assertEqual(ADDRESS, ECDSASignature.from_der(DER).recover_signer_address(
            WEB3_RECOVERY_ID, WEB3_DIGEST))

    def test_high_s(self):
        # Negating s flips the parity of the recovery id
        signature = ECDSASignature.from_der(HIGH_S_DER)
        self.assertEqual(ADDRESS, signature.recover_signer_address(
            1 - WEB3_RECOVERY_ID, WEB3_DIGEST))

    def test_other_recovery_id(self):
        self.assertNotEqual(ADDRESS, ECDSASignature.from_der(DER).recover_signer_address(
            1 - WEB3_RECOVERY_ID, WEB3_DIGEST))

    def test_invalid_recovery_id(self):
        with self.assertRaises(ValueError):
            ECDSASignature.from_der(DER).recover_signer_address(4, WEB3_DIGEST)

    def test_unrecoverable(self):
        with self.assertRaises(ValueError) as e:
            unrecoverable_ecdsa_signature().recover_signer_address(0, WEB3_DIGEST)
        self.assertIn("Unable to recover signer", str(e.exception))


class TestSignatureRecoverSignerAddresses(TestCase):
    def test_ok(self):
        addresses = ECDSASignature.from_der(DER).recover_signer_addresses(WEB3_DIGEST)
        self.assertEqual(2, len(addresses))
        self.assertIn(ADDRESS, addresses)
        # Same candidates, in swapped order (negating s flips the recovery ids)
        self.assertEqual(
            set(addresses),
            set(ECDSASignature.from_der(HIGH_S_DER).recover_signer_addresses(
                WEB3_DIGEST)))

    def test_unrecoverable(self):
        self.assertEqual(
            [], unrecoverable_ecdsa_signature().recover_signer_addresses(WEB3_DIGEST))


class TestAssertSignerNotPresent(TestCase):
    def test_no_signatures(self):
        assert_signer_not_present([], ECDSASignature.from_der(DER), WEB3_DIGEST)

    def test_different_signer(self):
        other = ECDSASignature.from_der(bytes.fromhex(sign("11"*32, WEB3_DIGEST)))
        assert_signer_not_present([other, unrecoverable_ecdsa_signature()],
                                  ECDSASignature.from_der(DER), WEB3_DIGEST)

    def test_same_signature(self):
        for der in [DER, HIGH_S_DER]:
            with self.assertRaises(ValueError) as e:
                assert_signer_not_present([ECDSASignature.from_der(DER)],
                                          ECDSASignature.from_der(der), WEB3_DIGEST)
            self.assertIn("A signature by the same signer (one of", str(e.exception))
            self.assertIn("0x2c7536E3605D9C16a7a3D7b1898e529396a65c23", str(e.exception))

    def test_unrecoverable_new_signature(self):
        with self.assertRaises(ValueError) as e:
            assert_signer_not_present([], unrecoverable_ecdsa_signature(), WEB3_DIGEST)
        self.assertIn("unable to recover any signer", str(e.exception))
