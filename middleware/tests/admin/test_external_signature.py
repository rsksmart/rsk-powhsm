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

import json
import os
import tempfile
from unittest import TestCase
import secp256k1 as ec
from admin.external_signature import (
    parse_external_signature,
    describe_external_signature,
    FORMAT_DER,
    FORMAT_RSV,
    FORMAT_JSON
)
from admin.ledger_utils import encode_eth_message
from admin.utils import keccak_256
from .ecdsa_utils import (
    SECP256K1_N,
    WEB3_PRIVATE_KEY,
    WEB3_ADDRESS,
    WEB3_MESSAGE,
    WEB3_DIGEST,
    WEB3_R,
    WEB3_S,
    der_encode
)

import logging

logging.disable(logging.CRITICAL)

# Hex-encoded r and s of the web3.js test vector signature
R = f"{WEB3_R:064x}"
S = f"{WEB3_S:064x}"
RSV_SIGNATURE = f"0x{R}{S}1c"
EXPECTED_DER = der_encode(WEB3_R, WEB3_S)


def sign_rsv(message):
    # Signs the given message with the test private key, as a wallet would
    private_key = ec.PrivateKey(bytes.fromhex(WEB3_PRIVATE_KEY), raw=True)
    compact_signature, recovery_id = private_key.ecdsa_recoverable_serialize(
        private_key.ecdsa_sign_recoverable(
            keccak_256(encode_eth_message(message)), raw=True))
    return "0x" + compact_signature.hex() + format(27 + recovery_id, "02x")


class TestParseExternalSignatureRsv(TestCase):
    def assert_ok(self, signature, format=FORMAT_RSV):
        self.assertEqual(format, signature.format)
        self.assertEqual(EXPECTED_DER, signature.der_signature)
        self.assertEqual([WEB3_ADDRESS.lower()], signature.signer_addresses)

    def test_v_27_28(self):
        self.assert_ok(parse_external_signature(RSV_SIGNATURE, WEB3_MESSAGE, WEB3_DIGEST))

    def test_v_0_1(self):
        self.assert_ok(parse_external_signature(f"{R}{S}01", WEB3_MESSAGE, WEB3_DIGEST))

    def test_no_prefix_uppercase_and_whitespace(self):
        self.assert_ok(parse_external_signature(
            f"  {R.upper()}{S.upper()}1C\n", WEB3_MESSAGE, WEB3_DIGEST))

    def test_quotes_not_accepted(self):
        with self.assertRaises(ValueError) as e:
            parse_external_signature(f"'{RSV_SIGNATURE}'", WEB3_MESSAGE, WEB3_DIGEST)
        self.assertIn("Supported signature formats", str(e.exception))

    def test_high_s_is_normalized(self):
        high_s = f"{SECP256K1_N - WEB3_S:064x}"
        # Negating s flips the parity of the recovery id
        self.assert_ok(parse_external_signature(f"{R}{high_s}1b",
                                                WEB3_MESSAGE, WEB3_DIGEST))

    def test_expected_signer_address(self):
        self.assert_ok(parse_external_signature(
            RSV_SIGNATURE, WEB3_MESSAGE, WEB3_DIGEST, WEB3_ADDRESS))
        self.assert_ok(parse_external_signature(
            RSV_SIGNATURE, WEB3_MESSAGE, WEB3_DIGEST, WEB3_ADDRESS.lower()[2:]))

    def test_expected_signer_public_key(self):
        pubkey = ec.PrivateKey(bytes.fromhex(WEB3_PRIVATE_KEY), raw=True).pubkey
        for compressed in [True, False]:
            self.assert_ok(parse_external_signature(
                RSV_SIGNATURE, WEB3_MESSAGE, WEB3_DIGEST,
                pubkey.serialize(compressed=compressed).hex()))

    def test_unexpected_signer(self):
        with self.assertRaises(ValueError) as e:
            parse_external_signature(RSV_SIGNATURE,
                                     WEB3_MESSAGE, WEB3_DIGEST, "0x" + "11"*20)
        self.assertIn("not produced by the expected signer", str(e.exception))

    def test_other_message_with_expected_signer(self):
        other_digest = keccak_256(encode_eth_message("Some other data"))
        with self.assertRaises(ValueError) as e:
            parse_external_signature(RSV_SIGNATURE, "Some other data",
                                     other_digest, WEB3_ADDRESS)
        self.assertIn("not produced by the expected signer", str(e.exception))

    def test_invalid_expected_signer(self):
        with self.assertRaises(ValueError) as e:
            parse_external_signature(RSV_SIGNATURE, WEB3_MESSAGE, WEB3_DIGEST, "0x1122")
        self.assertIn("Invalid signer", str(e.exception))

    def test_invalid_v(self):
        with self.assertRaises(ValueError) as e:
            parse_external_signature(f"{R}{S}25", WEB3_MESSAGE, WEB3_DIGEST)
        self.assertIn("Invalid signature v value: 37", str(e.exception))

    def test_invalid_r(self):
        with self.assertRaises(ValueError):
            parse_external_signature(f"{'00'*32}{S}1c", WEB3_MESSAGE, WEB3_DIGEST)

    def test_invalid_hex(self):
        with self.assertRaises(ValueError) as e:
            parse_external_signature("0xnothex", WEB3_MESSAGE, WEB3_DIGEST)
        self.assertIn("Supported signature formats", str(e.exception))

    def test_invalid_length(self):
        with self.assertRaises(ValueError) as e:
            parse_external_signature(f"{R}{S}", WEB3_MESSAGE, WEB3_DIGEST)
        self.assertIn("Supported signature formats", str(e.exception))


class TestParseExternalSignatureDer(TestCase):
    def test_ok(self):
        signature = parse_external_signature(EXPECTED_DER, WEB3_MESSAGE, WEB3_DIGEST)
        self.assertEqual(FORMAT_DER, signature.format)
        self.assertEqual(EXPECTED_DER, signature.der_signature)
        self.assertEqual(2, len(signature.signer_addresses))
        self.assertIn(WEB3_ADDRESS.lower(), signature.signer_addresses)

    def test_prefixed(self):
        signature = parse_external_signature("0x" + EXPECTED_DER,
                                             WEB3_MESSAGE, WEB3_DIGEST)
        self.assertEqual(EXPECTED_DER, signature.der_signature)

    def test_high_s_is_normalized(self):
        high_s_der = der_encode(WEB3_R, SECP256K1_N - WEB3_S)
        signature = parse_external_signature(high_s_der,
                                             WEB3_MESSAGE, WEB3_DIGEST, WEB3_ADDRESS)
        self.assertEqual(EXPECTED_DER, signature.der_signature)

    def test_expected_signer(self):
        signature = parse_external_signature(EXPECTED_DER,
                                             WEB3_MESSAGE, WEB3_DIGEST, WEB3_ADDRESS)
        self.assertEqual(EXPECTED_DER, signature.der_signature)

    def test_unexpected_signer(self):
        with self.assertRaises(ValueError) as e:
            parse_external_signature(EXPECTED_DER,
                                     WEB3_MESSAGE, WEB3_DIGEST, "0x" + "11"*20)
        self.assertIn("not produced by the expected signer", str(e.exception))


class TestParseExternalSignatureJson(TestCase):
    def signed_message(self, **overrides):
        signed_message = {
            "address": WEB3_ADDRESS,
            "msg": "0x" + WEB3_MESSAGE.encode().hex(),
            "sig": RSV_SIGNATURE,
            "version": "3",
            "signer": "MEW",
        }
        signed_message.update(overrides)
        return {k: v for k, v in signed_message.items() if v is not None}

    def assert_ok(self, signature):
        self.assertEqual(FORMAT_JSON, signature.format)
        self.assertEqual(EXPECTED_DER, signature.der_signature)
        self.assertEqual([WEB3_ADDRESS.lower()], signature.signer_addresses)

    def test_inline(self):
        self.assert_ok(parse_external_signature(
            json.dumps(self.signed_message()), WEB3_MESSAGE, WEB3_DIGEST))

    def test_inline_without_address(self):
        self.assert_ok(parse_external_signature(
            json.dumps(self.signed_message(address=None)), WEB3_MESSAGE, WEB3_DIGEST))

    def test_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as file:
            file.write(json.dumps(self.signed_message(), indent=2))
        try:
            self.assert_ok(parse_external_signature(
                file.name, WEB3_MESSAGE, WEB3_DIGEST, WEB3_ADDRESS))
        finally:
            os.remove(file.name)

    def test_message_mismatch(self):
        with self.assertRaises(ValueError) as e:
            parse_external_signature(
                json.dumps(self.signed_message(msg="0x" + b"Other data".hex())),
                WEB3_MESSAGE, WEB3_DIGEST)
        self.assertIn("does not match the expected message", str(e.exception))
        self.assertIn("Signed:   Other data", str(e.exception))

    def test_message_without_hex_prefix(self):
        self.assert_ok(parse_external_signature(
            json.dumps(self.signed_message(msg=WEB3_MESSAGE.encode().hex())),
            WEB3_MESSAGE, WEB3_DIGEST))

    def test_plain_text_message(self):
        self.assert_ok(parse_external_signature(
            json.dumps(self.signed_message(msg=WEB3_MESSAGE)), WEB3_MESSAGE, WEB3_DIGEST))

    def test_plain_text_message_mismatch(self):
        with self.assertRaises(ValueError) as e:
            parse_external_signature(
                json.dumps(self.signed_message(msg="Other data")),
                WEB3_MESSAGE, WEB3_DIGEST)
        self.assertIn("does not match the expected message", str(e.exception))
        self.assertIn("Signed:   Other data", str(e.exception))

    def test_malformed_hex_message(self):
        for msg in ["0x" + WEB3_MESSAGE.encode().hex()[:-1], "0xzz", "0xff"]:
            with self.assertRaises(ValueError) as e:
                parse_external_signature(
                    json.dumps(self.signed_message(msg=msg)), WEB3_MESSAGE, WEB3_DIGEST)
            self.assertIn("does not match the expected message", str(e.exception))
            self.assertIn(f"Signed:   {msg}", str(e.exception))

    def test_hex_looking_plain_text_message(self):
        # A plain text message that is also valid hex
        message = "cafe"
        digest = keccak_256(encode_eth_message(message))
        signature = parse_external_signature(json.dumps(self.signed_message(
            msg=message, sig=sign_rsv(message), address=None)), message, digest)
        self.assertEqual(FORMAT_JSON, signature.format)

    def test_address_mismatch(self):
        with self.assertRaises(ValueError) as e:
            parse_external_signature(
                json.dumps(self.signed_message(address="0x" + "11"*20)),
                WEB3_MESSAGE, WEB3_DIGEST)
        self.assertIn("does not match the signature's signer", str(e.exception))

    def test_unexpected_signer(self):
        with self.assertRaises(ValueError) as e:
            parse_external_signature(
                json.dumps(self.signed_message()),
                WEB3_MESSAGE, WEB3_DIGEST, "0x" + "11"*20)
        self.assertIn("not produced by the expected signer", str(e.exception))

    def test_missing_sig(self):
        with self.assertRaises(ValueError) as e:
            parse_external_signature(
                json.dumps(self.signed_message(sig=None)), WEB3_MESSAGE, WEB3_DIGEST)
        self.assertIn("missing 'sig' field", str(e.exception))

    def test_der_sig_not_allowed(self):
        with self.assertRaises(ValueError) as e:
            parse_external_signature(
                json.dumps(self.signed_message(sig=EXPECTED_DER)),
                WEB3_MESSAGE, WEB3_DIGEST)
        self.assertIn("65-byte", str(e.exception))

    def test_invalid_json(self):
        with self.assertRaises(ValueError) as e:
            parse_external_signature('{"msg": ', WEB3_MESSAGE, WEB3_DIGEST)
        self.assertIn("Invalid signed message JSON", str(e.exception))


class TestDescribeExternalSignature(TestCase):
    def test_single_signer_checked(self):
        signature = parse_external_signature(RSV_SIGNATURE, WEB3_MESSAGE, WEB3_DIGEST)
        self.assertEqual([
            "Signature format: r||s||v",
            f"Signer address: {WEB3_ADDRESS}",
            "Signer matches the expected signer",
        ], describe_external_signature(signature, True))

    def test_der_not_checked(self):
        signature = parse_external_signature(EXPECTED_DER, WEB3_MESSAGE, WEB3_DIGEST)
        lines = describe_external_signature(signature, False)
        self.assertEqual("Signature format: DER", lines[0])
        self.assertIn("one of", lines[1])
        self.assertIn(WEB3_ADDRESS, lines[1])
        self.assertIn("WARNING", lines[2])
