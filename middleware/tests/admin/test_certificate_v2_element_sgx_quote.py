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

import ecdsa
import hashlib
from unittest import TestCase
from unittest.mock import Mock
from sgx.envelope import SgxQuote
from admin.certificate_v2 import HSMCertificateV2Element, \
                                 HSMCertificateV2ElementSGXQuote
from .test_certificate_v2_resources import TEST_CERTIFICATE


class TestHSMCertificateV2ElementSGXQuote(TestCase):
    TEST_MESSAGE = \
        "03000200000000000a000f00939a7233f79c4ca9940a0db3957f0607ceae3549bc7273eb34d562f"\
        "4564fc182000000000e0e100fffff01000000000000000000010000000000000000000000000000"\
        "000000000000000000000000000000000005000000000000000700000000000000d32688d3c1f3d"\
        "fcc8b0b36eac7c89d49af331800bd56248044166fa6699442c10000000000000000000000000000"\
        "000000000000000000000000000000000000718c2f1a0efbd513e016fafd6cf62a624442f2d8370"\
        "8d4b33ab5a8d8c1cd4dd00000000000000000000000000000000000000000000000000000000000"\
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000"\
        "0000000000000000000000000000000000000000000000000000000640001000000000000000000"\
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000"\
        "00000000000000000000000005d53b30e22f66979d36721e10ab7722557257a9ef8ba77ec7fe430"\
        "493c3542f90000000000000000000000000000000000000000000000000000000000000000"

    def setUp(self):
        self.elem = HSMCertificateV2ElementSGXQuote({
            "name": "thename",
            "message": self.TEST_MESSAGE,
            "custom_data": "ddeeff",
            "signature": "112233",
            "signed_by": "whosigned",
        })

    def test_props(self):
        self.assertEqual("thename", self.elem.name)
        self.assertEqual("whosigned", self.elem.signed_by)
        self.assertIsInstance(self.elem.message, SgxQuote)
        self.assertEqual(bytes.fromhex(self.TEST_MESSAGE),
                         self.elem.message.get_raw_data())
        self.assertEqual("ddeeff", self.elem.custom_data)
        self.assertEqual("112233", self.elem.signature)

    def test_dict_ok(self):
        self.assertEqual({
            "name": "thename",
            "type": "sgx_quote",
            "message": self.TEST_MESSAGE,
            "custom_data": "ddeeff",
            "signature": "112233",
            "signed_by": "whosigned",
        }, self.elem.to_dict())

    def test_parse_identity(self):
        source = TEST_CERTIFICATE["elements"][0]
        elem = HSMCertificateV2Element.from_dict(source)
        self.assertTrue(isinstance(elem, HSMCertificateV2ElementSGXQuote))
        self.assertEqual(source, elem.to_dict())

    def test_from_dict_invalid_message(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2Element.from_dict({
                "name": "quote",
                "type": "sgx_quote",
                "message": "not-hex",
                "custom_data": "112233",
                "signature": "445566778899",
                "signed_by": "attestation"
            })
        self.assertIn("Invalid message", str(e.exception))

    def test_from_dict_invalid_custom_data(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2Element.from_dict({
                "name": "quote",
                "type": "sgx_quote",
                "message": self.TEST_MESSAGE,
                "custom_data": "not-hex",
                "signature": "445566778899",
                "signed_by": "attestation"
            })
        self.assertIn("Invalid custom data", str(e.exception))

    def test_from_dict_invalid_signature(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2Element.from_dict({
                "name": "quote",
                "type": "sgx_quote",
                "message": self.TEST_MESSAGE,
                "custom_data": "112233",
                "signature": "not-hex",
                "signed_by": "attestation"
            })
        self.assertIn("Invalid signature", str(e.exception))

    def test_get_pubkey_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.elem.get_pubkey()

    def test_is_valid_ok(self):
        pk = ecdsa.SigningKey.generate(ecdsa.NIST256p)
        certifier = Mock()
        certifier.get_pubkey.return_value = pk.verifying_key

        valid_elem = HSMCertificateV2ElementSGXQuote({
            "name": "thename",
            "message": self.TEST_MESSAGE,
            "custom_data": "10061982",
            "signature": pk.sign_digest(
                hashlib.sha256(bytes.fromhex(self.TEST_MESSAGE)).digest(),
                sigencode=ecdsa.util.sigencode_der
            ).hex(),
            "signed_by": "whosigned",
        })
        self.assertTrue(valid_elem.is_valid(certifier))

    def test_is_valid_custom_data_mismatch(self):
        pk = ecdsa.SigningKey.generate(ecdsa.NIST256p)
        certifier = Mock()
        certifier.get_pubkey.return_value = pk.verifying_key

        valid_elem = HSMCertificateV2ElementSGXQuote({
            "name": "thename",
            "message": self.TEST_MESSAGE,
            "custom_data": "11061982",
            "signature": pk.sign_digest(
                hashlib.sha256(bytes.fromhex(self.TEST_MESSAGE)).digest(),
                sigencode=ecdsa.util.sigencode_der
            ).hex(),
            "signed_by": "whosigned",
        })
        self.assertFalse(valid_elem.is_valid(certifier))

    def test_is_valid_signature_mismatch(self):
        pk = ecdsa.SigningKey.generate(ecdsa.NIST256p)
        certifier = Mock()
        certifier.get_pubkey.return_value = pk.verifying_key

        valid_elem = HSMCertificateV2ElementSGXQuote({
            "name": "thename",
            "message": self.TEST_MESSAGE,
            "custom_data": "10061982",
            "signature": pk.sign_digest(
                hashlib.sha256(b"something else").digest(),
                sigencode=ecdsa.util.sigencode_der
            ).hex(),
            "signed_by": "whosigned",
        })
        self.assertFalse(valid_elem.is_valid(certifier))

    def test_get_collateral_none(self):
        self.assertIsNone(self.elem.get_collateral())
