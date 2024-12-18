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
from admin.certificate_v1 import HSMCertificate
from admin.certificate_v2 import HSMCertificateV2, HSMCertificateV2Element, \
                                 HSMCertificateV2ElementSGXQuote, \
                                 HSMCertificateV2ElementSGXAttestationKey, \
                                 HSMCertificateV2ElementX509
from .test_certificate_v2_resources import TEST_CERTIFICATE


class TestHSMCertificateV2(TestCase):
    def test_behavior_inherited(self):
        self.assertTrue(issubclass(HSMCertificateV2, HSMCertificate))

    def test_create_empty_certificate_ok(self):
        cert = HSMCertificateV2()
        self.assertEqual({'version': 2, 'targets': [], 'elements': []}, cert.to_dict())

    def test_parse_identity(self):
        cert = HSMCertificateV2(TEST_CERTIFICATE)
        self.assertEqual(TEST_CERTIFICATE, cert.to_dict())


class TestHSMCertificateV2Element(TestCase):
    def test_from_dict_unknown_type(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2Element.from_dict({
                "name": "a-strange-name",
                "type": "an-unknown-type",
                "some": "other",
                "random": "attributes",
            })
        self.assertIn("a-strange-name", str(e.exception))

    def test_from_dict_no_name(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2Element.from_dict({
                "type": "sgx_quote",
                "signed_by": "a-signer",
                "some": "other",
                "random": "attributes",
            })
        self.assertIn("Missing name", str(e.exception))

    def test_from_dict_no_signed_by(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2Element.from_dict({
                "name": "a name",
                "type": "sgx_quote",
                "some": "other",
                "random": "attributes",
            })
        self.assertIn("Missing certifier", str(e.exception))


class TestHSMCertificateV2ElementSGXQuote(TestCase):
    def setUp(self):
        self.elem = HSMCertificateV2ElementSGXQuote({
            "name": "thename",
            "message": "aabbcc",
            "custom_data": "ddeeff",
            "signature": "112233",
            "signed_by": "whosigned",
        })

    def test_props(self):
        self.assertEqual("thename", self.elem.name)
        self.assertEqual("whosigned", self.elem.signed_by)
        self.assertEqual("aabbcc", self.elem.message)
        self.assertEqual("ddeeff", self.elem.custom_data)
        self.assertEqual("112233", self.elem.signature)

    def test_dict_ok(self):
        self.assertEqual({
            "name": "thename",
            "type": "sgx_quote",
            "message": "aabbcc",
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
                "message": "aabbccdd",
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
                "message": "aabbccdd",
                "custom_data": "112233",
                "signature": "not-hex",
                "signed_by": "attestation"
            })
        self.assertIn("Invalid signature", str(e.exception))


class TestHSMCertificateV2ElementSGXAttestationKey(TestCase):
    def setUp(self):
        self.elem = HSMCertificateV2ElementSGXAttestationKey({
            "name": "thename",
            "message": "aabbcc",
            "key": "ddeeff",
            "auth_data": "112233",
            "signature": "44556677",
            "signed_by": "whosigned",
        })

    def test_props(self):
        self.assertEqual("thename", self.elem.name)
        self.assertEqual("whosigned", self.elem.signed_by)
        self.assertEqual("aabbcc", self.elem.message)
        self.assertEqual("ddeeff", self.elem.key)
        self.assertEqual("112233", self.elem.auth_data)
        self.assertEqual("44556677", self.elem.signature)

    def test_dict_ok(self):
        self.assertEqual({
            "name": "thename",
            "type": "sgx_attestation_key",
            "message": "aabbcc",
            "key": "ddeeff",
            "auth_data": "112233",
            "signature": "44556677",
            "signed_by": "whosigned",
        }, self.elem.to_dict())

    def test_parse_identity(self):
        source = TEST_CERTIFICATE["elements"][1]
        elem = HSMCertificateV2Element.from_dict(source)
        self.assertTrue(isinstance(elem, HSMCertificateV2ElementSGXAttestationKey))
        self.assertEqual(source, elem.to_dict())

    def test_from_dict_invalid_message(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2Element.from_dict({
                "name": "attestation",
                "type": "sgx_attestation_key",
                "message": "not-hex",
                "key": "eeff",
                "auth_data": "112233",
                "signature": "44556677",
                "signed_by": "quoting_enclave"
            })
        self.assertIn("Invalid message", str(e.exception))

    def test_from_dict_invalid_key(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2Element.from_dict({
                "name": "attestation",
                "type": "sgx_attestation_key",
                "message": "aabbccdd",
                "key": "not-hex",
                "auth_data": "112233",
                "signature": "44556677",
                "signed_by": "quoting_enclave"
            })
        self.assertIn("Invalid key", str(e.exception))

    def test_from_dict_invalid_auth_data(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2Element.from_dict({
                "name": "attestation",
                "type": "sgx_attestation_key",
                "message": "aabbccdd",
                "key": "eeff",
                "auth_data": "not-hex",
                "signature": "44556677",
                "signed_by": "quoting_enclave"
            })
        self.assertIn("Invalid auth data", str(e.exception))

    def test_from_dict_invalid_signature(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2Element.from_dict({
                "name": "attestation",
                "type": "sgx_attestation_key",
                "message": "aabbccdd",
                "key": "eeff",
                "auth_data": "112233",
                "signature": "not-hex",
                "signed_by": "quoting_enclave"
            })
        self.assertIn("Invalid signature", str(e.exception))


class TestHSMCertificateV2ElementX509(TestCase):
    def setUp(self):
        self.elem = HSMCertificateV2ElementX509({
            "name": "thename",
            "message": "dGhpcyBpcyBhbiBhc2NpaSBtZXNzYWdl",
            "signed_by": "whosigned",
        })

    def test_props(self):
        self.assertEqual("thename", self.elem.name)
        self.assertEqual("whosigned", self.elem.signed_by)
        self.assertEqual("dGhpcyBpcyBhbiBhc2NpaSBtZXNzYWdl", self.elem.message)

    def test_dict_ok(self):
        self.assertEqual({
            "name": "thename",
            "type": "x509_pem",
            "message": "dGhpcyBpcyBhbiBhc2NpaSBtZXNzYWdl",
            "signed_by": "whosigned",
        }, self.elem.to_dict())

    def test_parse_identity(self):
        source = TEST_CERTIFICATE["elements"][3]
        elem = HSMCertificateV2Element.from_dict(source)
        self.assertTrue(isinstance(elem, HSMCertificateV2ElementX509))
        self.assertEqual(source, elem.to_dict())

    def test_from_dict_invalid_message(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2Element.from_dict({
                "name": "quoting_enclave",
                "type": "x509_pem",
                "message": "not-base-64",
                "signed_by": "platform_ca"
            })
        self.assertIn("Invalid message", str(e.exception))
