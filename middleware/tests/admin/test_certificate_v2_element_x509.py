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
from unittest.mock import Mock, patch
from ecdsa import NIST256p
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from admin.certificate_v2 import HSMCertificateV2Element, \
                                 HSMCertificateV2ElementX509
from .test_certificate_v2_resources import TEST_CERTIFICATE


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

    def test_get_value_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.elem.get_value()

    def test_from_pem(self):
        self.assertEqual({
            "name": "thename",
            "type": "x509_pem",
            "message": "dGhpcyBpcyBhbiBhc2NpaSBtZXNzYWdl",
            "signed_by": "whosigned",
        }, HSMCertificateV2ElementX509.from_pem("""
        -----BEGIN CERTIFICATE-----
        dGhpcyBpcyBhbiBhc2NpaSBtZXNzYWdl
        -----END CERTIFICATE-----
        """, "thename", "whosigned").to_dict())

    @patch("admin.certificate_v2.Path")
    @patch("admin.certificate_v2.HSMCertificateV2ElementX509.from_pem")
    def test_from_pemfile(self, from_pem, Path):
        Path.return_value.read_text.return_value = "the pem contents"
        from_pem.return_value = "the instance"
        self.assertEqual("the instance",
                         HSMCertificateV2ElementX509.from_pemfile("a-file.pem",
                                                                  "the name",
                                                                  "who signed"))
        Path.assert_called_with("a-file.pem")
        from_pem.assert_called_with("the pem contents",
                                    "the name",
                                    "who signed")

    @patch("admin.certificate_v2.x509.load_pem_x509_certificate")
    def test_certificate(self, load_pem_x509_certificate):
        load_pem_x509_certificate.return_value = "mock-certificate"

        self.assertEqual("mock-certificate", self.elem.certificate)
        self.assertEqual("mock-certificate", self.elem.certificate)

        load_pem_x509_certificate.assert_called_with(
            b"-----BEGIN CERTIFICATE-----"
            b"dGhpcyBpcyBhbiBhc2NpaSBtZXNzYWdl"
            b"-----END CERTIFICATE-----"
        )
        self.assertEqual(1, load_pem_x509_certificate.call_count)

    def setup_is_valid_mocks(self, load_pem_x509_certificate, VerifyingKey):
        self.pubkey = Mock()
        self.pubkey.curve = SECP256R1()
        self.pubkey.public_bytes.return_value = "the-public-bytes"
        self.cert = Mock()
        self.cert.public_key.return_value = self.pubkey
        load_pem_x509_certificate.return_value = self.cert
        VerifyingKey.from_string.return_value = "the-expected-pubkey"

    @patch("admin.certificate_v2.ecdsa.VerifyingKey")
    @patch("admin.certificate_v2.x509.load_pem_x509_certificate")
    def test_get_pubkey_ok(self, load_pem_x509_certificate, VerifyingKey):
        self.setup_is_valid_mocks(load_pem_x509_certificate, VerifyingKey)

        self.assertEqual("the-expected-pubkey", self.elem.get_pubkey())
        self.pubkey.public_bytes.assert_called_with(
            Encoding.X962, PublicFormat.CompressedPoint)
        VerifyingKey.from_string.assert_called_with("the-public-bytes", NIST256p)

    @patch("admin.certificate_v2.ecdsa.VerifyingKey")
    @patch("admin.certificate_v2.x509.load_pem_x509_certificate")
    def test_get_pubkey_err_load_cert(self, load_pem_x509_certificate, VerifyingKey):
        self.setup_is_valid_mocks(load_pem_x509_certificate, VerifyingKey)
        load_pem_x509_certificate.side_effect = Exception("blah blah")

        with self.assertRaises(ValueError) as e:
            self.elem.get_pubkey()
        self.assertIn("gathering public key", str(e.exception))
        self.assertIn("blah blah", str(e.exception))
        self.pubkey.public_bytes.assert_not_called()
        VerifyingKey.from_string.assert_not_called()

    @patch("admin.certificate_v2.ecdsa.VerifyingKey")
    @patch("admin.certificate_v2.x509.load_pem_x509_certificate")
    def test_get_pubkey_err_get_pub(self, load_pem_x509_certificate, VerifyingKey):
        self.setup_is_valid_mocks(load_pem_x509_certificate, VerifyingKey)
        self.cert.public_key.side_effect = Exception("blah blah")

        with self.assertRaises(ValueError) as e:
            self.elem.get_pubkey()
        self.assertIn("gathering public key", str(e.exception))
        self.assertIn("blah blah", str(e.exception))
        self.pubkey.public_bytes.assert_not_called()
        VerifyingKey.from_string.assert_not_called()

    @patch("admin.certificate_v2.ecdsa.VerifyingKey")
    @patch("admin.certificate_v2.x509.load_pem_x509_certificate")
    def test_get_pubkey_err_pub_notnistp256(self, load_pem_x509_certificate,
                                            VerifyingKey):
        self.setup_is_valid_mocks(load_pem_x509_certificate, VerifyingKey)
        self.pubkey.curve = "somethingelse"

        with self.assertRaises(ValueError) as e:
            self.elem.get_pubkey()
        self.assertIn("gathering public key", str(e.exception))
        self.assertIn("NIST P-256", str(e.exception))
        self.pubkey.public_bytes.assert_not_called()
        VerifyingKey.from_string.assert_not_called()

    @patch("admin.certificate_v2.ecdsa.VerifyingKey")
    @patch("admin.certificate_v2.x509.load_pem_x509_certificate")
    def test_get_pubkey_err_public_bytes(self, load_pem_x509_certificate, VerifyingKey):
        self.setup_is_valid_mocks(load_pem_x509_certificate, VerifyingKey)
        self.pubkey.public_bytes.side_effect = Exception("blah blah")

        with self.assertRaises(ValueError) as e:
            self.elem.get_pubkey()
        self.assertIn("gathering public key", str(e.exception))
        self.assertIn("blah blah", str(e.exception))
        self.pubkey.public_bytes.assert_called_with(
            Encoding.X962, PublicFormat.CompressedPoint)
        VerifyingKey.from_string.assert_not_called()

    @patch("admin.certificate_v2.ecdsa.VerifyingKey")
    @patch("admin.certificate_v2.x509.load_pem_x509_certificate")
    def test_get_pubkey_err_ecdsafromstring(self, load_pem_x509_certificate,
                                            VerifyingKey):
        self.setup_is_valid_mocks(load_pem_x509_certificate, VerifyingKey)
        VerifyingKey.from_string.side_effect = Exception("blah blah")

        with self.assertRaises(ValueError) as e:
            self.elem.get_pubkey()
        self.assertIn("gathering public key", str(e.exception))
        self.assertIn("blah blah", str(e.exception))
        self.pubkey.public_bytes.assert_called_with(
            Encoding.X962, PublicFormat.CompressedPoint)
        VerifyingKey.from_string.assert_called_with("the-public-bytes", NIST256p)
