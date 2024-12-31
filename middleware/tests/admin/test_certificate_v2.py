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
from unittest.mock import Mock, patch
from parameterized import parameterized
from admin.certificate_v1 import HSMCertificate
from sgx.envelope import SgxQuote
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
        self.assertEqual({"version": 2, "targets": [], "elements": []}, cert.to_dict())

    def test_parse_identity(self):
        cert = HSMCertificateV2(TEST_CERTIFICATE)
        self.assertEqual(TEST_CERTIFICATE, cert.to_dict())

    def mock_element(self, which_one_invalid):
        class MockElement:
            def __init__(self, d):
                self.d = d
                self.name = d["name"]
                self.signed_by = d["signed_by"]

            def is_valid(self, c):
                return self.name != which_one_invalid

            def get_value(self):
                return f"the value for {self.name}"

            def get_tweak(self):
                return None

        def mock_element_factory(k, d):
            return MockElement(d)

        HSMCertificateV2.ELEMENT_FACTORY = mock_element_factory

    def test_validate_and_get_values_value(self):
        self.mock_element(True)
        cert = HSMCertificateV2(TEST_CERTIFICATE)
        self.assertEqual({
                "quote": (True, "the value for quote", None),
            }, cert.validate_and_get_values("a-root-of-trust"))

    @parameterized.expand([
        ("invalid_quote", "quote"),
        ("invalid_attestation", "attestation"),
        ("invalid_qe", "quoting_enclave"),
        ("invalid_plf", "platform_ca"),
    ])
    def test_validate_and_get_values_invalid(self, _, invalid_name):
        self.mock_element(invalid_name)
        cert = HSMCertificateV2(TEST_CERTIFICATE)
        self.assertEqual({
                "quote": (False, invalid_name),
            }, cert.validate_and_get_values("a-root-of-trust"))


class TestHSMCertificateV2Element(TestCase):
    def setUp(self):
        class TestElement(HSMCertificateV2Element):
            def __init__(self):
                pass

        self.instance = TestElement()

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

    def test_cant_instantiate(self):
        with self.assertRaises(NotImplementedError):
            HSMCertificateV2Element()

    def test_get_pubkey_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.instance.get_pubkey()

    def test_get_value_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.instance.get_value()

    def test_is_valid_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.instance.is_valid("a-certifier")


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

    def test_get_value_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.elem.get_value()


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
