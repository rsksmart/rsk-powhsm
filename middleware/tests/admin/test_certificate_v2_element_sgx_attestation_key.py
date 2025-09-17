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
from unittest import TestCase
from unittest.mock import Mock
from admin.certificate_v2 import HSMCertificateV2Element, \
                                 HSMCertificateV2ElementSGXAttestationKey
from sgx.envelope import SgxReportBody
from .test_certificate_v2_resources import TEST_CERTIFICATE


class TestHSMCertificateV2ElementSGXAttestationKey(TestCase):
    def setUp(self):
        self.source = TEST_CERTIFICATE["elements"][1]
        self.elem = HSMCertificateV2ElementSGXAttestationKey(self.source)
        valid_key = ecdsa.VerifyingKey.from_string(
            bytes.fromhex("03a97b443365b192a412d01c5bb49f097d497a06ef1aae0ed2b454b74c"
                          "ff1ba7d9"),
            ecdsa.NIST256p)
        self.valid_certifier = Mock()
        self.valid_certifier.get_pubkey.return_value = valid_key

    def test_props(self):
        self.assertEqual("attestation", self.elem.name)
        self.assertEqual("quoting_enclave", self.elem.signed_by)
        self.assertEqual(bytes.fromhex(
            "0e0e100fffff01000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000001500000000000000e70000000000000096b347a64e5a045e2736"
            "9c26e6dcda51fd7c850e9b3a3a79e718f43261dee1e4000000000000000000000000000000"
            "00000000000000000000000000000000008c4f5775d796503e96137f77c68a829a0056ac8d"
            "ed70140b081b094490c57bff00000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000000000000000000000000001000a"
            "00000000000000000000000000000000000000000000000000000000000000000000000000"
            "0000000000000000000000000000000000000000000000001fe721d0322954821589237fd2"
            "7efb8fef1acb3ecd6b0352c31271550fc70f94000000000000000000000000000000000000"
            "0000000000000000000000000000"), self.elem.message.get_raw_data())
        self.assertEqual(bytes.fromhex(
            "03a024cb34c90ea6a8f9f2181c9020cbcc7c073e69981733c8deed6f6c451822aa"),
            self.elem.key.to_string("compressed"))
        self.assertEqual(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            self.elem.auth_data)
        self.assertEqual(
            "304502201f14d532274c4385fc0019ca2a21e53e17143cb62377ca4fcdd97fa9fef8fb25022"
            "10095d4ee272cf3c512e36779de67dc7814982f1160d981d138a32b265e928a0562",
            self.elem.signature)

    def test_to_dict(self):
        self.assertEqual(self.source, self.elem.to_dict())

    def test_parse_identity(self):
        elem = HSMCertificateV2Element.from_dict(self.source)
        self.assertTrue(isinstance(elem, HSMCertificateV2ElementSGXAttestationKey))
        self.assertEqual(self.source, elem.to_dict())

    def test_from_dict_invalid_message(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2ElementSGXAttestationKey({
                **self.source,
                "message": "not-hex",
            })
        self.assertIn("Invalid message", str(e.exception))

    def test_from_dict_invalid_key(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2ElementSGXAttestationKey({
                **self.source,
                "key": "not-hex",
            })
        self.assertIn("Invalid key", str(e.exception))

    def test_from_dict_invalid_auth_data(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2ElementSGXAttestationKey({
                **self.source,
                "auth_data": "not-hex",
            })
        self.assertIn("Invalid auth data", str(e.exception))

    def test_from_dict_invalid_signature(self):
        with self.assertRaises(ValueError) as e:
            HSMCertificateV2ElementSGXAttestationKey({
                **self.source,
                "signature": "not-hex",
            })
        self.assertIn("Invalid signature", str(e.exception))

    def test_get_value_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.elem.get_value()

    def test_is_valid_ok(self):
        self.assertTrue(self.elem.is_valid(self.valid_certifier))

    def test_is_valid_err_notthekey(self):
        invalid_key = ecdsa.VerifyingKey.from_string(
            bytes.fromhex("03986284e40eafc53a650547216176d4a227e1fa3a4473b76e48cfc442"
                          "efa004c4"),
            ecdsa.NIST256p)
        certifier = Mock()
        certifier.get_pubkey.return_value = invalid_key
        self.assertFalse(self.elem.is_valid(certifier))

    def test_is_valid_err_message(self):
        self.elem = HSMCertificateV2ElementSGXAttestationKey({
                **self.source,
                "message": "1e0e100fffff010000000000000000000000000000000000000000000000"
                "0000000000000000000000000000000000001500000000000000e70000000000000096b"
                "347a64e5a045e27369c26e6dcda51fd7c850e9b3a3a79e718f43261dee1e40000000000"
                "0000000000000000000000000000000000000000000000000000008c4f5775d796503e9"
                "6137f77c68a829a0056ac8ded70140b081b094490c57bff000000000000000000000000"
                "00000000000000000000000000000000000000000000000000000000000000000000000"
                "00000000000000000000000000000000000000000000000000000000000000000000000"
                "0000000000000000000000000001000a000000000000000000000000000000000000000"
                "00000000000000000000000000000000000000000000000000000000000000000000000"
                "0000000000001fe721d0322954821589237fd27efb8fef1acb3ecd6b0352c31271550fc"
                "70f940000000000000000000000000000000000000000000000000000000000000000",
            })
        self.assertFalse(self.elem.is_valid(self.valid_certifier))

    def test_is_valid_err_message_invalid(self):
        self.elem = HSMCertificateV2ElementSGXAttestationKey({
                **self.source,
                "message": "aabbccdd",
            })
        self.assertFalse(self.elem.is_valid(self.valid_certifier))

    def test_is_valid_err_auth_data(self):
        self.elem = HSMCertificateV2ElementSGXAttestationKey({
                **self.source,
                "auth_data": "aabbccdd",
            })
        self.assertFalse(self.elem.is_valid(self.valid_certifier))

    def test_is_valid_err_key(self):
        self.elem = HSMCertificateV2ElementSGXAttestationKey({
                **self.source,
                "key": "03e2005bbf9db399bcba0b40d181b691f0d81287dbc1b6280bebd9247b"
                       "c0933f38",
            })
        self.assertFalse(self.elem.is_valid(self.valid_certifier))

    def test_is_valid_err_key_invalid(self):
        self.elem = HSMCertificateV2ElementSGXAttestationKey({
                **self.source,
                "key": "aabbccdd",
            })
        self.assertFalse(self.elem.is_valid(self.valid_certifier))

    def test_get_collateral_message(self):
        self.assertEqual(SgxReportBody, type(self.elem.get_collateral()))
        self.assertEqual(
            self.elem.message.get_raw_data(),
            self.elem.get_collateral().get_raw_data())
