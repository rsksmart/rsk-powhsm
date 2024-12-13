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
from admin.certificate_v2 import HSMCertificateV2, HSMCertificateV2ElementSGXQuote, \
                                 HSMCertificateV2ElementSGXAttestationKey, \
                                 HSMCertificateV2ElementX509


class TestHSMCertificateV2(TestCase):
    def test_behavior_inherited(self):
        self.assertTrue(issubclass(HSMCertificateV2, HSMCertificate))

    def test_create_empty_certificate_ok(self):
        cert = HSMCertificateV2()
        self.assertEqual({'version': 2, 'targets': [], 'elements': []}, cert.to_dict())


class TestHSMCertificateV2ElementSGXQuote(TestCase):
    def test_dict_ok(self):
        elem = HSMCertificateV2ElementSGXQuote(
            "thename",
            bytes.fromhex("aabbcc"),
            bytes.fromhex("ddeeff"),
            bytes.fromhex("112233"),
            "whosigned"
        )
        self.assertEqual({
            "name": "thename",
            "type": "sgx_quote",
            "message": "aabbcc",
            "custom_data": "ddeeff",
            "signature": "112233",
            "signed_by": "whosigned",
        }, elem.to_dict())


class TestHSMCertificateV2ElementSGXAttestationKey(TestCase):
    def test_dict_ok(self):
        elem = HSMCertificateV2ElementSGXAttestationKey(
            "thename",
            bytes.fromhex("aabbcc"),
            bytes.fromhex("ddeeff"),
            bytes.fromhex("112233"),
            bytes.fromhex("44556677"),
            "whosigned"
        )
        self.assertEqual({
            "name": "thename",
            "type": "sgx_attestation_key",
            "message": "aabbcc",
            "key": "ddeeff",
            "auth_data": "112233",
            "signature": "44556677",
            "signed_by": "whosigned",
        }, elem.to_dict())


class TestHSMCertificateV2ElementX509(TestCase):
    def test_dict_ok(self):
        elem = HSMCertificateV2ElementX509(
            "thename",
            b"this is an ascii message",
            "whosigned"
        )
        self.assertEqual({
            "name": "thename",
            "type": "x509_pem",
            "message": "this is an ascii message",
            "signed_by": "whosigned",
        }, elem.to_dict())
