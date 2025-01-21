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
from parameterized import parameterized
from admin.certificate_v1 import HSMCertificate
from admin.certificate_v2 import HSMCertificateV2
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
