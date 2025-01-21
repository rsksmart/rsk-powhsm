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
from admin.certificate_v2 import HSMCertificateV2Element


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
