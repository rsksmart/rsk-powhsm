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
from unittest.mock import patch, Mock
from parameterized import parameterized
from admin.x509_utils import split_pem_certificates, get_intel_pcs_x509_crl
import logging

logging.disable(logging.CRITICAL)


class TestSplitPemCertificates(TestCase):
    def test_splits_ok(self):
        test_certs = """
-----BEGIN CERTIFICATE-----
something
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----somethingelse-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----whatis
thisstuff
-----END CERTIFICATE-----
"""
        certs = split_pem_certificates(test_certs)
        self.assertEqual(3, len(certs))
        self.assertEqual(
            "-----BEGIN CERTIFICATE-----something-----END CERTIFICATE-----",
            certs[0].strip().replace("\n", ""))
        self.assertEqual(
            "-----BEGIN CERTIFICATE-----somethingelse-----END CERTIFICATE-----",
            certs[1].strip().replace("\n", ""))
        self.assertEqual(
            "-----BEGIN CERTIFICATE-----whatisthisstuff-----END CERTIFICATE-----",
            certs[2].strip().replace("\n", ""))

    def test_nocerts(self):
        self.assertEqual([], split_pem_certificates("not a certificate in sight"))

    def test_certs_pref_suf(self):
        self.assertEqual(
            ["-----BEGIN CERTIFICATE-----"
             "something-----END CERTIFICATE-----"],
            split_pem_certificates(
                "prefix\n\n\n-----BEGIN CERTIFICATE-----"
                "something-----END CERTIFICATE-----\n\nsuffix\n\r\tmorestuff"
            ))


@patch("admin.x509_utils.url_unquote")
@patch("admin.x509_utils.split_pem_certificates")
@patch("admin.x509_utils.x509.load_der_x509_crl")
@patch("admin.x509_utils.x509.load_pem_x509_crl")
@patch("admin.x509_utils.requests")
class TestGetIntelPcsX509CRL(TestCase):
    def test_ok_pem(self, requests, load_pem, load_der, split, unquote):
        res = Mock()
        requests.get.return_value = res

        res.status_code = 200
        res.content = "the-crl-content"
        res.headers = {
            "Content-Type": "application/x-pem-file"
        }
        load_pem.return_value = "the-parsed-certificate"

        self.assertEqual({
            "crl": "the-parsed-certificate",
            "issuer_chain": None,
            "warning": None,
        }, get_intel_pcs_x509_crl("the-crl-url"))

        load_pem.assert_called_with("the-crl-content")
        load_der.assert_not_called()
        split.assert_not_called()
        unquote.assert_not_called()

    @parameterized.expand([
        ("header 1", "application/pkix-crl"),
        ("header 2", "application/x-x509-ca-cert"),
    ])
    def test_ok_der(self, requests, load_pem, load_der, split, unquote, _, ctype):
        res = Mock()
        requests.get.return_value = res

        res.status_code = 200
        res.content = "the-crl-content"
        res.headers = {
            "Content-Type": ctype,
        }
        load_der.return_value = "the-parsed-certificate"

        self.assertEqual({
            "crl": "the-parsed-certificate",
            "issuer_chain": None,
            "warning": None,
        }, get_intel_pcs_x509_crl("the-crl-url"))

        load_der.assert_called_with("the-crl-content")
        load_pem.assert_not_called()
        split.assert_not_called()
        unquote.assert_not_called()

    def test_ok_warning(self, requests, load_pem, load_der, split, unquote):
        res = Mock()
        requests.get.return_value = res

        res.status_code = 200
        res.content = "the-crl-content"
        res.headers = {
            "Content-Type": "application/x-pem-file",
            "warning": "this-is-a-warning",
        }
        load_pem.return_value = "the-parsed-certificate"

        self.assertEqual({
            "crl": "the-parsed-certificate",
            "issuer_chain": None,
            "warning": "Getting the-crl-url: this-is-a-warning",
        }, get_intel_pcs_x509_crl("the-crl-url"))

        load_pem.assert_called_with("the-crl-content")
        load_der.assert_not_called()
        split.assert_not_called()
        unquote.assert_not_called()

    @patch("admin.x509_utils.x509.load_pem_x509_certificate")
    def test_ok_issuer_chain(self, loadcer, requests, load_pem, load_der, split, unquote):
        res = Mock()
        requests.get.return_value = res

        res.status_code = 200
        res.content = "the-crl-content"
        res.headers = {
            "Content-Type": "application/x-x509-ca-cert",
            "SGX-PCK-CRL-Issuer-Chain": "chain0-chain1-chain2",
        }
        load_der.return_value = "the-parsed-certificate"
        loadcer.side_effect = lambda s: f"parsed-cert-{s.decode()}"
        split.side_effect = lambda s: s.split(",")
        unquote.side_effect = lambda s: s.replace("-", ",")

        self.assertEqual({
            "crl": "the-parsed-certificate",
            "issuer_chain": [
                "parsed-cert-chain0",
                "parsed-cert-chain1",
                "parsed-cert-chain2",
            ],
            "warning": None,
        }, get_intel_pcs_x509_crl("the-crl-url"))

        load_der.assert_called_with("the-crl-content")
        load_pem.assert_not_called()
        unquote.assert_called_with("chain0-chain1-chain2")
        split.assert_called_with("chain0,chain1,chain2")
        self.assertEqual(3, loadcer.call_count)

    def test_error_response(self, requests, load_pem, load_der, split, unquote):
        res = Mock()
        requests.get.return_value = res

        res.status_code = 404

        with self.assertRaises(RuntimeError) as e:
            get_intel_pcs_x509_crl("the-crl-url")
        self.assertIn("Error fetching", str(e.exception))

        load_pem.assert_not_called()
        load_der.assert_not_called()
        split.assert_not_called()
        unquote.assert_not_called()

    def test_error_unknown_ctype(self, requests, load_pem, load_der, split, unquote):
        res = Mock()
        requests.get.return_value = res

        res.status_code = 200
        res.headers = {
            "Content-Type": "not-known"
        }

        with self.assertRaises(RuntimeError) as e:
            get_intel_pcs_x509_crl("the-crl-url")
        self.assertIn("While", str(e.exception))
        self.assertIn("Unknown", str(e.exception))

        load_pem.assert_not_called()
        load_der.assert_not_called()
        split.assert_not_called()
        unquote.assert_not_called()

    @parameterized.expand([
        ("header 1", "application/x-pem-file", "pem"),
        ("header 2", "application/pkix-crl", "der"),
        ("header 3", "application/x-x509-ca-cert", "der"),
    ])
    def test_error_parsing(self, requests, load_pem, load_der,
                           split, unquote, _, ctype, errct):
        res = Mock()
        requests.get.return_value = res

        res.status_code = 200
        res.content = "some-content"
        res.headers = {
            "Content-Type": ctype,
        }

        load_pem.side_effect = ValueError("pem parsing issue")
        load_der.side_effect = ValueError("der parsing issue")

        with self.assertRaises(RuntimeError) as e:
            get_intel_pcs_x509_crl("the-crl-url")
        self.assertIn("While", str(e.exception))
        self.assertIn(f"{errct} parsing", str(e.exception))

        split.assert_not_called()
        unquote.assert_not_called()
