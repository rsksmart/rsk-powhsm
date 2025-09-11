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


from datetime import datetime, timedelta
from unittest import TestCase
from unittest.mock import patch, Mock, MagicMock
from admin.x509_validator import X509CertificateValidator, x509
import logging

logging.disable(logging.CRITICAL)


@patch("admin.x509_validator.ec")
class TestX509CertificateValidatorValidate(TestCase):
    def setUp(self):
        self.crl_getter = Mock()
        self.validator = X509CertificateValidator(self.crl_getter)

        self.subject = MagicMock(spec=x509.Certificate)
        self.subject.subject = "the subject"
        self.issuer = MagicMock(spec=x509.Certificate)
        self.issuer.subject = "the issuer"
        self.issuer.public_key.return_value = Mock()

        self.subject.not_valid_before_utc = datetime.now() - timedelta(days=100)
        self.subject.not_valid_after_utc = datetime.now() + timedelta(days=100)
        self.subject.signature_hash_algorithm = "the-algorithm"

    def setup_mocks(self, ec):
        ec.ECDSA.side_effect = lambda s: f"ecdsa-{s}"
        self.validator.get_crl_info = Mock()

    def mock_crl_info(self):
        self.crl_info = {
            "crl": Mock(),
            "issuer_chain": None,
            "warning": None,
        }
        self.validator.get_crl_info.return_value = self.crl_info

        self.crl_info["crl"].is_signature_valid.return_value = True
        self.crl_info["crl"].get_revoked_certificate_by_serial_number.return_value = None

    def test_validate_ok(self, ec):
        self.setup_mocks(ec)
        self.mock_crl_info()

        self.assertEqual({
            "valid": True,
            "warnings": [],
        }, self.validator.validate(self.subject, self.issuer, datetime.now()))

        self.subject.verify_directly_issued_by.assert_called_with(self.issuer)
        self.issuer.public_key.return_value.verify.assert_called_with(
            self.subject.signature,
            self.subject.tbs_certificate_bytes,
            "ecdsa-the-algorithm"
        )
        self.validator.get_crl_info.assert_called_with(self.subject)
        self.crl_info["crl"].is_signature_valid.assert_called_with(
            self.issuer.public_key())
        self.crl_info["crl"].get_revoked_certificate_by_serial_number.\
            assert_called_with(self.subject.serial_number)

    def test_validate_ok_no_crl_checking(self, ec):
        self.setup_mocks(ec)
        self.validator.get_crl_info = Mock()

        self.assertEqual({
            "valid": True,
            "warnings": [],
        }, self.validator.validate(self.subject, self.issuer,
                                   datetime.now(), check_crl=False))

        self.subject.verify_directly_issued_by.assert_called_with(self.issuer)
        self.issuer.public_key.return_value.verify.assert_called_with(
            self.subject.signature,
            self.subject.tbs_certificate_bytes,
            "ecdsa-the-algorithm"
        )
        self.validator.get_crl_info.assert_not_called()

    def test_validate_ok_with_crl_warnings(self, ec):
        self.setup_mocks(ec)
        self.mock_crl_info()
        self.crl_info["warning"] = "this is a CRL warning"

        self.assertEqual({
            "valid": True,
            "warnings": ["this is a CRL warning"],
        }, self.validator.validate(self.subject, self.issuer, datetime.now()))

    def test_validate_invalid_certificates(self, ec):
        self.setup_mocks(ec)
        self.mock_crl_info()

        self.assertEqual({
            "valid": False,
            "reason": "Both subject and issuer must be instances of x509.Certificate",
        }, self.validator.validate("not a certificate", self.issuer, datetime.now()))

        self.assertEqual({
            "valid": False,
            "reason": "Both subject and issuer must be instances of x509.Certificate",
        }, self.validator.validate(self.subject, "not a certificate", datetime.now()))

        self.subject.verify_directly_issued_by.assert_not_called()
        self.issuer.public_key.return_value.verify.assert_not_called()
        self.validator.get_crl_info.assert_not_called()

    def test_validate_invalid_period(self, ec):
        self.setup_mocks(ec)
        self.mock_crl_info()

        self.assertEqual({
            "valid": False,
            "reason": "the subject not within validity period",
        }, self.validator.validate(self.subject, self.issuer,
                                   datetime.now() - timedelta(days=101)))

        self.assertEqual({
            "valid": False,
            "reason": "the subject not within validity period",
        }, self.validator.validate(self.subject, self.issuer,
                                   datetime.now() + timedelta(days=101)))

        self.subject.verify_directly_issued_by.assert_not_called()
        self.issuer.public_key.return_value.verify.assert_not_called()
        self.validator.get_crl_info.assert_not_called()

    def test_validate_not_issued_by_issuer(self, ec):
        self.setup_mocks(ec)
        self.mock_crl_info()

        self.subject.verify_directly_issued_by.side_effect = RuntimeError("oops")

        self.assertEqual({
            "valid": False,
            "reason": "Verifying the subject issued by the issuer: oops",
        }, self.validator.validate(self.subject, self.issuer, datetime.now()))

        self.subject.verify_directly_issued_by.assert_called_with(self.issuer)
        self.issuer.public_key.return_value.verify.assert_not_called()
        self.validator.get_crl_info.assert_not_called()

    def test_validate_signature_invalid(self, ec):
        self.setup_mocks(ec)
        self.mock_crl_info()

        self.issuer.public_key.return_value.verify.side_effect = RuntimeError("oopsies")

        self.assertEqual({
            "valid": False,
            "reason": "Verifying the subject issued by the issuer: oopsies",
        }, self.validator.validate(self.subject, self.issuer, datetime.now()))

        self.subject.verify_directly_issued_by.assert_called_with(self.issuer)
        self.issuer.public_key.return_value.verify.assert_called_with(
            self.subject.signature,
            self.subject.tbs_certificate_bytes,
            "ecdsa-the-algorithm"
        )
        self.validator.get_crl_info.assert_not_called()

    def test_validate_crl_info_gathering_error(self, ec):
        self.setup_mocks(ec)
        self.mock_crl_info()
        self.validator.get_crl_info.side_effect = RuntimeError("Error gathering CRL info")

        self.assertEqual({
            "valid": False,
            "reason": "Error gathering CRL info",
        }, self.validator.validate(self.subject, self.issuer, datetime.now()))

        self.subject.verify_directly_issued_by.assert_called_with(self.issuer)
        self.issuer.public_key.return_value.verify.assert_called_with(
            self.subject.signature,
            self.subject.tbs_certificate_bytes,
            "ecdsa-the-algorithm"
        )
        self.validator.get_crl_info.assert_called_with(self.subject)
        self.crl_info["crl"].is_signature_valid.assert_not_called()
        self.crl_info["crl"].get_revoked_certificate_by_serial_number.assert_not_called()

    def test_validate_crl_invalid_signature(self, ec):
        self.setup_mocks(ec)
        self.mock_crl_info()
        self.crl_info["crl"].is_signature_valid.return_value = False

        self.assertEqual({
            "valid": False,
            "reason": "Invalid CRL signature from the issuer",
        }, self.validator.validate(self.subject, self.issuer, datetime.now()))

        self.subject.verify_directly_issued_by.assert_called_with(self.issuer)
        self.issuer.public_key.return_value.verify.assert_called_with(
            self.subject.signature,
            self.subject.tbs_certificate_bytes,
            "ecdsa-the-algorithm"
        )
        self.validator.get_crl_info.assert_called_with(self.subject)
        self.crl_info["crl"].is_signature_valid.assert_called_with(
            self.issuer.public_key())
        self.crl_info["crl"].get_revoked_certificate_by_serial_number.assert_not_called()

    def test_validate_subject_revoked(self, ec):
        self.setup_mocks(ec)
        self.mock_crl_info()
        self.crl_info["crl"].get_revoked_certificate_by_serial_number.return_value = 123

        self.assertEqual({
            "valid": False,
            "reason": "the subject found in the issuer CRL",
        }, self.validator.validate(self.subject, self.issuer, datetime.now()))

        self.subject.verify_directly_issued_by.assert_called_with(self.issuer)
        self.issuer.public_key.return_value.verify.assert_called_with(
            self.subject.signature,
            self.subject.tbs_certificate_bytes,
            "ecdsa-the-algorithm"
        )
        self.validator.get_crl_info.assert_called_with(self.subject)
        self.crl_info["crl"].is_signature_valid.assert_called_with(
            self.issuer.public_key())
        self.crl_info["crl"].get_revoked_certificate_by_serial_number.\
            assert_called_with(self.subject.serial_number)

    def test_validate_ok_with_crl_issuer_chain(self, ec):
        self.setup_mocks(ec)
        self.mock_crl_info()
        self.crl_info["issuer_chain"] = [self.issuer, "something", "else"]

        self.assertEqual({
            "valid": True,
            "warnings": [],
        }, self.validator.validate(self.subject, self.issuer, datetime.now()))

        self.subject.verify_directly_issued_by.assert_called_with(self.issuer)
        self.issuer.public_key.return_value.verify.assert_called_with(
            self.subject.signature,
            self.subject.tbs_certificate_bytes,
            "ecdsa-the-algorithm"
        )
        self.validator.get_crl_info.assert_called_with(self.subject)
        self.crl_info["crl"].is_signature_valid.assert_called_with(
            self.issuer.public_key())
        self.crl_info["crl"].get_revoked_certificate_by_serial_number.\
            assert_called_with(self.subject.serial_number)

    def test_validate_error_crl_issuer_chain_leaf_mismatch(self, ec):
        self.setup_mocks(ec)
        self.mock_crl_info()
        leaf = Mock()
        leaf.subject = "different subject"
        self.crl_info["issuer_chain"] = [leaf, "something", "else"]

        self.assertEqual({
            "valid": False,
            "reason": "CRL issuer chain leaf different subject does not match "
                      "certificate the subject issuer the issuer",
        }, self.validator.validate(self.subject, self.issuer, datetime.now()))

        self.subject.verify_directly_issued_by.assert_called_with(self.issuer)
        self.issuer.public_key.return_value.verify.assert_called_with(
            self.subject.signature,
            self.subject.tbs_certificate_bytes,
            "ecdsa-the-algorithm"
        )
        self.validator.get_crl_info.assert_called_with(self.subject)
        self.crl_info["crl"].is_signature_valid.assert_called_with(
            self.issuer.public_key())
        self.crl_info["crl"].get_revoked_certificate_by_serial_number.\
            assert_called_with(self.subject.serial_number)


class TestX509CertificateValidatorGetCRLInfo(TestCase):
    def setUp(self):
        self.crl_getter = Mock()
        self.validator = X509CertificateValidator(self.crl_getter)

        self.crldp_ext = Mock()

        self.subject = Mock()
        self.subject.extensions.get_extension_for_class.return_value = self.crldp_ext

    def test_get_crl_info_ok_first_url(self):
        crldp_1 = Mock(full_name=[Mock(value="url-1")])
        self.crldp_ext.value = [crldp_1, "doesnt-matter", "neither"]

        self.crl_getter.return_value = "crl-for-url-1"

        self.assertEqual("crl-for-url-1", self.validator.get_crl_info(self.subject))

        self.crl_getter.assert_called_once()
        self.crl_getter.assert_called_with("url-1")

    def test_get_crl_info_ok_third_url(self):
        crldp_1 = Mock(full_name=[Mock(value="url-1")])
        crldp_2 = Mock(full_name=[Mock(value="url-2")])
        crldp_3 = Mock(full_name=[Mock(value="url-3")])
        self.crldp_ext.value = [crldp_1, crldp_2, crldp_3]

        def getter(url):
            self.assertRegex(url, "^url-[123]$")
            if url[-1] == "3":
                return "crl-for-url-3"

            raise RuntimeError("Unable to retrieve")

        self.crl_getter.side_effect = getter

        self.assertEqual("crl-for-url-3", self.validator.get_crl_info(self.subject))

        self.assertEqual(3, self.crl_getter.call_count)

    def test_get_crl_info_all_urls_error(self):
        crldp_1 = Mock(full_name=[Mock(value="url-1")])
        crldp_2 = Mock(full_name=[Mock(value="url-2")])
        crldp_3 = Mock(full_name=[Mock(value="url-3")])
        self.crldp_ext.value = [crldp_1, crldp_2, crldp_3]

        self.crl_getter.side_effect = RuntimeError("Unable to retrieve")

        with self.assertRaises(RuntimeError) as e:
            self.validator.get_crl_info(self.subject)
        self.assertIn("None of the distribution", str(e.exception))

        self.assertEqual(3, self.crl_getter.call_count)

    def test_get_crl_info_no_crldp(self):
        self.crldp_ext.value = []

        self.crl_getter.side_effect = RuntimeError("Unable to retrieve")

        with self.assertRaises(RuntimeError) as e:
            self.validator.get_crl_info(self.subject)
        self.assertIn("No CRL distribution", str(e.exception))

        self.crl_getter.assert_not_called()

    def test_get_crl_info_no_crldp_ext(self):
        self.subject.extensions.get_extension_for_class.side_effect = RuntimeError("oops")

        with self.assertRaises(RuntimeError) as e:
            self.validator.get_crl_info(self.subject)
        self.assertIn("Unable to fetch", str(e.exception))
        self.assertIn("oops", str(e.exception))

        self.crl_getter.assert_not_called()
