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
from unittest.mock import Mock, call, patch, mock_open
from adm import main
from admin.certificate import HSMCertificate, HSMCertificateElement
from admin.misc import AdminError
from ledger.hsm2dongle import HSM2Dongle

import json
import logging

logging.disable(logging.CRITICAL)


@patch("sys.stdout.write")
class TestAttestation(TestCase):
    def setUp(self):
        self.ui_attestation = {
            "app_hash": "1122334455",
            "message": "6677889900",
            "signature": "AABBCCDDEE",
        }

        self.signer_attestation = {
            "app_hash": "aabbccddee",
            "message": "ffeeddccbb",
            "signature": "9988776655",
        }

        self.expected_cert = HSMCertificate()
        self.expected_cert.add_element(
            HSMCertificateElement({
                "name": "ui",
                "message": self.ui_attestation["message"],
                "signature": self.ui_attestation["signature"],
                "signed_by": "attestation",
                "tweak": self.ui_attestation["app_hash"]
            }))
        self.expected_cert.add_element(
            HSMCertificateElement({
                "name": "signer",
                "message": self.signer_attestation["message"],
                "signature": self.signer_attestation["signature"],
                "signed_by": "attestation",
                "tweak": self.signer_attestation["app_hash"]
            }))
        self.expected_cert.add_target("ui")
        self.expected_cert.add_target("signer")
        self.dongle = Mock()

    @patch("admin.attestation.do_unlock")
    @patch("admin.attestation.HSMCertificate")
    @patch("admin.attestation.get_hsm")
    def test_attestation(self, get_hsm, certificate, *_):
        get_hsm.return_value = self.dongle
        certificate.from_jsonfile = Mock(return_value=self.expected_cert)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.get_ui_attestation = Mock(return_value=self.ui_attestation)
        self.dongle.get_signer_attestation = Mock(return_value=self.signer_attestation)
        certificate_path = 'cert-path'

        with patch('sys.argv', [
                'adm.py',
                '-o', certificate_path,
                '-c', '112233:445566:778899',
                '-t', 'certification-path',
                'attestation'
        ]):
            with patch('builtins.open', mock_open()) as file_mock:
                main()
        self.assertEqual([call(certificate_path, 'w')], file_mock.call_args_list)
        self.assertEqual(
            [call("%s\n" % json.dumps(self.expected_cert.to_dict(), indent=2))],
            file_mock.return_value.write.call_args_list)

    @patch("admin.attestation.HSMCertificate")
    def test_attestation_invalid_certificate(self, certificate, *_):
        certificate.from_jsonfile = Mock(side_effect=Exception('inner error'))
        with patch('sys.argv', [
                'adm.py',
                '-o', 'a-path',
                '-c', '112233:445566:778899',
                '-t', 'certification-path',
                'attestation'
        ]):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual('While loading the attestation certificate file: inner error',
                         str(e.exception))

    @patch("admin.attestation.do_unlock")
    @patch("admin.attestation.HSMCertificate")
    @patch("admin.attestation.get_hsm")
    def test_attestation_invalid_ui_attestation(self, get_hsm, certificate, *_):
        get_hsm.return_value = self.dongle
        certificate.from_jsonfile = Mock(return_value=self.expected_cert)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.get_ui_attestation = Mock(side_effect=Exception('an-error-msg'))
        self.dongle.get_signer_attestation = Mock(return_value=self.signer_attestation)
        certificate_path = 'cert-path'

        with patch('sys.argv', [
                'adm.py',
                '-o', certificate_path,
                '-c', '112233:445566:778899',
                '-t', 'certification-path',
                'attestation'
        ]):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual('Failed to gather UI attestation: an-error-msg',
                         str(e.exception))

    @patch("admin.attestation.do_unlock")
    @patch("admin.attestation.HSMCertificate")
    @patch("admin.attestation.get_hsm")
    def test_attestation_invalid_signer_attestation(self, get_hsm, certificate, *_):
        get_hsm.return_value = self.dongle
        certificate.from_jsonfile = Mock(return_value=self.expected_cert)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.get_ui_attestation = Mock(return_value=self.ui_attestation)
        self.dongle.get_signer_attestation = Mock(side_effect=Exception('an-error-msg'))
        certificate_path = 'cert-path'

        with patch('sys.argv', [
                'adm.py',
                '-o', certificate_path,
                '-c', '112233:445566:778899',
                '-t', 'certification-path',
                'attestation'
        ]):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual('Failed to gather Signer attestation: an-error-msg',
                         str(e.exception))

    @patch("admin.attestation.do_unlock")
    @patch("admin.attestation.HSMCertificate")
    def test_attestation_unlock_error(self, certificate, unlock_mock, *_):
        certificate.from_jsonfile = Mock(return_value=self.expected_cert)
        unlock_error_msg = 'Unlock error msg'
        unlock_mock.side_effect = Exception(unlock_error_msg)
        with patch('sys.argv', [
                'adm.py',
                '-o', 'a-path',
                '-c', '112233:445566:778899',
                '-t', 'certification-path',
                'attestation'
        ]):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual(f'Failed to unlock device: {unlock_error_msg}', str(e.exception))

    def test_attestation_no_out_path(self, *_):
        with patch('sys.argv', [
                'adm.py',
                '-c', '112233:445566:778899',
                '-t', 'certification-path',
                'attestation'
        ]):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual('No output file path given', str(e.exception))

    def test_attestation_no_certificate_path(self, *_):
        with patch('sys.argv', [
                'sys.argv',
                '-c', '112233:445566:778899',
                '-o', 'out-path',
                'attestation'
        ]):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual('No attestation certificate file given', str(e.exception))

    @patch("admin.attestation.HSMCertificate")
    def test_attestation_no_ca_info(self, certificate, *_):
        certificate.from_jsonfile = Mock(return_value=self.expected_cert)
        with patch('sys.argv', [
                'adm.py',
                '-o', 'a-path',
                '-t', 'certification-path',
                'attestation'
        ]):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual('No CA info given', str(e.exception))

    @patch("admin.attestation.HSMCertificate")
    def test_attestation_invalid_ca_info(self, certificate, *_):
        certificate.from_jsonfile = Mock(return_value=self.expected_cert)
        with patch('sys.argv', [
                'adm.py',
                '-o', 'a-path',
                '-c', 'invalid-ca',
                '-t', 'certification-path',
                'attestation'
        ]):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual('Invalid CA info given', str(e.exception))

    @patch("admin.attestation.HSMCertificate")
    def test_attestation_invalid_ca_pubkey(self, certificate, *_):
        certificate.from_jsonfile = Mock(return_value=self.expected_cert)
        with patch('sys.argv', [
                'adm.py',
                '-o', 'a-path',
                '-c', 'INVALID:445566:778899',
                '-t', 'certification-path',
                'attestation'
        ]):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual('Invalid CA public key given', str(e.exception))

    @patch("admin.attestation.HSMCertificate")
    def test_attestation_invalid_ca_hash(self, certificate, *_):
        certificate.from_jsonfile = Mock(return_value=self.expected_cert)
        with patch('sys.argv', [
                'adm.py',
                '-o', 'a-path',
                '-c', '112233:INVALID:778899',
                '-t', 'certification-path',
                'attestation'
        ]):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual('Invalid CA hash given', str(e.exception))

    @patch("admin.attestation.HSMCertificate")
    def test_attestation_invalid_ca_signature(self, certificate, *_):
        certificate.from_jsonfile = Mock(return_value=self.expected_cert)
        with patch('sys.argv', [
                'adm.py',
                '-o', 'a-path',
                '-c', '112233:445566:INVALID',
                '-t', 'certification-path', 'attestation'
        ]):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual('Invalid CA signature given', str(e.exception))
