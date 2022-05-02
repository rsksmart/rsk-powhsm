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
from adm import create_actions, create_parser
from admin.certificate import HSMCertificate
from admin.misc import AdminError, not_implemented
from ledger.hsm2dongle import HSM2Dongle

import logging

logging.disable(logging.CRITICAL)


@patch("sys.stdout.write")
@patch("admin.attestation.do_unlock")
@patch("admin.attestation.HSMCertificate")
@patch("admin.attestation.get_hsm")
@patch("ledger.hsm2dongle.HSM2Dongle")
class TestAttestation(TestCase):
    def setUp(self):
        self.actions = create_actions()
        self.parser = create_parser(self.actions)

    def test_attestation(self, dongle, get_hsm, certificate, *_):
        get_hsm.return_value = dongle

        certificate_map = {
            "version": 1,
            "targets": [],
            "elements": [],
        }

        mock_attestation = {
            "app_hash": "1122334455",
            "message": "6677889900",
            "signature": "AABBCCDDEE",
        }

        certificate.from_jsonfile = Mock(return_value=HSMCertificate(certificate_map))
        dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        dongle.is_onboarded = Mock(return_value=True)
        dongle.get_signer_attestation = Mock(return_value=mock_attestation)
        dongle.get_ui_attestation = Mock(return_value=mock_attestation)

        options = self.parser.parse_args([
            '-p', 'a-pin', '-o', 'out-path', '-c', '112233:445566:778899', '-t',
            'certification-path', 'attestation'
        ])
        self.actions.get(options.operation, not_implemented)(options)

    def test_attestation_no_out_path(self, *_):
        options = self.parser.parse_args([
            '-p', 'a-pin', '-c', '112233:445566:778899', '-t', 'certification-path',
            'attestation'
        ])
        with self.assertRaises(AdminError):
            self.actions.get(options.operation, not_implemented)(options)

    def test_attestation_no_certificate_path(self, *_):
        options = self.parser.parse_args([
            '-p', 'a-pin', '-c', '112233:445566:778899', '-o', 'out-path', 'attestation'
        ])
        with self.assertRaises(AdminError):
            self.actions.get(options.operation, not_implemented)(options)
