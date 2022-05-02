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
from admin.misc import AdminError, not_implemented
from ledger.hsm2dongle import HSM2Dongle

import logging

logging.disable(logging.CRITICAL)


@patch("sys.stdout.write")
@patch("admin.onboard.get_hsm")
@patch("ledger.hsm2dongle.HSM2Dongle")
class TestOnboard(TestCase):
    VALID_PIN = '1234ABCD'
    INVALID_PIN = '123456789'

    DEVICE_KEY = {
        "pubkey": "this-is-the-public-key",
        "message": "1122334455",
        "signature": "aabbccddee",
    }

    ENDORSEMENT_KEY = {
        "pubkey": "this-is-another-public-key",
        "message": "5544332211",
        "signature": "eeddccbbaa",
    }

    INVALID_KEY = {
        "pubkey": "this-is-the-public-key",
        "message": "invalid-message",
        "signature": "invalid-signature",
    }

    def setUp(self):
        self.actions = create_actions()
        self.parser = create_parser(self.actions)

    @patch("admin.onboard.get_admin_hsm")
    @patch("admin.unlock.get_hsm")
    @patch("admin.onboard.get_user_answer", return_value="yes")
    @patch("admin.onboard.wait_user_confirmation")
    @patch("admin.dongle_admin.DongleAdmin")
    def test_onboard(self, dongleAdmin, _unused1, _unused2, get_hsm_unlock, get_admin_hsm,
                     hsm2Dongle, get_hsm_onboard, _):
        get_hsm_onboard.return_value = hsm2Dongle
        get_hsm_unlock.return_value = hsm2Dongle
        get_admin_hsm.return_value = dongleAdmin

        hsm2Dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        hsm2Dongle.is_onboarded = Mock(return_value=True)
        dongleAdmin.get_device_key = Mock(return_value=self.DEVICE_KEY)
        dongleAdmin.setup_endorsement_key = Mock(return_value=self.ENDORSEMENT_KEY)

        options = self.parser.parse_args(
            ['-p', self.VALID_PIN, '-o', 'a-path', 'onboard'])
        self.actions.get(options.operation, not_implemented)(options)

    @patch("admin.onboard.get_user_answer", return_value="no")
    def test_onboard_user_cancelled(self, _unused1, hsm2Dongle, get_hsm, _unused2):
        get_hsm.return_value = hsm2Dongle

        hsm2Dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        hsm2Dongle.is_onboarded = Mock(return_value=True)

        options = self.parser.parse_args(
            ['-p', self.VALID_PIN, '-o', 'a-path', 'onboard'])

        with self.assertRaises(AdminError):
            self.actions.get(options.operation, not_implemented)(options)

    def test_onboard_no_output_file(self, *_):
        options = self.parser.parse_args(['-p', self.VALID_PIN, 'onboard'])

        with self.assertRaises(AdminError):
            self.actions.get(options.operation, not_implemented)(options)

    def test_onboard_invalid_pin(self, hsm2Dongle, get_hsm, _):
        get_hsm.return_value = hsm2Dongle

        hsm2Dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        hsm2Dongle.is_onboarded = Mock(return_value=True)

        options = self.parser.parse_args(
            ['-p', self.INVALID_PIN, '-o', 'a-path', 'onboard'])

        with self.assertRaises(AdminError):
            self.actions.get(options.operation, not_implemented)(options)

    def test_onboard_invalid_mode(self, hsm2Dongle, get_hsm, _):
        get_hsm.return_value = hsm2Dongle

        hsm2Dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.APP)
        hsm2Dongle.is_onboarded = Mock(return_value=True)

        options = self.parser.parse_args(
            ['-p', self.VALID_PIN, '-o', 'a-path', 'onboard'])

        with self.assertRaises(AdminError):
            self.actions.get(options.operation, not_implemented)(options)

    @patch("admin.onboard.get_admin_hsm")
    @patch("admin.unlock.get_hsm")
    @patch("admin.onboard.get_user_answer", return_value="yes")
    @patch("admin.onboard.wait_user_confirmation")
    @patch("admin.dongle_admin.DongleAdmin")
    def test_onboard_invalid_device_key(self, dongleAdmin, _unused1, _unused2,
                                        get_hsm_unlock, get_admin_hsm, hsm2Dongle,
                                        get_hsm_onboard, _unused3):
        get_hsm_onboard.return_value = hsm2Dongle
        get_hsm_unlock.return_value = hsm2Dongle
        get_admin_hsm.return_value = dongleAdmin

        hsm2Dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        hsm2Dongle.is_onboarded = Mock(return_value=True)
        dongleAdmin.get_device_key = Mock(return_value=self.INVALID_KEY)
        dongleAdmin.setup_endorsement_key = Mock(return_value=self.ENDORSEMENT_KEY)

        options = self.parser.parse_args(
            ['-p', self.VALID_PIN, '-o', 'a-path', 'onboard'])
        with self.assertRaises(ValueError):
            self.actions.get(options.operation, not_implemented)(options)

    @patch("admin.onboard.get_admin_hsm")
    @patch("admin.unlock.get_hsm")
    @patch("admin.onboard.get_user_answer", return_value="yes")
    @patch("admin.onboard.wait_user_confirmation")
    @patch("admin.dongle_admin.DongleAdmin")
    def test_onboard_invalid_attestation_key(self, dongleAdmin, _unused1, _unused2,
                                             get_hsm_unlock, get_admin_hsm, hsm2Dongle,
                                             get_hsm_onboard, _unused3):
        get_hsm_onboard.return_value = hsm2Dongle
        get_hsm_unlock.return_value = hsm2Dongle
        get_admin_hsm.return_value = dongleAdmin

        hsm2Dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        hsm2Dongle.is_onboarded = Mock(return_value=True)
        dongleAdmin.get_device_key = Mock(return_value=self.DEVICE_KEY)
        dongleAdmin.setup_endorsement_key = Mock(return_value=self.INVALID_KEY)

        options = self.parser.parse_args(
            ['-p', self.VALID_PIN, '-o', 'a-path', 'onboard'])
        with self.assertRaises(ValueError):
            self.actions.get(options.operation, not_implemented)(options)
