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
import json
from ledger.hsm2dongle import HSM2Dongle, HSM2DongleError

import logging


logging.disable(logging.CRITICAL)


@patch("sys.stdout.write")
@patch("admin.onboard.info")
@patch("admin.onboard.get_hsm")
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
        self.expected_cert = HSMCertificate()
        self.expected_cert.add_element(
            HSMCertificateElement({
                "name": "attestation",
                "message": self.ENDORSEMENT_KEY["message"],
                "signature": self.ENDORSEMENT_KEY["signature"],
                "signed_by": "device",
            })
        )
        self.expected_cert.add_element(
            HSMCertificateElement({
                "name": "device",
                "message": self.DEVICE_KEY["message"],
                "signature": self.DEVICE_KEY["signature"],
                "signed_by": "root",
            })
        )
        self.expected_cert.add_target("attestation")
        self.dongle = Mock()

    @patch("admin.onboard.get_admin_hsm")
    @patch("admin.unlock.get_hsm")
    @patch("sys.stdin.readline")
    def test_onboard(self, readline, get_hsm_unlock, get_admin_hsm,
                     get_hsm_onboard, info_mock, _):
        get_hsm_onboard.return_value = self.dongle
        get_hsm_unlock.return_value = self.dongle
        get_admin_hsm.return_value = self.dongle

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.get_device_key = Mock(return_value=self.DEVICE_KEY)
        self.dongle.setup_endorsement_key = Mock(return_value=self.ENDORSEMENT_KEY)
        self.dongle.handshake = Mock()
        self.dongle.onboard = Mock()

        certificate_path = 'cert-path'

        readline.return_value = "yes\n"

        with patch('sys.argv',
                   ['adm.py',
                    '-p', self.VALID_PIN,
                    '-o', certificate_path,
                    'onboard']):
            with patch('builtins.open', mock_open()) as file_mock:
                main()

            self.assertTrue(info_mock.call_args_list[5][0][0] == 'Onboarded: Yes')
            self.assertTrue(info_mock.call_args_list[10][0][0] == 'Onboarded')
            self.assertTrue(info_mock.call_args_list[14][0][0] == 'Device key gathered')
            self.assertTrue(info_mock.call_args_list[16][0][0] ==
                            'Attestation key setup complete')

            self.assertEqual([call(certificate_path, 'w')], file_mock.call_args_list)
            self.assertEqual([call("%s\n" %
                             json.dumps(self.expected_cert.to_dict(), indent=2))],
                             file_mock.return_value.write.call_args_list)
            self.assertTrue(self.dongle.onboard.called)
            self.assertTrue(self.dongle.handshake.called)

    @patch("admin.onboard.get_admin_hsm")
    @patch("admin.unlock.get_hsm")
    @patch("sys.stdin.readline")
    def test_onboard_onboard_error(self, readline, get_hsm_unlock, get_admin_hsm,
                                   get_hsm_onboard, *_):
        get_hsm_onboard.return_value = self.dongle
        get_hsm_unlock.return_value = self.dongle
        get_admin_hsm.return_value = self.dongle

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.get_device_key = Mock()
        self.dongle.setup_endorsement_key = Mock()
        self.dongle.handshake = Mock()
        self.dongle.onboard = Mock(side_effect=HSM2DongleError('error-msg'))

        certificate_path = 'cert-path'

        readline.return_value = "yes\n"

        with patch('sys.argv',
                   ['adm.py',
                    '-p', self.VALID_PIN,
                    '-o', certificate_path,
                    'onboard']):
            with patch('builtins.open', mock_open()) as file_mock:
                with self.assertRaises(HSM2DongleError) as e:
                    main()
            self.assertTrue(self.dongle.onboard.called)
            self.assertEqual('error-msg', str(e.exception))
            self.assertFalse(self.dongle.get_device_key.called)
            self.assertFalse(self.dongle.setup_endorsement_key.called)
            self.assertFalse(self.dongle.handshake.called)
            self.assertFalse(file_mock.return_value.write.called)

    @patch("admin.onboard.get_admin_hsm")
    @patch("admin.unlock.get_hsm")
    @patch("sys.stdin.readline")
    def test_onboard_handshake_error(self, readline, get_hsm_unlock, get_admin_hsm,
                                     get_hsm_onboard, *_):
        get_hsm_onboard.return_value = self.dongle
        get_hsm_unlock.return_value = self.dongle
        get_admin_hsm.return_value = self.dongle

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.get_device_key = Mock()
        self.dongle.setup_endorsement_key = Mock()
        self.dongle.handshake = Mock(side_effect=HSM2DongleError('error-msg'))
        self.dongle.onboard = Mock()

        certificate_path = 'cert-path'

        readline.return_value = "yes\n"

        with patch('sys.argv',
                   ['adm.py',
                    '-p', self.VALID_PIN,
                    '-o', certificate_path,
                    'onboard']):
            with patch('builtins.open', mock_open()) as file_mock:
                with self.assertRaises(HSM2DongleError) as e:
                    main()
            self.assertEqual('error-msg', str(e.exception))
            self.assertTrue(self.dongle.onboard.called)
            self.assertTrue(self.dongle.handshake.called)
            self.assertFalse(self.dongle.get_device_key.called)
            self.assertFalse(self.dongle.setup_endorsement_key.called)
            self.assertFalse(file_mock.return_value.write.called)

    @patch("admin.onboard.get_admin_hsm")
    @patch("admin.unlock.get_hsm")
    @patch("sys.stdin.readline")
    def test_onboard_getkey_error(self, readline, get_hsm_unlock, get_admin_hsm,
                                  get_hsm_onboard, *_):
        get_hsm_onboard.return_value = self.dongle
        get_hsm_unlock.return_value = self.dongle
        get_admin_hsm.return_value = self.dongle

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.get_device_key = Mock(side_effect=HSM2DongleError('error-msg'))
        self.dongle.setup_endorsement_key = Mock()
        self.dongle.handshake = Mock()
        self.dongle.onboard = Mock()

        certificate_path = 'cert-path'

        readline.return_value = "yes\n"

        with patch('sys.argv',
                   ['adm.py',
                    '-p', self.VALID_PIN,
                    '-o', certificate_path,
                    'onboard']):
            with patch('builtins.open', mock_open()) as file_mock:
                with self.assertRaises(HSM2DongleError) as e:
                    main()
            self.assertEqual('error-msg', str(e.exception))
            self.assertTrue(self.dongle.onboard.called)
            self.assertTrue(self.dongle.handshake.called)
            self.assertTrue(self.dongle.get_device_key.called)
            self.assertFalse(self.dongle.setup_endorsement_key.called)
            self.assertFalse(file_mock.return_value.write.called)

    @patch("admin.onboard.get_admin_hsm")
    @patch("admin.unlock.get_hsm")
    @patch("sys.stdin.readline")
    def test_onboard_setupkey_error(self, readline, get_hsm_unlock, get_admin_hsm,
                                    get_hsm_onboard, *_):
        get_hsm_onboard.return_value = self.dongle
        get_hsm_unlock.return_value = self.dongle
        get_admin_hsm.return_value = self.dongle

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.get_device_key = Mock()
        self.dongle.setup_endorsement_key = Mock(side_effect=HSM2DongleError('error-msg'))
        self.dongle.handshake = Mock()
        self.dongle.onboard = Mock()

        certificate_path = 'cert-path'

        readline.return_value = "yes\n"

        with patch('sys.argv',
                   ['adm.py',
                    '-p', self.VALID_PIN,
                    '-o', certificate_path,
                    'onboard']):
            with patch('builtins.open', mock_open()) as file_mock:
                with self.assertRaises(HSM2DongleError) as e:
                    main()
            self.assertEqual('error-msg', str(e.exception))
            self.assertTrue(self.dongle.onboard.called)
            self.assertTrue(self.dongle.handshake.called)
            self.assertTrue(self.dongle.get_device_key.called)
            self.assertTrue(self.dongle.setup_endorsement_key.called)
            self.assertFalse(file_mock.return_value.write.called)

    @patch("admin.onboard.get_admin_hsm")
    @patch("admin.unlock.get_hsm")
    @patch("sys.stdin.readline")
    def test_onboard_user_cancelled(self, readline, hsm_unlock, hsm_admin,
                                    hsm_onboard, *_):
        hsm_onboard.return_value = self.dongle
        hsm_unlock.return_value = self.dongle
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.onboard = Mock()
        hsm_admin.return_value = self.dongle
        certificate_path = 'cert-path'
        readline.return_value = "no\n"

        with patch('sys.argv',
                   ['adm.py',
                    '-p', self.VALID_PIN,
                    '-o', certificate_path,
                    'onboard']):
            with patch('builtins.open', mock_open()) as file_mock:
                with self.assertRaises(AdminError) as e:
                    main()
        self.assertEqual('Cancelled by user', str(e.exception))
        self.assertFalse(self.dongle.onboard.called)
        self.assertFalse(self.dongle.get_device_key.called)
        self.assertFalse(self.dongle.setup_endorsement_key.called)
        self.assertFalse(file_mock.return_value.write.called)

    @patch("sys.stdin.readline")
    def test_onboard_no_output_file(self, readline, get_hsm, *_):
        readline.return_value = "yes\n"
        get_hsm.return_value = self.dongle

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.onboard = Mock()

        with patch('sys.argv',
                   ['adm.py',
                    '-p', self.VALID_PIN,
                    'onboard']):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual('No output file path given', str(e.exception))
        self.assertFalse(self.dongle.onboard.called)

    def test_onboard_invalid_pin(self, *_):
        with patch('sys.argv',
                   ['adm.py',
                    '-p', self.INVALID_PIN,
                    '-o', 'a-path',
                    'onboard']):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertTrue(str(e.exception).startswith('Invalid pin given.'))

    def test_onboard_invalid_mode(self, get_hsm, *_):
        get_hsm.return_value = self.dongle
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.APP)
        self.dongle.is_onboarded = Mock(return_value=True)

        with patch('sys.argv',
                   ['adm.py',
                    '-p', self.VALID_PIN,
                    '-o', 'a-path',
                    'onboard']):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertTrue(str(e.exception).startswith('Device not in bootloader mode.'))

    @patch("admin.onboard.get_admin_hsm")
    @patch("admin.unlock.get_hsm")
    @patch("sys.stdin.readline")
    def test_onboard_invalid_device_key(self, readline, get_hsm_unlock, get_admin_hsm,
                                        get_hsm_onboard, *_):
        get_hsm_onboard.return_value = self.dongle
        get_hsm_unlock.return_value = self.dongle
        get_admin_hsm.return_value = self.dongle

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.get_device_key = Mock(return_value=self.INVALID_KEY)
        self.dongle.setup_endorsement_key = Mock(return_value=self.ENDORSEMENT_KEY)

        certificate_path = 'cert-path'

        readline.return_value = "yes\n"

        with patch('sys.argv',
                   ['adm.py',
                    '-p', self.VALID_PIN,
                    '-o', certificate_path,
                    'onboard']):
            with self.assertRaises(ValueError) as e:
                main()
            self.assertEqual(('Missing or invalid message for HSM certificate element'
                              ' device'), str(e.exception))

    @patch("admin.onboard.get_admin_hsm")
    @patch("admin.unlock.get_hsm")
    @patch("sys.stdin.readline")
    def test_onboard_invalid_attestation_key(self, readline, get_hsm_unlock,
                                             get_admin_hsm, get_hsm_onboard, *_):
        get_hsm_onboard.return_value = self.dongle
        get_hsm_unlock.return_value = self.dongle
        get_admin_hsm.return_value = self.dongle

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.get_device_key = Mock(return_value=self.DEVICE_KEY)
        self.dongle.setup_endorsement_key = Mock(return_value=self.INVALID_KEY)

        certificate_path = 'cert-path'

        readline.return_value = "yes\n"

        with patch('sys.argv',
                   ['adm.py',
                    '-p', self.VALID_PIN,
                    '-o', certificate_path,
                    'onboard']):
            with self.assertRaises(ValueError) as e:
                main()
            self.assertEqual(('Missing or invalid message for HSM certificate element'
                              ' attestation'), str(e.exception))
