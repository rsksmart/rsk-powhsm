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

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, call, patch
from admin.changepin import do_changepin
from admin.misc import AdminError
from ledger.hsm2dongle import HSM2Dongle

import logging

logging.disable(logging.CRITICAL)


@patch("sys.stdout.write")
@patch("admin.changepin.get_hsm")
class TestChangepin(TestCase):
    VALID_PIN = '1234ABCD'
    INVALID_PIN = '123456789'

    def setUp(self):
        options = {
            'new_pin': self.VALID_PIN,
            'no_unlock': False,
            'any_pin': False,
            'verbose': False,
            'pin': self.VALID_PIN
        }
        self.default_options = SimpleNamespace(**options)
        self.dongle = Mock()

    @patch("admin.changepin.do_unlock")
    def test_changepin(self, do_unlock_mock, get_hsm, _):
        get_hsm.return_value = self.dongle
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.new_pin = Mock(return_value=True)

        do_changepin(self.default_options)

        self.assertTrue(do_unlock_mock.called)
        self.assertTrue(self.dongle.new_pin.called)
        self.assertEqual([call(self.VALID_PIN.encode())],
                         self.dongle.new_pin.call_args_list)

    @patch("admin.changepin.do_unlock")
    def test_changepin_unlock_error(self, do_unlock_mock, get_hsm, _):
        get_hsm.return_value = self.dongle
        do_unlock_mock.side_effect = Exception('unlock-error')
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.new_pin = Mock(return_value=True)

        with self.assertRaises(AdminError) as e:
            do_changepin(self.default_options)

        self.assertEqual('Failed to unlock device: unlock-error', str(e.exception))

    @patch("admin.changepin.do_unlock")
    def test_changepin_invalid_mode(self, do_unlock_mock, get_hsm, _):
        get_hsm.return_value = self.dongle
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.SIGNER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.new_pin = Mock(return_value=True)

        with self.assertRaises(AdminError) as e:
            do_changepin(self.default_options)

        self.assertTrue(do_unlock_mock.called)
        self.assertTrue(str(e.exception).startswith('Device not in bootloader mode.'))
        self.assertFalse(self.dongle.new_pin.called)

    def test_changepin_invalid_pin(self, get_hsm, _):
        get_hsm.return_value = self.dongle

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.new_pin = Mock(return_value=True)

        options = self.default_options
        options.new_pin = self.INVALID_PIN
        with self.assertRaises(AdminError) as e:
            do_changepin(options)

        self.assertTrue(str(e.exception).startswith('Invalid pin given.'))
        self.assertFalse(self.dongle.new_pin.called)

    @patch("admin.changepin.do_unlock")
    def test_changepin_newpin_error(self, do_unlock_mock, get_hsm, _):
        get_hsm.return_value = self.dongle
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.new_pin = Mock(return_value=False)

        with self.assertRaises(AdminError) as e:
            do_changepin(self.default_options)

        self.assertTrue(do_unlock_mock.called)
        self.assertEqual('Failed to change pin', str(e.exception))
