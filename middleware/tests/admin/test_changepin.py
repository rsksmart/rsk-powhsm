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
from unittest.mock import Mock, call, patch
from adm import main
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
        self.dongle = Mock()

    def test_changepin(self, get_hsm, _):
        get_hsm.return_value = self.dongle

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.new_pin = Mock(return_value=True)

        with patch('sys.argv', ['adm.py', '-n', self.VALID_PIN, '-u', 'changepin']):
            main()
        self.assertTrue(self.dongle.new_pin.called)
        self.assertEqual([call(self.VALID_PIN.encode())],
                         self.dongle.new_pin.call_args_list)

    def test_changepin_invalid_mode(self, get_hsm, _):
        get_hsm.return_value = self.dongle

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.APP)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.new_pin = Mock(return_value=True)

        with patch('sys.argv', ['adm.py', '-n', self.VALID_PIN, '-u', 'changepin']):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertTrue(str(e.exception).startswith('Device not in bootloader mode.'))
        self.assertFalse(self.dongle.new_pin.called)

    def test_changepin_invalid_pin(self, get_hsm, _):
        get_hsm.return_value = self.dongle

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.new_pin = Mock(return_value=True)

        with patch('sys.argv', ['adm.py', '-n', self.INVALID_PIN, '-u', 'changepin']):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertTrue(str(e.exception).startswith('Invalid pin given.'))
        self.assertFalse(self.dongle.new_pin.called)

    def test_changepin_newpin_error(self, get_hsm, _):
        get_hsm.return_value = self.dongle

        self.dongle.get_current_mode = Mock()
        self.dongle.is_onboarded = Mock()
        self.dongle.new_pin = Mock()

        self.dongle.get_current_mode.return_value = HSM2Dongle.MODE.BOOTLOADER
        self.dongle.is_onboarded.return_value = True
        self.dongle.new_pin.return_value = False

        with patch('sys.argv', ['adm.py', '-n', self.VALID_PIN, '-u', 'changepin']):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual('Failed to change pin', str(e.exception))
