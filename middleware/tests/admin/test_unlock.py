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
from admin.misc import AdminError
from admin.unlock import do_unlock
from ledger.hsm2dongle import HSM2Dongle
from parameterized import parameterized

import logging

logging.disable(logging.CRITICAL)


@patch("sys.stdout.write")
@patch("admin.unlock.get_hsm")
class TestUnlock(TestCase):
    def setUp(self):
        self.valid_pin = '1234ABCD'
        self.invalid_pin = '123456789'

        options = {
            'pin': self.valid_pin,
            'any_pin': False,
            'no_exec': None,
            'verbose': False
        }
        self.default_options = SimpleNamespace(**options)
        self.dongle = Mock()

    @patch("admin.unlock.info")
    def test_unlock(self, info_mock, get_hsm, _):
        get_hsm.return_value = self.dongle
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)

        do_unlock(self.default_options)
        self.assertEqual(call('PIN accepted'), info_mock.call_args_list[7])

    def test_unlock_invalid_pin(self, get_hsm, _):
        get_hsm.return_value = self.dongle
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)

        options = self.default_options
        options.pin = self.invalid_pin
        with self.assertRaises(AdminError) as e:
            do_unlock(options)
        self.assertTrue(str(e.exception).startswith('Invalid pin given.'))

    def test_unlock_not_onboarded(self, get_hsm, _):
        get_hsm.return_value = self.dongle
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=False)

        with self.assertRaises(AdminError) as e:
            do_unlock(self.default_options)
        self.assertEqual('Device not onboarded', str(e.exception))

    @parameterized.expand([
        (HSM2Dongle.MODE.SIGNER, ),
        (HSM2Dongle.MODE.UI_HEARTBEAT, ),
    ])
    def test_unlock_invalid_mode(self, get_hsm, _, mode):
        get_hsm.return_value = self.dongle
        self.dongle.get_current_mode = Mock(return_value=mode)
        self.dongle.is_onboarded = Mock(return_value=True)

        with self.assertRaises(AdminError) as e:
            do_unlock(self.default_options)
        self.assertEqual('Device already unlocked', str(e.exception))

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.UNKNOWN)
        with self.assertRaises(AdminError) as e:
            do_unlock(self.default_options)

        self.assertTrue(str(e.exception).startswith('Device mode unknown.'))

    def test_unlock_wrong_pin(self, get_hsm, _):
        get_hsm.return_value = self.dongle
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        self.dongle.unlock = Mock(return_value=False)

        with self.assertRaises(AdminError) as e:
            do_unlock(self.default_options)
        self.assertEqual('Unable to unlock: PIN mismatch', str(e.exception))
