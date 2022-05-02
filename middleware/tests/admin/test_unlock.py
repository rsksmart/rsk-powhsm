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
@patch("admin.unlock.get_hsm")
@patch("ledger.hsm2dongle.HSM2Dongle")
class TestUnlock(TestCase):
    VALID_PIN = '1234ABCD'
    INVALID_PIN = '123456789'

    def setUp(self):
        self.actions = create_actions()
        self.parser = create_parser(self.actions)

    def test_unlock(self, dongle, get_hsm, _):
        get_hsm.return_value = dongle

        dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        dongle.is_onboarded = Mock(return_value=True)

        options = self.parser.parse_args(['-p', self.VALID_PIN, 'unlock'])
        self.actions.get(options.operation, not_implemented)(options)

    def test_unlock_invalid_pin(self, dongle, get_hsm, _):
        get_hsm.return_value = dongle

        dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        dongle.is_onboarded = Mock(return_value=True)

        options = self.parser.parse_args(['-p', self.INVALID_PIN, 'unlock'])
        with self.assertRaises(AdminError):
            self.actions.get(options.operation, not_implemented)(options)

    def test_unlock_not_onboarded(self, dongle, get_hsm, _):
        get_hsm.return_value = dongle

        dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        dongle.is_onboarded = Mock(return_value=False)

        options = self.parser.parse_args(['-p', self.VALID_PIN, 'unlock'])
        with self.assertRaises(AdminError):
            self.actions.get(options.operation, not_implemented)(options)

    def test_unlock_mode(self, dongle, get_hsm, _):
        get_hsm.return_value = dongle

        dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.APP)
        dongle.is_onboarded = Mock(return_value=True)

        options = self.parser.parse_args(['-p', self.VALID_PIN, 'unlock'])
        with self.assertRaises(AdminError):
            self.actions.get(options.operation, not_implemented)(options)
