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
@patch("admin.pubkeys.get_hsm")
@patch("ledger.hsm2dongle.HSM2Dongle")
class TestPubkeys(TestCase):
    VALID_PUBLIC_KEY = '04ef25f25c6b142785e4912b78eb08e8a47c03722af4d3c1705631e97868a5bddb4eaa821560b6a55942466084cabfba9233bfc564e60293663a0667cd3b6807e6' # noqa E501
    INVALID_PUBLIC_KEY = '04aabbccddee'

    def setUp(self):
        self.actions = create_actions()
        self.parser = create_parser(self.actions)

    def test_pubkeys(self, dongle, get_hsm, _):
        get_hsm.return_value = dongle

        dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.APP)
        dongle.get_public_key = Mock(return_value=self.VALID_PUBLIC_KEY)
        dongle.is_onboarded = Mock(return_value=True)

        options = self.parser.parse_args(['-u', 'pubkeys'])
        self.actions.get(options.operation, not_implemented)(options)

    def test_pubkeys_invalid_pubkey(self, dongle, get_hsm, _):
        get_hsm.return_value = dongle

        dongle.get_current_mode = Mock()
        dongle.get_public_key = Mock()
        dongle.is_onboarded = Mock()

        dongle.get_current_mode.return_value = HSM2Dongle.MODE.APP
        dongle.get_public_key.return_value = self.INVALID_PUBLIC_KEY
        dongle.is_onboarded.return_value = True

        options = self.parser.parse_args(['-u', 'pubkeys'])
        with self.assertRaises(AdminError):
            self.actions.get(options.operation, not_implemented)(options)

    def test_pubkeys_invalid_mode(self, dongle, get_hsm, _):
        get_hsm.return_value = dongle

        dongle.get_current_mode = Mock()
        dongle.get_public_key = Mock()
        dongle.is_onboarded = Mock()

        dongle.get_current_mode.return_value = HSM2Dongle.MODE.BOOTLOADER
        dongle.get_public_key.return_value = self.VALID_PUBLIC_KEY
        dongle.is_onboarded.return_value = True

        options = self.parser.parse_args(['-u', 'pubkeys'])
        with self.assertRaises(AdminError):
            self.actions.get(options.operation, not_implemented)(options)
