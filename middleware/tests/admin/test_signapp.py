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
from signapp import create_parser, do_main

import logging

logging.disable(logging.CRITICAL)

RETURN_SUCCESS = 0


@patch("sys.stdout.write")
class TestSignApp(TestCase):
    def setUp(self):
        self.parser = create_parser()

    def test_args(self, _):
        options = self.parser.parse_args([
            '-a', 'a-path',
            '-o', 'out-path',
            '-p', 'sign-path',
            '-k', '11223344556677',
            '-v',
            'hash'
        ])
        self.assertEqual(options.app_path, 'a-path')
        self.assertEqual(options.output_path, 'out-path')
        self.assertEqual(options.path, 'sign-path')
        self.assertEqual(options.key, '11223344556677')
        self.assertEqual(options.verbose, True)
        self.assertEqual(options.operation, 'hash')

    @patch("signapp.compute_app_hash", return_value=b"1122334455")
    def test_key(self, *_):
        key = '112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00'
        options = self.parser.parse_args([
            '-a', 'a-path',
            '-o', 'out-path',
            '-k', key,
            'key'
        ])

        with self.assertRaises(SystemExit) as exit:
            do_main(options)
        self.assertEqual(exit.exception.code, RETURN_SUCCESS)

    @patch("signapp.compute_app_hash", side_effect=Exception)
    def test_key_invalid_app_hash(self, *_):
        key = '112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00'
        options = self.parser.parse_args([
            '-a', 'a-path',
            '-o', 'out-path',
            '-k', key,
            'key'
        ])

        with self.assertRaises(SystemExit) as exit:
            do_main(options)
        self.assertNotEqual(exit.exception.code, RETURN_SUCCESS)

    @patch("signapp.compute_app_hash", return_value=b"1122334455")
    def test_key_no_key(self, *_):
        options = self.parser.parse_args([
            '-a', 'a-path',
            '-o', 'out-path',
            'key'
        ])

        with self.assertRaises(SystemExit) as exit:
            do_main(options)
        self.assertNotEqual(exit.exception.code, RETURN_SUCCESS)

    @patch("signapp.compute_app_hash", return_value=b"1122334455")
    def test_key_invalid_key(self, *_):
        key = '11223344'
        options = self.parser.parse_args([
            '-a', 'a-path',
            '-o', 'out-path',
            '-k', key,
            'key'
        ])

        with self.assertRaises(SystemExit) as exit:
            do_main(options)
        self.assertNotEqual(exit.exception.code, RETURN_SUCCESS)

    @patch("signapp.compute_app_hash", return_value=b"1122334455")
    def test_hash(self, *_):
        options = self.parser.parse_args([
            '-a', 'a-path',
            '-o', 'out-path',
            'hash'
        ])

        with self.assertRaises(SystemExit) as exit:
            do_main(options)
        self.assertEqual(exit.exception.code, RETURN_SUCCESS)

    @patch("signapp.compute_app_hash", side_effect=Exception)
    def test_hash_invalid_app_hash(self, *_):
        options = self.parser.parse_args([
            '-a', 'a-path',
            '-o', 'out-path',
            'hash'
        ])

        with self.assertRaises(SystemExit) as exit:
            do_main(options)
        self.assertNotEqual(exit.exception.code, RETURN_SUCCESS)

    @patch("signapp.compute_app_hash", return_value=b"1122334455")
    @patch("ecdsa.VerifyingKey.verify_digest", return_value=True)
    @patch("signapp.get_hsm")
    @patch("ledger.hsm2dongle.HSM2Dongle")
    def test_ledger(self, dongle, get_hsm, *_):
        key = bytes.fromhex('04b76bfeb41e93536c95d2ea28125bc5016889f4fdd32515bdecc4b0d2cea0d2633b732d7a092b1125b05c07053cc96f30094467811da87a85bc9d0b24efceaa1f')  # noqa E501
        get_hsm.return_value = dongle
        dongle._send_command = Mock(return_value=key)

        options = self.parser.parse_args([
            '-a', 'a-path',
            '-o', 'out-path',
            '-p', "m/44'/0'/0'/0/0",
            'ledger'
        ])

        with self.assertRaises(SystemExit) as exit:
            do_main(options)
        self.assertEqual(exit.exception.code, RETURN_SUCCESS)

    @patch("signapp.compute_app_hash", side_effect=Exception)
    @patch("ecdsa.VerifyingKey.verify_digest", return_value=True)
    @patch("signapp.get_hsm")
    @patch("ledger.hsm2dongle.HSM2Dongle")
    def test_ledger_invalid_app_hash(self, dongle, get_hsm, *_):
        key = bytes.fromhex('04b76bfeb41e93536c95d2ea28125bc5016889f4fdd32515bdecc4b0d2cea0d2633b732d7a092b1125b05c07053cc96f30094467811da87a85bc9d0b24efceaa1f')  # noqa E501
        get_hsm.return_value = dongle
        dongle._send_command = Mock(return_value=key)

        options = self.parser.parse_args([
            '-a', 'a-path',
            '-o', 'out-path',
            '-p', "m/44'/0'/0'/0/0",
            'ledger'
        ])

        with self.assertRaises(SystemExit) as exit:
            do_main(options)
        self.assertNotEqual(exit.exception.code, RETURN_SUCCESS)

    @patch("signapp.compute_app_hash", return_value=b"1122334455")
    @patch("ecdsa.VerifyingKey.verify_digest", return_value=True)
    @patch("signapp.get_hsm")
    @patch("ledger.hsm2dongle.HSM2Dongle")
    def test_ledger_invalid_key(self, dongle, get_hsm, *_):
        key = bytes.fromhex('11223344')
        get_hsm.return_value = dongle
        dongle._send_command = Mock(return_value=key)

        options = self.parser.parse_args([
            '-a', 'a-path',
            '-o', 'out-path',
            '-p', "m/44'/0'/0'/0/0",
            'ledger'
        ])

        with self.assertRaises(SystemExit) as exit:
            do_main(options)
        self.assertNotEqual(exit.exception.code, RETURN_SUCCESS)
