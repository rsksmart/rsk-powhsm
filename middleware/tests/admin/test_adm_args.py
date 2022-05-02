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
from adm import create_actions, create_parser
from admin.attestation import do_attestation
from admin.changepin import do_changepin
from admin.onboard import do_onboard
from admin.pubkeys import do_get_pubkeys
from admin.unlock import do_unlock
from admin.verify_attestation import do_verify_attestation

import logging

logging.disable(logging.CRITICAL)


class TestAdmArgs(TestCase):
    def setUp(self):
        self.actions = create_actions()
        self.parser = create_parser(self.actions)

    def test_create_actions(self):
        self.assertEqual(self.actions["unlock"], do_unlock)
        self.assertEqual(self.actions["onboard"], do_onboard)
        self.assertEqual(self.actions["pubkeys"], do_get_pubkeys)
        self.assertEqual(self.actions["changepin"], do_changepin)
        self.assertEqual(self.actions["attestation"], do_attestation)
        self.assertEqual(self.actions["verify_attestation"], do_verify_attestation)

    def test_unlock_args(self):
        options = self.parser.parse_args(['-p', 'a-pin', 'unlock'])
        self.assertEqual(options.operation, 'unlock')
        self.assertEqual(options.pin, 'a-pin')
        self.assertFalse(options.no_exec)
        self.assertFalse(options.verbose)

    def test_unlock_args_long(self):
        options = self.parser.parse_args(['--pin', 'a-pin', 'unlock'])
        self.assertEqual(options.operation, 'unlock')
        self.assertEqual(options.pin, 'a-pin')
        self.assertFalse(options.no_exec)
        self.assertFalse(options.verbose)

    def test_onboard_args(self):
        options = self.parser.parse_args(['-p', 'a-pin', '-o', 'a-path', 'onboard'])
        self.assertEqual(options.operation, 'onboard')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.output_file_path, 'a-path')
        self.assertFalse(options.verbose)

    def test_onboard_args_long(self):
        options = self.parser.parse_args(
            ['--pin', 'a-pin', '--output', 'a-path', 'onboard'])
        self.assertEqual(options.operation, 'onboard')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.output_file_path, 'a-path')
        self.assertFalse(options.verbose)

    def test_pubkeys_args(self):
        options = self.parser.parse_args(['-p', 'a-pin', '-o', 'a-path', '-u', 'pubkeys'])
        self.assertEqual(options.operation, 'pubkeys')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.output_file_path, 'a-path')
        self.assertTrue(options.no_unlock)
        self.assertFalse(options.verbose)

    def test_pubkeys_args_long(self):
        options = self.parser.parse_args(
            ['--pin', 'a-pin', '--output', 'a-path', '--nounlock', 'pubkeys'])
        self.assertEqual(options.operation, 'pubkeys')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.output_file_path, 'a-path')
        self.assertTrue(options.no_unlock)
        self.assertFalse(options.verbose)

    def test_pubkeys_no_unlock_args(self):
        options = self.parser.parse_args(['-p', 'a-pin', '-o', 'a-path', '-u', 'pubkeys'])
        self.assertEqual(options.operation, 'pubkeys')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.output_file_path, 'a-path')
        self.assertTrue(options.no_unlock)
        self.assertFalse(options.verbose)

    def test_pubkeys_no_unlock_args_long(self):
        options = self.parser.parse_args(
            ['--pin', 'a-pin', '--output', 'a-path', '--nounlock', 'pubkeys'])
        self.assertEqual(options.operation, 'pubkeys')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.output_file_path, 'a-path')
        self.assertTrue(options.no_unlock)
        self.assertFalse(options.verbose)

    def test_changepin_args(self):
        options = self.parser.parse_args(['-p', 'a-pin', '-n', 'new-pin', 'changepin'])
        self.assertEqual(options.operation, 'changepin')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.new_pin, 'new-pin')
        self.assertFalse(options.no_unlock)
        self.assertFalse(options.verbose)
        self.assertFalse(options.any_pin)

    def test_changepin_args_long(self):
        options = self.parser.parse_args(
            ['--pin', 'a-pin', '--newpin', 'new-pin', 'changepin'])
        self.assertEqual(options.operation, 'changepin')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.new_pin, 'new-pin')
        self.assertFalse(options.no_unlock)
        self.assertFalse(options.verbose)
        self.assertFalse(options.any_pin)

    def test_changepin_anypin_args(self):
        options = self.parser.parse_args(
            ['-p', 'a-pin', '-n', 'new-pin', '-a', 'changepin'])
        self.assertEqual(options.operation, 'changepin')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.new_pin, 'new-pin')
        self.assertFalse(options.no_unlock)
        self.assertFalse(options.verbose)
        self.assertTrue(options.any_pin)

    def test_changepin_anypin_args_long(self):
        options = self.parser.parse_args(
            ['--pin', 'a-pin', '--newpin', 'new-pin', '--anypin', 'changepin'])
        self.assertEqual(options.operation, 'changepin')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.new_pin, 'new-pin')
        self.assertFalse(options.no_unlock)
        self.assertFalse(options.verbose)
        self.assertTrue(options.any_pin)

    def test_changepin_no_unlock_args(self):
        options = self.parser.parse_args(
            ['-p', 'a-pin', '-n', 'new-pin', '-u', 'changepin'])
        self.assertEqual(options.operation, 'changepin')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.new_pin, 'new-pin')
        self.assertTrue(options.no_unlock)
        self.assertFalse(options.verbose)

    def test_changepin_no_unlock_args_long(self):
        options = self.parser.parse_args(
            ['--pin', 'a-pin', '--newpin', 'new-pin', '--nounlock', 'changepin'])
        self.assertEqual(options.operation, 'changepin')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.new_pin, 'new-pin')
        self.assertTrue(options.no_unlock)
        self.assertFalse(options.verbose)

    def test_attestation_args(self):
        options = self.parser.parse_args([
            '-p', 'a-pin', '-o', 'out-path', '-c', 'ca-info', '-t', 'certification-path',
            'attestation'
        ])
        self.assertEqual(options.operation, 'attestation')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.output_file_path, 'out-path')
        self.assertEqual(options.ca, 'ca-info')
        self.assertEqual(options.attestation_certificate_file_path, 'certification-path')
        self.assertFalse(options.verbose)

    def test_attestation_args_long(self):
        options = self.parser.parse_args([
            '--pin', 'a-pin', '--output', 'out-path', '--ca', 'ca-info', '--attcert',
            'certification-path', 'attestation'
        ])
        self.assertEqual(options.operation, 'attestation')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.output_file_path, 'out-path')
        self.assertEqual(options.ca, 'ca-info')
        self.assertEqual(options.attestation_certificate_file_path, 'certification-path')
        self.assertFalse(options.verbose)

    def test_verify_attestation_args(self):
        options = self.parser.parse_args([
            '-p', 'a-pin', '-t', 'certification-path', '-r', 'root-authority', '-b',
            'pubkeys-path', 'verify_attestation'
        ])
        self.assertEqual(options.operation, 'verify_attestation')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.attestation_certificate_file_path, 'certification-path')
        self.assertEqual(options.root_authority, 'root-authority')
        self.assertEqual(options.pubkeys_file_path, 'pubkeys-path')
        self.assertFalse(options.verbose)

    def test_verify_attestation_args_long(self):
        options = self.parser.parse_args([
            '--pin', 'a-pin', '--attcert', 'certification-path', '--root',
            'root-authority', '--pubkeys', 'pubkeys-path', 'verify_attestation'
        ])
        self.assertEqual(options.operation, 'verify_attestation')
        self.assertEqual(options.pin, 'a-pin')
        self.assertEqual(options.attestation_certificate_file_path, 'certification-path')
        self.assertEqual(options.root_authority, 'root-authority')
        self.assertEqual(options.pubkeys_file_path, 'pubkeys-path')
        self.assertFalse(options.verbose)
