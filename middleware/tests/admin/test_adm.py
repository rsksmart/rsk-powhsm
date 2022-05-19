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

from argparse import Namespace
from unittest import TestCase
from unittest.mock import call, patch
from adm import main, DEFAULT_ATT_UD_SOURCE
import logging

logging.disable(logging.CRITICAL)


class TestAdmArgs(TestCase):
    @patch("adm.do_unlock")
    def test_unlock(self, do_unlock):
        expected_options = {
            'any_pin': False,
            'attestation_certificate_file_path': None,
            'attestation_ud_source': DEFAULT_ATT_UD_SOURCE,
            'ca': None,
            'new_pin': None,
            'no_exec': False,
            'no_unlock': False,
            'operation': 'unlock',
            'output_file_path': None,
            'pin': 'a-pin',
            'pubkeys_file_path': None,
            'root_authority': None,
            'verbose': False
        }
        expected_call_args_list = [
            call(Namespace(**expected_options)),
            call(Namespace(**expected_options))
        ]

        with patch('sys.argv', ['adm.py', '-p', 'a-pin', 'unlock']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch('sys.argv', ['adm.py', '--pin', 'a-pin', 'unlock']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        self.assertTrue(do_unlock.called)
        self.assertEqual(do_unlock.call_count, 2)
        self.assertEqual(expected_call_args_list, do_unlock.call_args_list)

    @patch("adm.do_onboard")
    def test_onboard(self, do_onboard):
        expected_options = {
            'any_pin': False,
            'attestation_certificate_file_path': None,
            'attestation_ud_source': DEFAULT_ATT_UD_SOURCE,
            'ca': None,
            'new_pin': None,
            'no_exec': False,
            'no_unlock': False,
            'operation': 'onboard',
            'output_file_path': 'a-path',
            'pin': 'a-pin',
            'pubkeys_file_path': None,
            'root_authority': None,
            'verbose': False
        }

        expected_call_args_list = [
            call(Namespace(**expected_options)),
            call(Namespace(**expected_options))
        ]

        with patch('sys.argv', ['adm.py', '-p', 'a-pin', '-o', 'a-path', 'onboard']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch('sys.argv',
                   ['adm.py', '--pin', 'a-pin', '--output', 'a-path', 'onboard']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        self.assertTrue(do_onboard.called)
        self.assertEqual(expected_call_args_list, do_onboard.call_args_list)

    @patch("adm.do_get_pubkeys")
    def test_pubkeys(self, do_get_pubkeys):
        expected_options = {
            'any_pin': False,
            'attestation_certificate_file_path': None,
            'attestation_ud_source': DEFAULT_ATT_UD_SOURCE,
            'ca': None,
            'new_pin': None,
            'no_exec': False,
            'no_unlock': True,
            'operation': 'pubkeys',
            'output_file_path': 'a-path',
            'pin': 'a-pin',
            'pubkeys_file_path': None,
            'root_authority': None,
            'verbose': False
        }

        expected_call_args_list = [
            call(Namespace(**expected_options)),
            call(Namespace(**expected_options))
        ]

        with patch('sys.argv', ['adm.py', '-p', 'a-pin', '-o', 'a-path', '-u',
                                'pubkeys']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch('sys.argv',
                   ['adm.py',
                    '--pin', 'a-pin',
                    '--output', 'a-path',
                    '--nounlock',
                    'pubkeys']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        self.assertTrue(do_get_pubkeys.called)
        self.assertEqual(expected_call_args_list, do_get_pubkeys.call_args_list)

    @patch("adm.do_changepin")
    def test_changepin(self, do_changepin):
        expected_options = {
            'any_pin': True,
            'attestation_certificate_file_path': None,
            'attestation_ud_source': DEFAULT_ATT_UD_SOURCE,
            'ca': None,
            'new_pin': 'new-pin',
            'no_exec': False,
            'no_unlock': False,
            'operation': 'changepin',
            'output_file_path': None,
            'pin': None,
            'pubkeys_file_path': None,
            'root_authority': None,
            'verbose': False
        }
        expected_call_args_list = [
            call(Namespace(**expected_options)),
            call(Namespace(**expected_options))
        ]

        with patch('sys.argv', ['adm.py', '-n', 'new-pin', '-a', 'changepin']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch('sys.argv', ['adm.py',
                                '--newpin', 'new-pin', '--anypin', 'changepin']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        self.assertTrue(do_changepin.called)
        self.assertEqual(do_changepin.call_count, 2)
        self.assertEqual(expected_call_args_list, do_changepin.call_args_list)

    @patch("adm.do_attestation")
    def test_attestation(self, do_attestation):
        expected_options = {
            'any_pin': False,
            'attestation_certificate_file_path': 'certification-path',
            'attestation_ud_source': DEFAULT_ATT_UD_SOURCE,
            'ca': 'ca-info',
            'new_pin': None,
            'no_exec': False,
            'no_unlock': False,
            'operation': 'attestation',
            'output_file_path': 'out-path',
            'pin': 'a-pin',
            'pubkeys_file_path': None,
            'root_authority': None,
            'verbose': False
        }
        expected_call_args_list = [
            call(Namespace(**expected_options)),
            call(Namespace(**expected_options))
        ]

        with patch('sys.argv', ['adm.py',
                                '-p', 'a-pin',
                                '-o', 'out-path',
                                '-c', 'ca-info',
                                '-t', 'certification-path',
                                'attestation']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch('sys.argv', ['adm.py',
                                '--pin', 'a-pin',
                                '--output', 'out-path',
                                '--ca', 'ca-info',
                                '--attcert', 'certification-path',
                                'attestation']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        self.assertTrue(do_attestation.called)
        self.assertEqual(do_attestation.call_count, 2)
        self.assertEqual(expected_call_args_list, do_attestation.call_args_list)

    @patch("adm.do_verify_attestation")
    def test_verify_attestation(self, do_verify_attestation):
        expected_options = {
            'any_pin': False,
            'attestation_certificate_file_path': 'certification-path',
            'attestation_ud_source': DEFAULT_ATT_UD_SOURCE,
            'ca': None,
            'new_pin': None,
            'no_exec': False,
            'no_unlock': False,
            'operation': 'verify_attestation',
            'output_file_path': None,
            'pin': 'a-pin',
            'pubkeys_file_path': 'pubkeys-path',
            'root_authority': 'root-authority',
            'verbose': False
        }
        expected_call_args_list = [
            call(Namespace(**expected_options)),
            call(Namespace(**expected_options))
        ]

        with patch('sys.argv', ['adm.py',
                                '-p', 'a-pin',
                                '-t', 'certification-path',
                                '-r', 'root-authority',
                                '-b', 'pubkeys-path',
                                'verify_attestation']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch('sys.argv', ['adm.py',
                                '--pin', 'a-pin',
                                '--attcert', 'certification-path',
                                '--root', 'root-authority',
                                '--pubkeys', 'pubkeys-path',
                                'verify_attestation']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        self.assertTrue(do_verify_attestation.called)
        self.assertEqual(do_verify_attestation.call_count, 2)
        self.assertEqual(expected_call_args_list, do_verify_attestation.call_args_list)
