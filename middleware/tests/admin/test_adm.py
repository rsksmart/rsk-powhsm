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

import sys
from argparse import Namespace
from unittest import TestCase
from unittest.mock import call, patch
from adm import main, DEFAULT_ATT_UD_SOURCE
import logging

logging.disable(logging.CRITICAL)


class TestAdm(TestCase):
    def setUp(self):
        self.old_stderr = sys.stderr
        # sys.stderr = Mock()
        self.old_stdout = sys.stdout
        # sys.stdout = Mock()
        self.DEFAULT_OPTIONS = {
            "any_pin": False,
            "attestation_certificate_file_path": None,
            "attestation_ud_source": DEFAULT_ATT_UD_SOURCE,
            "new_pin": None,
            "no_exec": False,
            "no_unlock": False,
            "operation": None,
            "output_file_path": None,
            "pin": None,
            "pubkeys_file_path": None,
            "root_authority": None,
            "signer_authorization_file_path": None,
            "verbose": False,
        }

    def tearDown(self):
        sys.stderr = self.old_stderr
        sys.stdout = self.old_stdout

    @patch("adm.do_unlock")
    def test_unlock(self, do_unlock):
        expected_options = {
            **self.DEFAULT_OPTIONS,
            'operation': 'unlock',
            'pin': 'a-pin',
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
            **self.DEFAULT_OPTIONS,
            'operation': 'onboard',
            'output_file_path': 'a-path',
            'pin': 'a-pin',
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
            **self.DEFAULT_OPTIONS,
            'no_unlock': True,
            'operation': 'pubkeys',
            'output_file_path': 'a-path',
            'pin': 'a-pin',
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
            **self.DEFAULT_OPTIONS,
            'any_pin': True,
            'new_pin': 'new-pin',
            'operation': 'changepin',
            'pin': 'old-pin',
        }
        expected_call_args_list = [
            call(Namespace(**expected_options)),
            call(Namespace(**expected_options))
        ]

        with patch('sys.argv', ['adm.py', '-p', 'old-pin', '-n', 'new-pin',
                                '-a', 'changepin']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch('sys.argv', ['adm.py',
                                '--newpin', 'new-pin', '--anypin', 'changepin',
                                '--pin', 'old-pin']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        self.assertTrue(do_changepin.called)
        self.assertEqual(do_changepin.call_count, 2)
        self.assertEqual(expected_call_args_list, do_changepin.call_args_list)

    @patch("adm.do_attestation")
    def test_attestation(self, do_attestation):
        expected_options = {
            **self.DEFAULT_OPTIONS,
            'attestation_certificate_file_path': 'certification-path',
            'attestation_ud_source': 'user-defined-source',
            'operation': 'attestation',
            'output_file_path': 'out-path',
            'pin': 'a-pin',
        }
        expected_call_args_list = [
            call(Namespace(**expected_options)),
            call(Namespace(**expected_options))
        ]

        with patch('sys.argv', ['adm.py',
                                '-p', 'a-pin',
                                '-o', 'out-path',
                                '-t', 'certification-path',
                                '--attudsource', 'user-defined-source',
                                'attestation']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch('sys.argv', ['adm.py',
                                '--pin', 'a-pin',
                                '--output', 'out-path',
                                '--attcert', 'certification-path',
                                '--attudsource', 'user-defined-source',
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
            **self.DEFAULT_OPTIONS,
            'attestation_certificate_file_path': 'certification-path',
            'operation': 'verify_attestation',
            'pin': 'a-pin',
            'pubkeys_file_path': 'pubkeys-path',
            'root_authority': 'root-authority',
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

    @patch("adm.do_authorize_signer")
    def test_authorize_signer(self, do_authorize_signer):
        expected_options = {
            **self.DEFAULT_OPTIONS,
            'operation': 'authorize_signer',
            'pin': 'a-pin',
            'signer_authorization_file_path': 'a-file-path',
        }
        expected_call_args_list = [
            call(Namespace(**expected_options)),
            call(Namespace(**expected_options))
        ]

        with patch('sys.argv', ['adm.py',
                                '-p', 'a-pin',
                                '-z', 'a-file-path',
                                'authorize_signer']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch('sys.argv', ['adm.py',
                                '--pin', 'a-pin',
                                '--signauth', 'a-file-path',
                                'authorize_signer']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        self.assertTrue(do_authorize_signer.called)
        self.assertEqual(do_authorize_signer.call_count, 2)
        self.assertEqual(expected_call_args_list, do_authorize_signer.call_args_list)
