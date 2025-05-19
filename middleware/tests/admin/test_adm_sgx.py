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
from adm_sgx import main
import logging

logging.disable(logging.CRITICAL)


class TestAdmSgx(TestCase):
    def setUp(self):
        self.old_stdout = sys.stdout
        self.DEFAULT_OPTIONS = {
            "sgx_host": "localhost",
            "sgx_port": 7777,
            "any_pin": False,
            "new_pin": None,
            "no_unlock": False,
            "attestation_ud_source": "https://public-node.rsk.co",
            "attestation_certificate_file_path": None,
            "root_authority": None,
            "pubkeys_file_path": None,
            "operation": None,
            "output_file_path": None,
            "pin": None,
            "destination_sgx_port": 3333,
            "destination_sgx_host": "localhost",
            "migration_authorization_file_path": None,
            "verbose": False,
        }

    def tearDown(self):
        sys.stdout = self.old_stdout

    @patch("adm_sgx.do_unlock")
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

        with patch('sys.argv', ['adm_sgx.py', '-P', 'a-pin', 'unlock']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch('sys.argv', ['adm_sgx.py', '--pin', 'a-pin', 'unlock']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        self.assertTrue(do_unlock.called)
        self.assertEqual(do_unlock.call_count, 2)
        self.assertEqual(expected_call_args_list, do_unlock.call_args_list)

    @patch("adm_sgx.do_onboard")
    def test_onboard(self, do_onboard):
        expected_options = {
            **self.DEFAULT_OPTIONS,
            'operation': 'onboard',
            'pin': 'a-pin',
        }

        expected_call_args_list = [
            call(Namespace(**expected_options)),
            call(Namespace(**expected_options))
        ]

        with patch('sys.argv',
                   ['adm_sgx.py', '-P', 'a-pin', 'onboard']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch('sys.argv',
                   ['adm_sgx.py', '--pin', 'a-pin', 'onboard']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        self.assertTrue(do_onboard.called)
        self.assertEqual(expected_call_args_list, do_onboard.call_args_list)

    @patch("adm_sgx.do_get_pubkeys")
    def test_pubkeys(self, do_get_pubkeys):
        expected_options = {
            **self.DEFAULT_OPTIONS,
            'no_unlock': True,
            'operation': 'pubkeys',
            'output_file_path': 'a-path',
            'pin': 'a-pin',
            'sgx_host': '1.2.3.4',
        }

        expected_call_args_list = [
            call(Namespace(**expected_options)),
            call(Namespace(**expected_options))
        ]

        with patch('sys.argv', ['adm_sgx.py', '-P', 'a-pin', '-o', 'a-path', '-u',
                                '-s', '1.2.3.4', 'pubkeys']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch('sys.argv',
                   ['adm_sgx.py',
                    '--host', '1.2.3.4',
                    '--pin', 'a-pin',
                    '--output', 'a-path',
                    '--nounlock',
                    'pubkeys']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        self.assertTrue(do_get_pubkeys.called)
        self.assertEqual(expected_call_args_list, do_get_pubkeys.call_args_list)

    @patch("adm_sgx.do_changepin")
    def test_changepin(self, do_changepin):
        expected_options = {
            **self.DEFAULT_OPTIONS,
            'any_pin': True,
            'new_pin': 'new-pin',
            'operation': 'changepin',
            'pin': 'old-pin',
            'sgx_port': 4567,
        }
        expected_call_args_list = [
            call(Namespace(**expected_options)),
            call(Namespace(**expected_options))
        ]

        with patch('sys.argv', ['adm_sgx.py', '-P', 'old-pin', '-n', 'new-pin',
                                '-p', '4567', '-a', 'changepin']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch('sys.argv', ['adm_sgx.py',
                                '--newpin', 'new-pin', '--anypin', 'changepin',
                                '--port', '4567', '--pin', 'old-pin']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        self.assertTrue(do_changepin.called)
        self.assertEqual(do_changepin.call_count, 2)
        self.assertEqual(expected_call_args_list, do_changepin.call_args_list)

    @patch("adm_sgx.do_attestation")
    def test_attestation(self, do_attestation):
        expected_options = {
            **self.DEFAULT_OPTIONS,
            'attestation_ud_source': 'user-defined-source',
            'operation': 'attestation',
            'output_file_path': 'out-path',
            'pin': 'a-pin',
        }
        expected_call_args_list = [
            call(Namespace(**expected_options)),
            call(Namespace(**{**expected_options, "no_unlock": True}))
        ]

        with patch('sys.argv', ['adm_sgx.py',
                                '-P', 'a-pin',
                                '-o', 'out-path',
                                '--attudsource', 'user-defined-source',
                                'attestation']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch('sys.argv', ['adm_sgx.py',
                                '--pin', 'a-pin',
                                '--output', 'out-path',
                                '--attudsource', 'user-defined-source',
                                '--nounlock',
                                'attestation']):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        self.assertTrue(do_attestation.called)
        self.assertEqual(do_attestation.call_count, 2)
        self.assertEqual(expected_call_args_list, do_attestation.call_args_list)

    @patch("adm_sgx.do_migrate_db")
    def test_migrate_db(self, do_migrate_db):
        expected_options = {
            **self.DEFAULT_OPTIONS,
            "operation": "migrate_db",
            "migration_authorization_file_path": "a-file-path",
        }
        expected_call_args_list = [
            call(Namespace(**expected_options)),
            call(Namespace(**{
                **expected_options,
                "destination_sgx_port": 4444,
                "destination_sgx_host": "another.host.com"}))
        ]

        with patch("sys.argv", ["adm_sgx.py",
                                "migrate_db",
                                "--migauth", "a-file-path"]):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        with patch("sys.argv", ["adm_sgx.py",
                                "migrate_db",
                                "-z", "a-file-path",
                                "--dest-port", "4444",
                                "--dest-host", "another.host.com"]):
            with self.assertRaises(SystemExit) as e:
                main()
        self.assertEqual(e.exception.code, 0)

        self.assertTrue(do_migrate_db.called)
        self.assertEqual(do_migrate_db.call_count, 2)
        for i, call_args in enumerate(expected_call_args_list):
            self.assertEqual(call_args, do_migrate_db.call_args_list[i], f"Call #{i}")
