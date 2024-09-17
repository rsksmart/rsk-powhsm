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


class TestAdmLedger(TestCase):
    def setUp(self):
        self.old_stdout = sys.stdout
        self.DEFAULT_OPTIONS = {
            "sgx_host": "localhost",
            "sgx_port": 7777,
            "any_pin": False,
            "new_pin": None,
            "no_unlock": False,
            "operation": None,
            "output_file_path": None,
            "pin": None,
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

        with patch('sys.argv', ['adm_sgx.py', '-p', 'a-pin', 'unlock']):
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
                   ['adm_sgx.py', '-p', 'a-pin', 'onboard']):
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

        with patch('sys.argv', ['adm_sgx.py', '-p', 'a-pin', '-o', 'a-path', '-u',
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

        with patch('sys.argv', ['adm_sgx.py', '-p', 'old-pin', '-n', 'new-pin',
                                '-r', '4567', '-a', 'changepin']):
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
