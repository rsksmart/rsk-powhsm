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
from unittest.mock import call, patch
from lbutils import main

import logging

logging.disable(logging.CRITICAL)


@patch("runpy.run_module")
class TestLbutils(TestCase):
    def test_load(self, run_module):
        with patch('sys.argv', ['lbutils.py', 'load']):
            with self.assertRaises(SystemExit) as e:
                main()

        self.assertTrue(run_module.called)
        self.assertEqual([call('ledgerblue.loadApp', run_name='__main__')],
                         run_module.call_args_list)
        self.assertEqual(e.exception.code, 0)

    def test_delete(self, run_module):
        with patch('sys.argv', ['lbutils.py', 'delete']):
            with self.assertRaises(SystemExit) as e:
                main()

        self.assertTrue(run_module.called)
        self.assertEqual([call('ledgerblue.deleteApp', run_name='__main__')],
                         run_module.call_args_list)
        self.assertEqual(e.exception.code, 0)

    def test_setup_ca(self, run_module):
        with patch('sys.argv', ['lbutils.py', 'setupCA']):
            with self.assertRaises(SystemExit) as e:
                main()

        self.assertTrue(run_module.called)
        self.assertEqual([call('ledgerblue.setupCustomCA', run_name='__main__')],
                         run_module.call_args_list)
        self.assertEqual(e.exception.code, 0)

    def test_reset_ca(self, run_module):
        with patch('sys.argv', ['lbutils.py', 'resetCA']):
            with self.assertRaises(SystemExit) as e:
                main()

        self.assertTrue(run_module.called)
        self.assertEqual([call('ledgerblue.resetCustomCA', run_name='__main__')],
                         run_module.call_args_list)
        self.assertEqual(e.exception.code, 0)

    def test_gen_ca(self, run_module):
        with patch('sys.argv', ['lbutils.py', 'genCA']):
            with self.assertRaises(SystemExit) as e:
                main()

        self.assertTrue(run_module.called)
        self.assertEqual([call('ledgerblue.genCAPair', run_name='__main__')],
                         run_module.call_args_list)
        self.assertEqual(e.exception.code, 0)
