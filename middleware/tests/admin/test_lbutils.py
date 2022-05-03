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
from lbutils import get_utilities, parse_args

import logging

logging.disable(logging.CRITICAL)


class TestLbutils(TestCase):
    def setUp(self):
        self.expected_utilities = {
            "load": "loadApp",
            "delete": "deleteApp",
            "setupCA": "setupCustomCA",
            "resetCA": "resetCustomCA",
            "genCA": "genCAPair",
        }
        self.utilities = get_utilities()

    def test_utilities(self):
        for key in self.utilities.keys():
            self.assertEqual(self.utilities[key], self.expected_utilities[key])

    def test_load(self):
        input_argv = ['lnutils.py', 'load', 'an-arg']
        module, argv = parse_args(input_argv)
        self.assertEqual(module, 'ledgerblue.loadApp')
        self.assertEqual(argv, [f"{input_argv[0]} {input_argv[1]}"] + input_argv[2:])

    def test_delete(self):
        input_argv = ['lnutils.py', 'delete', 'an-arg']
        module, argv = parse_args(input_argv)
        self.assertEqual(module, 'ledgerblue.deleteApp')
        self.assertEqual(argv, [f"{input_argv[0]} {input_argv[1]}"] + input_argv[2:])

    def test_setup_ca(self):
        input_argv = ['lnutils.py', 'setupCA', 'an-arg']
        module, argv = parse_args(input_argv)
        self.assertEqual(module, 'ledgerblue.setupCustomCA')
        self.assertEqual(argv, [f"{input_argv[0]} {input_argv[1]}"] + input_argv[2:])

    def test_gen_ca(self):
        input_argv = ['lnutils.py', 'genCA', 'an-arg']
        module, argv = parse_args(input_argv)
        self.assertEqual(module, 'ledgerblue.genCAPair')
        self.assertEqual(argv, [f"{input_argv[0]} {input_argv[1]}"] + input_argv[2:])
