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
from parameterized import parameterized
from mnemonic import Mnemonic
from comm.english_mnemonic import EnglishMnemonic

import logging

logging.disable(logging.CRITICAL)


class TestEnglishMnemonic(TestCase):
    def test_same_wordlist(self):
        self.assertEqual(Mnemonic("english").wordlist, EnglishMnemonic().wordlist)

    @parameterized.expand([
        (
            "case 1",
            bytes.fromhex(
                "26c1421a93584708c99c508da34696cf63d500e2adc34baa49513e36b65a0cc3"),
        ),
        (
            "case 2",
            bytes.fromhex(
                "211ee4f472151547f3620c967827139438307f6bb75b3a0d5a765ef899ed470a"),
        ),
        (
            "case 3",
            bytes.fromhex(
                "3d3936c1535e6b82d4e23cd79034b31c14a16e747cbc6cbc9b8e619caeab6e23"),
        ),
    ])
    def test_same_mnemonic(self, _, bs):
        m = Mnemonic("english").to_mnemonic(bs)
        em = EnglishMnemonic().to_mnemonic(bs)
        self.assertEqual(24, len(em.split(" ")))
        self.assertEqual(m, em)
