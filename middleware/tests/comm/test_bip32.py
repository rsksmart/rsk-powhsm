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
from comm.bip32 import BIP32Element, BIP32Path

import logging

logging.disable(logging.CRITICAL)


class TestBIP32Element(TestCase):
    def test_normal(self):
        element = BIP32Element("456")
        self.assertFalse(element.is_hardened)
        self.assertEqual(456, element.spec_index)
        self.assertEqual(456, element.index)
        self.assertEqual("456", str(element))

    def test_max_normal(self):
        element = BIP32Element("0")
        self.assertFalse(element.is_hardened)
        self.assertEqual(0, element.spec_index)
        self.assertEqual(0, element.index)
        self.assertEqual("0", str(element))

    def test_hardened(self):
        element = BIP32Element("789'")
        self.assertTrue(element.is_hardened)
        self.assertEqual(789, element.spec_index)
        self.assertEqual(2147484437, element.index)
        self.assertEqual("789'", str(element))

    def test_max_hardened(self):
        element = BIP32Element("0'")
        self.assertTrue(element.is_hardened)
        self.assertEqual(0, element.spec_index)
        self.assertEqual(2147483648, element.index)
        self.assertEqual("0'", str(element))

    def test_spec_invalid(self):
        for spec in [
                "",
                "notanumber",
                "notanumber'",
                "'",
                "2147483648",
                "2147483648'",
                "-1",
                "-1'",
        ]:
            with self.assertRaises(ValueError):
                BIP32Element(spec)


class TestBIP32Path(TestCase):
    def test_paths(self):
        self.assertEqual("m/44'/137'/0'/0/0", str(BIP32Path("m/44'/137'/0'/0/0")))
        self.assertEqual("m/44'/0'/0'/0/0", str(BIP32Path("m/44'/0'/0'/0/0")))

    def test_to_binary(self):
        self.assertEqual(
            "052c00008089000080000000800000000000000000",
            BIP32Path("m/44'/137'/0'/0/0").to_binary().hex(),
        )
        self.assertEqual(
            "058000002c80000089800000000000000000000000",
            BIP32Path("m/44'/137'/0'/0/0").to_binary("big").hex(),
        )
        self.assertEqual(
            "052c00008000000080000000800000000000000000",
            BIP32Path("m/44'/0'/0'/0/0").to_binary().hex(),
        )
        self.assertEqual(
            "058000002c80000000800000000000000000000000",
            BIP32Path("m/44'/0'/0'/0/0").to_binary("big").hex(),
        )

    def test_spec_invalid(self):
        for spec in ["44/1/2/3/4", "m/", "m/44'", "m/44'/0'/0/0/0/1", "notevenaspec"]:
            with self.assertRaises(ValueError):
                BIP32Path(spec)

    def test_equality(self):
        self.assertEqual(BIP32Path("m/44'/0'/0'/0/0"), BIP32Path("m/44'/0'/0'/0/0"))
        self.assertEqual(BIP32Path("m/44'/137'/0'/0/0"), BIP32Path("m/44'/137'/0'/0/0"))
        self.assertNotEqual(BIP32Path("m/44'/137'/0'/0/0'"),
                            BIP32Path("m/44'/137'/0'/0/0"))
        self.assertNotEqual(BIP32Path("m/45'/137'/0'/0/0"),
                            BIP32Path("m/44'/137'/0'/0/0"))
