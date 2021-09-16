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
        self.assertEqual("m/44'/137'/0'/0/1", str(BIP32Path("m/44'/137'/0'/0/1")))
        self.assertEqual("m/44'/0'/0'/0/0", str(BIP32Path("m/44'/0'/0'/0/0")))

    def test_to_binary(self):
        self.assertEqual(
            "052c00008089000080000000800000000000000000",
            BIP32Path("m/44'/137'/0'/0/0").to_binary().hex(),
        )
        self.assertEqual(
            "052c00008089000080000000800000000001000000",
            BIP32Path("m/44'/137'/0'/0/1").to_binary().hex(),
        )
        self.assertEqual(
            "052c00008000000080000000800000000000000000",
            BIP32Path("m/44'/0'/0'/0/0").to_binary().hex(),
        )

    def test_spec_invalid(self):
        for spec in ["44/1/2/3/4", "m/", "m/44'", "m/44'/0'/0/0/0/1", "notevenaspec"]:
            with self.assertRaises(ValueError):
                BIP32Path(spec)

    def test_equality(self):
        self.assertEqual(BIP32Path("m/44'/0'/0'/0/0"), BIP32Path("m/44'/0'/0'/0/0"))
        self.assertEqual(BIP32Path("m/44'/137'/0'/0/0"), BIP32Path("m/44'/137'/0'/0/0"))
        self.assertEqual(BIP32Path("m/44'/137'/0'/0/1"), BIP32Path("m/44'/137'/0'/0/1"))
        self.assertNotEqual(BIP32Path("m/44'/137'/0'/0/1"),
                            BIP32Path("m/44'/137'/0'/0/0"))
        self.assertNotEqual(BIP32Path("m/44'/137'/0'/0/0'"),
                            BIP32Path("m/44'/137'/0'/0/0"))
        self.assertNotEqual(BIP32Path("m/45'/137'/0'/0/0"),
                            BIP32Path("m/44'/137'/0'/0/0"))
