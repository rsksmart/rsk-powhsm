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
