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
from comm.bitcoin import (
    get_tx_hash_for_unsigned_tx,
    get_signature_hash_for_p2sh_input,
    get_block_hash_as_int,
    get_merkle_root,
    get_unsigned_tx,
    get_tx_hash,
    get_tx_version,
)

import logging

logging.disable(logging.CRITICAL)

SAMPLE_1_UNSIGNED = """
010000000187ace6cb83436c876dd2233dfadf537068ecb1b9a0000d3590c9072d46d2bf4c000000006e0
000004c69522102cd53fc53a07f211641a677d250f6de99caf620e8e77071e811a28b3bcddf0be1210362
634ab57dae9cb373a5d536e66a8c4f67468bbcfb063809bab643072d78a1242103c5946b3fbae03a65423
7da863c9ed534e0878657175b132b8ca630f245df04db53aeffffffff02b030eb0b000000001976a914f6
b794549667efd57f083e018c1a4726c73ccb4388ac00301a1e0100000017a914896ed9f3446d51b5510f7
f0b6ef81b2bde55140e8700000000
""".replace("\n", "").replace("\r", "")

SAMPLE_1_PARTIALLY_SIGNED = """
010000000187ace6cb83436c876dd2233dfadf537068ecb1b9a0000d3590c9072d46d2bf4c00000000b60
048304502210084ddb5c7c6b57405c4068fa6634c8dd736d53ebf1ea878ad962026eecb86b57502206988
e345a0af65ca5a72418580896028cdd1834404fe97774234725e494a18f101004c69522102cd53fc53a07
f211641a677d250f6de99caf620e8e77071e811a28b3bcddf0be1210362634ab57dae9cb373a5d536e66a
8c4f67468bbcfb063809bab643072d78a1242103c5946b3fbae03a654237da863c9ed534e0878657175b1
32b8ca630f245df04db53aeffffffff02b030eb0b000000001976a914f6b794549667efd57f083e018c1a
4726c73ccb4388ac00301a1e0100000017a914896ed9f3446d51b5510f7f0b6ef81b2bde55140e8700000
000
""".replace("\n", "").replace("\r", "")

SAMPLE_1_PARTIALLY_SIGNED_HASH = (
    "e9ceb9260f258f13a029ad212f08719d8656b564cf4108b86199d83969de7c2e")
SAMPLE_1_UNSIGNED_HASH = (
    "f7e2b314eb12bd13481c5325ae3839fdbe5c508dbc7e24a44aac5e9992d07718")
SAMPLE_1_SIGHASH_INPUT0 = (
    "db4ca3f81a68996e7c51e7e138524a53ab9770410f628199dc6ab5a5bac73e5c")

SAMPLE_2_UNSIGNED = """
01000000025cc070156cd1487db3c0c0d22affe09f208950bbe1bd6d2bc4a7c65749cee0c1000000006e000000
4c69522102cd53fc53a07f211641a677d250f6de99caf620e8e77071e811a28b3bcddf0be1210362634ab57dae
9cb373a5d536e66a8c4f67468bbcfb063809bab643072d78a1242103c5946b3fbae03a654237da863c9ed534e0
878657175b132b8ca630f245df04db53aeffffffffbe6be3ddaf27e9609c9b319db9c97eae36e88dcda760ff4e
0b77ccd086c7f4c6000000006e0000004c69522102cd53fc53a07f211641a677d250f6de99caf620e8e77071e8
11a28b3bcddf0be1210362634ab57dae9cb373a5d536e66a8c4f67468bbcfb063809bab643072d78a1242103c5
946b3fbae03a654237da863c9ed534e0878657175b132b8ca630f245df04db53aeffffffff021044d871020000
001976a914f6b794549667efd57f083e018c1a4726c73ccb4388ac008d380c0100000017a914896ed9f3446d51
b5510f7f0b6ef81b2bde55140e8700000000
""".replace("\n", "").replace("\r", "")

SAMPLE_2_PARTIALLY_SIGNED = """
01000000025cc070156cd1487db3c0c0d22affe09f208950bbe1bd6d2bc4a7c65749cee0c100000000b5004730
4402203743f5bc4632b46fa261de4bdeaa1b3d617bd9dcaaf9fb3f9272c95c7f7b8b11022055464b2dae639037
b42b3bc559bcf7580a7aa3e421c1511a6419ae7338029cc601004c69522102cd53fc53a07f211641a677d250f6
de99caf620e8e77071e811a28b3bcddf0be1210362634ab57dae9cb373a5d536e66a8c4f67468bbcfb063809ba
b643072d78a1242103c5946b3fbae03a654237da863c9ed534e0878657175b132b8ca630f245df04db53aeffff
ffffbe6be3ddaf27e9609c9b319db9c97eae36e88dcda760ff4e0b77ccd086c7f4c600000000b5004730440220
046b94168f1181a81ac8b4d7543b6392743d81a5b0c494db95be12ce2d9ba91002201dc5ad6c9f7b6171678a78
a910fbd59150d8f86ef39f3244a82761cbf87670c801004c69522102cd53fc53a07f211641a677d250f6de99ca
f620e8e77071e811a28b3bcddf0be1210362634ab57dae9cb373a5d536e66a8c4f67468bbcfb063809bab64307
2d78a1242103c5946b3fbae03a654237da863c9ed534e0878657175b132b8ca630f245df04db53aeffffffff02
1044d871020000001976a914f6b794549667efd57f083e018c1a4726c73ccb4388ac008d380c0100000017a914
896ed9f3446d51b5510f7f0b6ef81b2bde55140e8700000000
""".replace("\n", "").replace("\r", "")

SAMPLE_2_PARTIALLY_SIGNED_HASH = (
    "39ae0553e91565866acc81a61da52cd87702ed2b4632f52bba19e3d9ba7e46ce")
SAMPLE_2_UNSIGNED_HASH = (
    "f8318d6c071efd988411cd63ee7d3fbf736d5ed38ba0679fa0be7acddb1bddda")
SAMPLE_2_SIGHASH_INPUT0 = (
    "ef95325f9c819476a54097abe466374f8293f26637af3686833d73dc29be2093")
SAMPLE_2_SIGHASH_INPUT1 = (
    "20d8b8e413868c08e987ae11c7280b95293c05f0e191ef847a6060593b759814")

SAMPLE_3_UNSIGNED = """
0100000001ec7281cfc9e59db5c1e69fc294846572bd3d78091bd0c6fdc21c2209c500556a000000004b000000
475221031da807c71c2f303b7f409dd2605b297ac494a563be3b9ca5f52d95a43d183cc521036bb9eab797eadc
8b697f0e82a01d01cabbfaaca37e5bafc06fdc6fdd38af894a52aeffffffff01b01c661b0c0000001976a914f7
ee4511563688dce9b5d74e07cc9932b8e01f2288ac00000000
""".replace("\n", "").replace("\r", "")

SAMPLE_3_UNSIGNED_HASH = (
    "ea73e8a9a6b98da8ba3f47d28f94af6818c8e906937a95f302263920b4cda792")
SAMPLE_3_SIGHASH_INPUT0 = (
    "5aeb5a6bbecda560b297da643559ce3c1b727076fb2ba1118c94d5906617aa19")

SAMPLE_TX_V2 = """
02000000010ac6236167ee3c88aee00f0f3b89f92b43a84797a71b6b62ffd354f11ef8c2f000000000de000000
004cd8645221024c759affafc5589872d218ca30377e6d97211c039c375672c169ba76ce7fad6a21031f4aa494
3fa2b731cd99c551d6992021555877b3b32c125385600fbc1b89c2a92103767a0994daa8babee7215b2371916d
09fc1158de3c23feeefaae2dfe5baf483053670132b275522102132685d71b0109fecef0160f1efcab0187eff9
16f4d472289741bff2666d0e1c2102ed498022f9d618a96f272b1990a640d9f24fb97d2648f8716f9ee22dc008
eba721036f66639295ca8e4294c24d63e3fbc11247f6ba6a27b6b4de9a3492f414152d9b5368aeffffffff0294
8e4b00000000001976a9140a4f09cbd39d5d8072b24385e1a9eb1c84ae544688acf83d6e0b0000000017a914ba
053351893c7495e0c75d5abacb3ed886cf1ff88700000000
""".replace("\n", "").replace("\r", "")


class TestBitcoin(TestCase):
    def test_signed_unsigned_different_sample1(self):
        self.assertNotEqual(SAMPLE_1_UNSIGNED, SAMPLE_1_PARTIALLY_SIGNED)

    def test_get_tx_hash_for_unsigned_sample1(self):
        self.assertEqual(SAMPLE_1_UNSIGNED_HASH,
                         get_tx_hash_for_unsigned_tx(SAMPLE_1_UNSIGNED))

    def test_get_tx_hash_sample1(self):
        self.assertEqual(SAMPLE_1_UNSIGNED_HASH, get_tx_hash(SAMPLE_1_UNSIGNED))

    def test_get_tx_hash_sample1_signed(self):
        self.assertEqual(SAMPLE_1_PARTIALLY_SIGNED_HASH,
                         get_tx_hash(SAMPLE_1_PARTIALLY_SIGNED))

    def test_get_tx_for_unsigned_hash_partially_signed_sample1(self):
        self.assertEqual(SAMPLE_1_UNSIGNED_HASH,
                         get_tx_hash_for_unsigned_tx(SAMPLE_1_PARTIALLY_SIGNED))

    def test_get_sighash_unsigned_sample1(self):
        self.assertEqual(
            SAMPLE_1_SIGHASH_INPUT0,
            get_signature_hash_for_p2sh_input(SAMPLE_1_UNSIGNED, 0),
        )

    def test_get_sighash_partially_signed_sample1(self):
        self.assertEqual(
            SAMPLE_1_SIGHASH_INPUT0,
            get_signature_hash_for_p2sh_input(SAMPLE_1_PARTIALLY_SIGNED, 0),
        )

    def test_get_unsigned_sample1(self):
        self.assertEqual(SAMPLE_1_UNSIGNED, get_unsigned_tx(SAMPLE_1_PARTIALLY_SIGNED))

    def test_get_unsigned_sample2(self):
        self.assertEqual(SAMPLE_2_UNSIGNED, get_unsigned_tx(SAMPLE_2_PARTIALLY_SIGNED))

    def test_signed_unsigned_different_sample2(self):
        self.assertNotEqual(SAMPLE_2_UNSIGNED, SAMPLE_2_PARTIALLY_SIGNED)

    def test_get_tx_hash_sample2(self):
        self.assertEqual(SAMPLE_2_UNSIGNED_HASH, get_tx_hash(SAMPLE_2_UNSIGNED))

    def test_get_tx_hash_sample2_signed(self):
        self.assertEqual(SAMPLE_2_PARTIALLY_SIGNED_HASH,
                         get_tx_hash(SAMPLE_2_PARTIALLY_SIGNED))

    def test_get_tx_hash_for_unsigned_sample2(self):
        self.assertEqual(SAMPLE_2_UNSIGNED_HASH,
                         get_tx_hash_for_unsigned_tx(SAMPLE_2_UNSIGNED))

    def test_get_tx_hash_for_unsigned_partially_signed_sample2(self):
        self.assertEqual(SAMPLE_2_UNSIGNED_HASH,
                         get_tx_hash_for_unsigned_tx(SAMPLE_2_PARTIALLY_SIGNED))

    def test_get_sighash_unsigned_sample2_input0(self):
        self.assertEqual(
            SAMPLE_2_SIGHASH_INPUT0,
            get_signature_hash_for_p2sh_input(SAMPLE_2_UNSIGNED, 0),
        )

    def test_get_sighash_unsigned_sample2_input1(self):
        self.assertEqual(
            SAMPLE_2_SIGHASH_INPUT1,
            get_signature_hash_for_p2sh_input(SAMPLE_2_UNSIGNED, 1),
        )

    def test_get_tx_hash_not_signed_sample3(self):
        self.assertEqual(SAMPLE_3_UNSIGNED_HASH,
                         get_tx_hash_for_unsigned_tx(SAMPLE_3_UNSIGNED))

    def test_get_sighash_unsigned_sample3_input0(self):
        self.assertEqual(
            SAMPLE_3_SIGHASH_INPUT0,
            get_signature_hash_for_p2sh_input(SAMPLE_3_UNSIGNED, 0),
        )

    # Taken from https://www.blockchain.com/btc/block/624147
    # Raw taken from first 80 bytes of https://blockchain.info/block/624147?format=hex
    def test_get_block_hash_as_int_sample1(self):
        expected = int.from_bytes(
            bytes.fromhex(
                "0000000000000000000cca3342146c09d6907c7f9ca57523b9bd86fa30899894"),
            byteorder="big",
            signed=True,
        )
        actual = get_block_hash_as_int(
            "0000c0208426f01512acfecc731b6087fc29bbaecceb90343bd40800000000000000000032ec"
            "a913ca8c61beb3776f9701938c4c4ae1e400a574d3e56c5fbac67ab17677a18d865e413b1417"
            "cef412c9"
        )
        self.assertEqual(actual, expected)

    # Taken from https://www.blockchain.com/btc/block/564123
    # Raw taken from first 80 bytes of https://blockchain.info/block/564123?format=hex
    def test_get_block_hash_as_int_sample2(self):
        expected = int.from_bytes(
            bytes.fromhex(
                "0000000000000000001561d124184ae540941dbeaf34841f0ec7d9301f5bc487"),
            byteorder="big",
            signed=True,
        )
        actual = get_block_hash_as_int(
            "00004020b274d71decd77d50ef2465a0e06de23d4e6ac2940f6629000000000000000000b0c4"
            "11fb72cf1406ea03172719ca3da827e256868b24b3d40db188759e8c66e7309a6f5c886f2e17"
            "04d58fd3"
        )
        self.assertEqual(actual, expected)

    def test_get_block_hash_as_int_malformed(self):
        with self.assertRaises(ValueError):
            get_block_hash_as_int("aabbcc")

    # Taken from https://www.blockchain.com/btc/block/421895
    # Raw taken from first 80 bytes of https://blockchain.info/block/421895?format=hex
    def test_get_merkle_root_sample1(self):
        actual = get_merkle_root(
            "00000020d03543c0470f715b5eb9a77963b1442ea86e7deb89151d0200000000000000002ee2"
            "fbed876dc6559e75dddca7de82d619a442ce7df93e2c5f507f926a8257e690cc925769260518"
            "6e4b7622"
        )
        self.assertEqual(
            actual, "2ee2fbed876dc6559e75dddca7de82d619a442ce7df93e2c5f507f926a8257e6")

    # Taken from https://www.blockchain.com/btc/block/564123
    # Raw taken from first 80 bytes of https://blockchain.info/block/564123?format=hex
    def test_get_merkle_root_sample2(self):
        actual = get_merkle_root(
            "00004020b274d71decd77d50ef2465a0e06de23d4e6ac2940f6629000000000000000000b0c4"
            "11fb72cf1406ea03172719ca3da827e256868b24b3d40db188759e8c66e7309a6f5c886f2e17"
            "04d58fd3"
        )
        self.assertEqual(
            actual, "b0c411fb72cf1406ea03172719ca3da827e256868b24b3d40db188759e8c66e7")

    def test_get_merkle_root_malformed(self):
        with self.assertRaises(ValueError):
            get_merkle_root("aabbcc")

    def test_get_tx_version_a(self):
        self.assertEqual(1, get_tx_version(SAMPLE_1_UNSIGNED))

    def test_get_tx_version_b(self):
        self.assertEqual(2, get_tx_version(SAMPLE_TX_V2))
