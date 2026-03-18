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
    get_signature_hash_for_p2sh_input,
    get_signature_hash_for_p2sh_p2wsh_input,
    get_block_hash_as_int,
    get_merkle_root,
)

import logging

logging.disable(logging.CRITICAL)

# Taken from https://en.bitcoin.it/wiki/BIP_0143#P2SH-P2WSH
SAMPLE_1 = """
010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e010000
0000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688
acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000
""".replace("\n", "").replace("\r", "")

SAMPLE_1_SIGHASH_I0 = "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c"

SAMPLE_1_WITNESS_SCRIPT = """
56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae
""".replace("\n", "").replace("\r", "")
SAMPLE_1_I0_OUTVAL = 987654321

SAMPLE_2 = """
02000000018fd94eaa9b2c5baf1356826d549741ea53d7063e830e9907cf86cdd4fe46c278010000
00232200200fca68baeb0517ceaf99d1d61947d142c29fbba23b6c173d18b034992df2e1c2ffffff
ff07fc240900000000001976a914ac3df06ee0d2596ed38f23722335f4c01ecdc40288ac9c028547
000000001976a91473179e1c334c7b9c393f3a31d6e9c1896bf480cd88ac5c3d2c00000000001976
a91487b7bfba7a7703864dec1a1aeb0536d4c09120d488ac256c0800000000001976a91435ad11a2
ac31cfbc01426351c8ba4c333f90296088ac1c302900000000001976a91487b7bfba7a7703864dec
1a1aeb0536d4c09120d488ac347f8f05000000001976a914f4ef22351609132290bf20f8bca034c6
ee101f5888acaedb7dc63100000017a914cb24588cf67c2126c63fa55bedd02dff319626c6870000
0000
""".replace("\n", "").replace("\r", "")

SAMPLE_2_SIGHASH_I0 = "a93253994b04069f720b116fc1ba161839a67b00cccc9af52e2fa76569e27da2"

SAMPLE_2_WITNESS_SCRIPT = """
6455210274c7a2c584eb9dbc3d78fede48d1258b974cd537d82fce4d18f0e85604774e652102daa3
cd74c9d06bc7928e1214f0de4ee5744c694975d70e160f562c5e1c4f587d2102f0844d9c1df50f55
97118659badf40ea6956903f405f6a604402c8014d926fd42103250c11be0561b1d7ae168b1f59e3
9cbc1fd1ba3cf4d2140c1a365b2723a2bf93210328f0386fe2b2840a424d3a5073be89a4cb643c43
4752b8c865e867611d0041832103b8faf3ebcf3fe89085fe8c6046dd9cece45bb56e466103f96b4f
ca2f21072ded2103e59ed1ba1240ac6ff0cb9234afc0e44d6e7653219982d4f1eb55844395e93496
2103e8f68168606392c5e17f2f9bf1fd3fa55c295cad3990e72e7e3e4470ed644c8f2103f4501687
1f91a1d81984280b9abd1aad6987e1a73a51e0ae8c920b7b238d62cb59ae670350cd00b275532102
370a9838e4d15708ad14a104ee5606b36caaaaf739d833e67770ce9fd9b3ec80210257c293086c4d
4fe8943deda5f890a37d11bebd140e220faa76258a41d077b4d42103c2660a46aa73078ee6016dee
953488566426cf55fc8011edd0085634d75395f92103cd3e383ec6e12719a6c69515e5559bcbe037
d0aa24c187e1e26ce932e22ad7b354ae68
""".replace("\n", "").replace("\r", "")
SAMPLE_2_I0_OUTVAL = 215083478191

SAMPLE_3 = """
010000000187ace6cb83436c876dd2233dfadf537068ecb1b9a0000d3590c9072d46d2bf4c000000006e0
000004c69522102cd53fc53a07f211641a677d250f6de99caf620e8e77071e811a28b3bcddf0be1210362
634ab57dae9cb373a5d536e66a8c4f67468bbcfb063809bab643072d78a1242103c5946b3fbae03a65423
7da863c9ed534e0878657175b132b8ca630f245df04db53aeffffffff02b030eb0b000000001976a914f6
b794549667efd57f083e018c1a4726c73ccb4388ac00301a1e0100000017a914896ed9f3446d51b5510f7
f0b6ef81b2bde55140e8700000000
""".replace("\n", "").replace("\r", "")

SAMPLE_3_SIGHASH_I0 = "db4ca3f81a68996e7c51e7e138524a53ab9770410f628199dc6ab5a5bac73e5c"

SAMPLE_4 = """
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

SAMPLE_4_SIGHASH_I0 = "ef95325f9c819476a54097abe466374f8293f26637af3686833d73dc29be2093"
SAMPLE_4_SIGHASH_I1 = "20d8b8e413868c08e987ae11c7280b95293c05f0e191ef847a6060593b759814"

SAMPLE_5 = """
01000000024c62cd14e351b13b960e76502307cf26fc1dcf8681e4b0d9d1bb6ca69156d90f030000
00220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff
fd55c4e8a3a616fedc40187a6214775006fdda1155544b6fd3486374ace05ce4050000002200200f
bed83438cf3f837ab484b29426bb643fd36b1c800fb37076a3e9d50fbf3845ffffffff0200e9a435
000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976
a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000
""".replace("\n", "").replace("\r", "")


class TestBitcoin(TestCase):
    def test_get_sig_hash_sample_1_i0(self):
        self.assertEqual(
            SAMPLE_1_SIGHASH_I0,
            get_signature_hash_for_p2sh_p2wsh_input(
                SAMPLE_1, 0, SAMPLE_1_WITNESS_SCRIPT, SAMPLE_1_I0_OUTVAL))

    def test_get_sig_hash_sample_2_i0(self):
        self.assertEqual(
            SAMPLE_2_SIGHASH_I0,
            get_signature_hash_for_p2sh_p2wsh_input(
                SAMPLE_2, 0, SAMPLE_2_WITNESS_SCRIPT, SAMPLE_2_I0_OUTVAL))

    def test_get_sig_hash_sample_3_i0(self):
        self.assertEqual(
            SAMPLE_3_SIGHASH_I0,
            get_signature_hash_for_p2sh_input(SAMPLE_3, 0))

    def test_get_sig_hash_sample_4_i0(self):
        self.assertEqual(
            SAMPLE_4_SIGHASH_I0,
            get_signature_hash_for_p2sh_input(SAMPLE_4, 0))

    def test_get_sig_hash_sample_4_i1(self):
        self.assertEqual(
            SAMPLE_4_SIGHASH_I1,
            get_signature_hash_for_p2sh_input(SAMPLE_4, 1))

    def test_get_sig_hash_sample_5_i0(self):
        with self.assertRaises(ValueError) as err:
            get_signature_hash_for_p2sh_input(SAMPLE_5, 0)
        self.assertIn("Invalid redeem script", str(err.exception))

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
