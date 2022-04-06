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
from comm.pow import (
    difficulty_to_target,
    coinbase_tx_extract_merge_mining_hash,
    coinbase_tx_get_hash,
    is_valid_merkle_proof,
)
from comm.bitcoin import get_merkle_root
import logging

logging.disable(logging.CRITICAL)


class TestDifficultyToTarget(TestCase):
    def test_min(self):
        self.assertEqual(pow(2, 256)//3, difficulty_to_target(3))
        self.assertEqual(pow(2, 256)//3, difficulty_to_target(2))
        self.assertEqual(pow(2, 256)//3, difficulty_to_target(1))
        self.assertEqual(pow(2, 256)//3, difficulty_to_target(-1))
        self.assertEqual(pow(2, 256)//3, difficulty_to_target(-19865))

    def test_max(self):
        self.assertEqual(1, difficulty_to_target(pow(2, 256)))

    def test_zero(self):
        self.assertEqual(0, difficulty_to_target(pow(2, 256) + 1))

    def test_normal(self):
        self.assertEqual(pow(2, 256)//12345678, difficulty_to_target(12345678))


class TestMergeMiningHash(TestCase):
    def test_coinbase_tx_extract_merge_mining_hash_ok_1(self):
        # Taken from https://explorer.rsk.co/block/1987345?__ctab=Mining
        self.assertEqual(
            "ddc052e0aa24959d2ff8a27d08dcfe96fefa98a93cb5018f93373a24001e5311",
            coinbase_tx_extract_merge_mining_hash(
                "000000000000010000a44ebb7a8bcef35aa7a849070f9dd026b6a8a576aab96ece2692fc"
                "bd215408301d6fbd7cfda6f6845ad9d6a19500000000000000002b6a2952534b424c4f43"
                "4b3addc052e0aa24959d2ff8a27d08dcfe96fefa98a93cb5018f93373a24001e5311d942"
                "ae07"))

    def test_coinbase_tx_extract_merge_mining_hash_ok_2(self):
        # Taken from https://explorer.rsk.co/block/2123456?__ctab=Mining
        self.assertEqual(
            "3ed227d685e0a6cee102c6eb3bf60c0fac152c0632efd19533f2ab24002066c0",
            coinbase_tx_extract_merge_mining_hash(
                "00000000000000c0b8348e3bbc8df1d6619d2453d8cc7cbe1b7b44369232fb8d83ebdcfc"
                "87992989aa21a9ed7d8f27254fc6eb6bfa94986d7f343fb3e9e735e5167f15b15b9e2783"
                "ea75437908000000000000000000000000000000002c6a4c2952534b424c4f434b3a3ed2"
                "27d685e0a6cee102c6eb3bf60c0fac152c0632efd19533f2ab24002066c0000000000000"
                "0000266a24b9e11b6d7d2854ea2c3c3fbf54009a4efa7d140c703bd4db3bb668a8500555"
                "bc6ac0b4e8c4e72a3c"))

    def test_coinbase_tx_extract_merge_mining_hash_nohex(self):
        with self.assertRaises(ValueError):
            coinbase_tx_extract_merge_mining_hash("not-a-hex")

    def test_coinbase_tx_extract_merge_mining_hash_notag(self):
        with self.assertRaises(ValueError):
            coinbase_tx_extract_merge_mining_hash(
                "00000000000000c0b8348e3bbc8df1d6619d2453d8cc7cbe1b7b44369232fb8d83ebdcfc"
                "87992989aa21a9ed7d8f27254fc6eb6bfa94986d7f343fb3e9e735e5167f15b15b9e2783"
                "ea75437908000000000000000000")


class TestCoinbaseTxHash(TestCase):
    # Case taken from https://explorer.rsk.co/block/2270854
    # Expected value generated with rskj
    def test_coinbase_tx_hash_block_2270854(self):
        coinbase_tx = ("000000000000010030de89b6d016cf88a808cc2d0c06928530c82aeda"
                       "5331368f14f76e6e4e189ba45ba1709e9cc4145350477040000000000"
                       "0000002b6a2952534b424c4f434b3a39954393c3394e087aa3e9c3430"
                       "916923cfcab898b6626e8bb25ed270022a686b0c33346")

        expected_hash = "2f5717e593aa881b1f834070b011be537acc52d47c52cf84233c62d175a2897e"

        self.assertEqual(expected_hash, coinbase_tx_get_hash(coinbase_tx))

    # Case taken from https://explorer.rsk.co/block/2274299
    # Expected value generated with rskj
    def test_coinbase_tx_hash_block_2274299(self):
        coinbase_tx = (
            "00000000000000c093f05208e09a61d839a2c6a56c45c1efa073352676aa02"
            "c742724be1b9ae4107aa21a9ed88947bc2dd3b04e7e40aff8d06151baebb3c"
            "18b04102a86e05d46b8239b4c9ff0800000000000000000000000000000000"
            "2c6a4c2952534b424c4f434b3a9bee23f1109d394f036e1e08ee84f573291a"
            "7697c373ab79f8d8612d0022b3fb0000000000000000266a24b9e11b6da689"
            "ec32dfd8ff2bbd22e79f70a6365a11b430805d1477c1aed8cdabb443401d1baf673e")

        expected_hash = "e81b51a25c61792160541295a434534093e1bb7f6f87914aeda1b8191d22310e"

        self.assertEqual(expected_hash, coinbase_tx_get_hash(coinbase_tx))

    # Case taken from https://explorer.rsk.co/block/1987456
    # Expected value generated with rskj
    def test_coinbase_tx_hash_block_1987456(self):
        coinbase_tx = (
            "00000000000000c07a7db5f845b4c05d32d44fae5632ec2a3f89eb57fc3baf8071"
            "e7fcdf810e3eb8942705e693cf4e95f41a2600000000000000002b6a2952534b42"
            "4c4f434b3ac0c1d0cf9eb8b1660d8ed6d88bd905b4b5756e2c583cb5018f933720"
            "001e53800000000000000000266a24b9e11b6da66cf0be3c2d62df8efbc9c2fcef"
            "47cf9663261ebcf74c67a35c9b10f3a6d40f00000000")

        expected_hash = "8d9dc077d02b2ad985eeeb594501b672deb30c4d87e318881a2efaec6d02ae08"

        self.assertEqual(expected_hash, coinbase_tx_get_hash(coinbase_tx))

    def test_coinbase_tx_hash_block_1987456_nohex(self):
        with self.assertRaises(ValueError):
            coinbase_tx_get_hash("not-a-hex")


class TestPoW(TestCase):
    # Case taken from https://explorer.rsk.co/block/2270854
    def test_valid_pow_block_2270854(self):
        coinbase_tx = (
            "000000000000010030de89b6d016cf88a808cc2d0c06928530c82aeda5331368f"
            "14f76e6e4e189ba45ba1709e9cc41453504770400000000000000002b6a295253"
            "4b424c4f434b3a39954393c3394e087aa3e9c3430916923cfcab898b6626e8bb2"
            "5ed270022a686b0c33346")

        block_header = (
            "000000207de60bdbe8292ee7e241606bfb158bbdc8d55b614d2e070000000000"
            "00000000ae8eaa23f3d9787b9c9c6260e9213b030ae76b2851d45fc6897a447ae9"
            "a320486fe7945ebc20131730a01a6e")

        merkle_proof = (
            "3847857690f1645b42c49bb7056b68f336d86032c5cbf1fd6ef5188f6d8d3872c10"
            "cfd6d219ff09436fdedb7afda021749d583324596584187498e17ed99471f20c743"
            "416ad2b728a0a3c917b80717b24aa33c0d4fa3af9b8973ce30252fea85605fa5be8"
            "5cf5f86fd4c3e370178a3772c0cbf64263c3987545e16c10049c97620d586fa0eef"
            "ef75c07d67989b74a0a2866f1765e2835b422ead9b39fc6f1eae674899e0618ada0"
            "0c29d9140d59aa8a0f931da006fc0f5697e64543fd641991de86af0fc6f3718776c"
            "59e6a347bfd73413932ba0eca5f51af6b6219f3e7944b9577bf266d3496cb37ac8f"
            "d712843af11d02e30ffb2b847b6386195f894d34e80caaf26fa6c37dd10b0e13101"
            "d0c053a931a9fbeea44994ea61adb2f0e427a3cc")

        coinbase_tx_hash = coinbase_tx_get_hash(coinbase_tx)
        merkle_root = get_merkle_root(block_header)

        self.assertTrue(is_valid_merkle_proof(merkle_proof, merkle_root,
                                              coinbase_tx_hash))

    # Case taken from https://explorer.rsk.co/block/1922766
    def test_valid_pow_block_1922766(self):
        coinbase_tx = (
            "00000000000000c0f1b4f631cd13f1ea3035c6a750ef6fbd1b31114f240b6dbc56"
            "73e6d426c97828676a3cde8b29c70b030d3700000000000000002b6a2952534b42"
            "4c4f434b3a026f5babf7343f6204f4169522ac5fc8e0c83747492a18f654ef1c20"
            "001d56ce0000000000000000266a24b9e11b6d69647308c07cce40754123a67181"
            "3c790b8eb019de841342cdf22e1a86cb82a800000000")

        block_header = (
            "00e0ff3f5eead175ce1c4d051ffa5962f799935388c3b15b148e040000000000000"
            "000001043b7faa6ca83c206607e1d115307b5c6a89bc96d84c60ada94cc3075b20d"
            "da6abee55d3eb2151713115ed1")

        merkle_proof = (
            "bac42978e28731524cca8f2f1aa6f585fe88126397188f7bfb5e7977cafed738920"
            "103f3dad5823d8ab3784e51c984d0fedc77b853ad6a58adcdd92d89631bbd88e845"
            "4ad1cfa7c1f060ae78f4bc19d839ea4767d303e6167f39612a3cf95c22b6598987a"
            "11b057a167718ed3b7683ee1f2211d0d855ddbfa9a5d12c2865ee8f19b5a8fd6d57"
            "642425681ba88c32ee4100f1764999182f67fbd7018f8fee6b1e6e061039add22c2"
            "445856f8d2f0743af170eb69af55b6f8cb4ae636eecd5f49aee0a77ca15460ea7a9"
            "0615d90aef244e473552a1bc00a5578c3ddd748447fa193fba521c129e75cdc3b7e"
            "d46d2deeec659cc61ba5fabce97a4a09dd0aa96a67f803aa74027c3b926e38d6aaa"
            "b6f37b1a60d192c944dba8d9b6a9b3e48228d666d3adaea562a4e34067f4c5503e0"
            "878b2b748edf53b389340cb5292a6e8ddb5b9")

        coinbase_tx_hash = coinbase_tx_get_hash(coinbase_tx)
        merkle_root = get_merkle_root(block_header)

        self.assertTrue(is_valid_merkle_proof(merkle_proof, merkle_root,
                                              coinbase_tx_hash))

    # Case taken from https://explorer.rsk.co/block/2123567
    def test_valid_pow_block_2123567(self):
        coinbase_tx = (
            "00000000000000c04cef4dbeb65637e41a5630f595f1ce3055748a090204f811d8db7c"
            "0f2a71b77e0fd0fa30e9641c80a71af500000000000000002b6a2952534b424c4f434b"
            "3a26d1d511740ac8e8b6e90bb068c07c08091c334bc4f232efd19533220020672f0000"
            "000000000000266a24b9e11b6dbae5d451a9cd3ae2ea3daa44dc0a68d16ed2ecb05f6d"
            "ea332dd0481178b8e5cd00000000")

        block_header = (
            "0000c0209b7a6bbc6da94132d7a344ec61e479a3587f952904620a000000000000000"
            "000fa4dcfd0d72f9bc22f43a6bd4f0a85ca4c8447e4405972435ec5fdf152dc52049846"
            "4b5ed41a12178c327896")

        merkle_proof = (
            "b80b3e93911ca9f5b0936c2bcd874bf5d2b1b2cb414c7c4ee185356953144e3fb8eaa5f"
            "6c970f69475067669dfb6797bf2131fc49425d06cf3c8f1622afde5faa29a40f7aefd5d"
            "b33ab7b35a624b3f91ce2594093623916a6c28b5fa734072570da278f4bf5d406b0811a"
            "0ade2b4a177b4f2fdf27893ece200a4265b37268ae6a6f93d56e896cd9cc94ad216f6b3"
            "e944094acfcaf1d804ca49636980e7900c34faa5b7ad2850d254aab37c86ae3fc7a7178"
            "dcc247f22a25eb559cb0825fdb0b0f3c047c519ca12cf78c073dd69544d0696e20e488b"
            "d2a2af654ec57cf4a397af6fbb014225b8419ed3e1b2f089cc11db87252e0b5f0b08d25"
            "53865fb178b0355a0acce0c7f58cfb72338115fd556cdd3432a49d4a60d1288387d5e23"
            "1d16a5c3eb3f6d1bd5e0ca47e59830bb3a0af6e01482aa0bc483f3ff1ad70b9d9967c74"
            "c84bd6877efdaa61b6fdc959af1dc94de458ddea29221395600f6e5fa5f56f7d1")

        coinbase_tx_hash = coinbase_tx_get_hash(coinbase_tx)
        merkle_root = get_merkle_root(block_header)

        self.assertTrue(is_valid_merkle_proof(merkle_proof, merkle_root,
                                              coinbase_tx_hash))
