from unittest import TestCase
from unittest.mock import patch, call
from simulator.rsk.block import RskBlockHeader
from simulator.rsk.netparams import NetworkParameters, NetworkUpgrades
from tests.utils import removespace
import rlp
import sha3

import logging

logging.disable(logging.CRITICAL)


class TestRskBlockHeader(TestCase):
    def setUp(self):
        self.netparams = NetworkParameters(
            NetworkUpgrades(wasabi=2000, papyrus=2500, iris=5000))

    def mock_raw_block(
        self,
        parent_hash,
        receipt_root,
        difficulty,
        number,
        mm_header,
        mm_mp,
        mm_cbtx,
        umm_root,
        with_mm=True,
    ):
        umm_offset = 1 if umm_root is not None else 0
        num_fields = (19 if with_mm else 17) + umm_offset
        block_list = [0]*num_fields
        block_list[0] = bytes.fromhex(parent_hash)
        block_list[5] = bytes.fromhex(receipt_root)
        block_list[7] = difficulty.to_bytes((difficulty.bit_length() + 7)//8,
                                            byteorder="big",
                                            signed=True)
        block_list[8] = number.to_bytes((number.bit_length() + 7)//8,
                                        byteorder="big",
                                        signed=False)
        if umm_root is not None:
            block_list[16] = bytes.fromhex(umm_root)
        block_list[16 + umm_offset] = bytes.fromhex(mm_header)
        if with_mm:
            block_list[17 + umm_offset] = bytes.fromhex(mm_mp)
            block_list[18 + umm_offset] = bytes.fromhex(mm_cbtx)
        mocked_block = rlp.encode(block_list).hex()
        mocked_block_hash_mm = None
        if with_mm:
            mocked_block_hash_mm = (sha3.keccak_256(rlp.encode(
                block_list[:-3])).digest().hex())
            mocked_block_hash = (sha3.keccak_256(rlp.encode(
                block_list[:-2])).digest().hex())
        else:
            mocked_block_hash = sha3.keccak_256(rlp.encode(block_list)).digest().hex()
        return (mocked_block, mocked_block_hash_mm, mocked_block_hash)

    def test_decoding_ok_before_umm(self):
        mocked_block, mocked_block_hash_mm, mocked_block_hash = self.mock_raw_block(
            "22"*32, "11"*32, 100, 2100, "aa", "bb", "cc", None)
        block_header = RskBlockHeader(mocked_block, self.netparams)
        expected_hash = (mocked_block_hash_mm[:40] + "00"*8 +
                         (2100).to_bytes(4, byteorder="big", signed=False).hex())
        self.assertEqual(block_header.hash, mocked_block_hash)
        self.assertEqual(block_header.hash_for_merge_mining, expected_hash)
        self.assertEqual(block_header.hash_for_merge_mining_mask,
                         "ff"*20 + "00"*8 + "ff"*4)

    def test_decoding_ok_umm(self):
        mocked_block, mocked_block_hash_mm, mocked_block_hash = self.mock_raw_block(
            "22"*32, "11"*32, 100, 3000, "aa", "bb", "cc", "33"*20)
        block_header = RskBlockHeader(mocked_block, self.netparams)
        umm_hash = (sha3.keccak_256(bytes.fromhex(mocked_block_hash_mm[:40] +
                                                  "33"*20)).digest()[:20].hex())
        expected_hash = (umm_hash + "00"*8 +
                         (3000).to_bytes(4, byteorder="big", signed=False).hex())
        self.assertEqual(block_header.hash, mocked_block_hash)
        self.assertEqual(block_header.hash_for_merge_mining, expected_hash)
        self.assertEqual(block_header.hash_for_merge_mining_mask,
                         "ff"*20 + "00"*8 + "ff"*4)

    def test_decoding_ok_no_mm(self):
        mocked_block, mocked_block_hash_mm, mocked_block_hash = self.mock_raw_block(
            "22"*32, "11"*32, 100, 2100, "aa", "bb", "cc", None, with_mm=False)
        block_header = RskBlockHeader(mocked_block, self.netparams, mm_is_mandatory=False)
        self.assertEqual(block_header.hash, mocked_block_hash)
        self.assertEqual(block_header.hash_for_merge_mining, None)
        self.assertEqual(block_header.hash_for_merge_mining_mask, None)

    def test_decoding_ok_umm_no_mm(self):
        mocked_block, mocked_block_hash_mm, mocked_block_hash = self.mock_raw_block(
            "22"*32, "11"*32, 100, 3000, "aa", "bb", "cc", "33"*20, with_mm=False)
        block_header = RskBlockHeader(mocked_block, self.netparams, mm_is_mandatory=False)
        self.assertEqual(block_header.hash, mocked_block_hash)
        self.assertEqual(block_header.hash_for_merge_mining, None)
        self.assertEqual(block_header.hash_for_merge_mining_mask, None)

    def test_fields_ok(self):
        mocked_block, _, _ = self.mock_raw_block("22"*32, "11"*32, 100, 2100, "aa",
                                                 "bbcc", "ddeeff", None)
        block_header = RskBlockHeader(mocked_block, self.netparams)
        self.assertEqual(block_header.parent_hash, "22"*32)
        self.assertEqual(block_header.receipts_trie_root, "11"*32)
        self.assertEqual(block_header.difficulty, 100)
        self.assertEqual(block_header.number, 2100)
        self.assertEqual(block_header.mm_header, "aa")
        self.assertEqual(block_header.mm_merkleproof, "bbcc")
        self.assertEqual(block_header.mm_coinbasetx, "ddeeff")
        self.assertEqual(block_header.umm_root, None)

    def test_fields_ok_no_mm(self):
        mocked_block, _, _ = self.mock_raw_block(
            "22"*32,
            "11"*32,
            100,
            2100,
            "aa",
            "doesntmatter",
            "doesntmatter",
            None,
            with_mm=False,
        )
        block_header = RskBlockHeader(mocked_block, self.netparams, mm_is_mandatory=False)
        self.assertEqual(block_header.parent_hash, "22"*32)
        self.assertEqual(block_header.receipts_trie_root, "11"*32)
        self.assertEqual(block_header.difficulty, 100)
        self.assertEqual(block_header.number, 2100)
        self.assertEqual(block_header.mm_header, "aa")
        self.assertEqual(block_header.mm_merkleproof, None)
        self.assertEqual(block_header.mm_coinbasetx, None)
        self.assertEqual(block_header.umm_root, None)

    def test_fields_ok_umm(self):
        mocked_block, _, _ = self.mock_raw_block("22"*32, "11"*32, 100, 3000, "aa",
                                                 "bbcc", "ddeeff", "33"*20)
        block_header = RskBlockHeader(mocked_block, self.netparams)
        self.assertEqual(block_header.parent_hash, "22"*32)
        self.assertEqual(block_header.receipts_trie_root, "11"*32)
        self.assertEqual(block_header.difficulty, 100)
        self.assertEqual(block_header.number, 3000)
        self.assertEqual(block_header.mm_header, "aa")
        self.assertEqual(block_header.mm_merkleproof, "bbcc")
        self.assertEqual(block_header.mm_coinbasetx, "ddeeff")
        self.assertEqual(block_header.umm_root, "33"*20)

    def test_fields_ok_umm_no_mm(self):
        mocked_block, _, _ = self.mock_raw_block(
            "22"*32,
            "11"*32,
            100,
            3000,
            "aa",
            "doesntmatter",
            "doesntmatter",
            "33"*20,
            with_mm=False,
        )
        block_header = RskBlockHeader(mocked_block, self.netparams, mm_is_mandatory=False)
        self.assertEqual(block_header.parent_hash, "22"*32)
        self.assertEqual(block_header.receipts_trie_root, "11"*32)
        self.assertEqual(block_header.difficulty, 100)
        self.assertEqual(block_header.number, 3000)
        self.assertEqual(block_header.mm_header, "aa")
        self.assertEqual(block_header.mm_merkleproof, None)
        self.assertEqual(block_header.mm_coinbasetx, None)
        self.assertEqual(block_header.umm_root, "33"*20)

    def test_fields_ok_umm_empty(self):
        mocked_block, _, _ = self.mock_raw_block("22"*32, "11"*32, 100, 3000, "aa",
                                                 "bbcc", "ddeeff", "")
        block_header = RskBlockHeader(mocked_block, self.netparams)
        self.assertEqual(block_header.parent_hash, "22"*32)
        self.assertEqual(block_header.receipts_trie_root, "11"*32)
        self.assertEqual(block_header.difficulty, 100)
        self.assertEqual(block_header.number, 3000)
        self.assertEqual(block_header.mm_header, "aa")
        self.assertEqual(block_header.mm_merkleproof, "bbcc")
        self.assertEqual(block_header.mm_coinbasetx, "ddeeff")
        self.assertEqual(block_header.umm_root, None)

    def test_fields_ok_umm_empty_no_mm(self):
        mocked_block, _, _ = self.mock_raw_block(
            "22"*32,
            "11"*32,
            100,
            3000,
            "aa",
            "doesntmatter",
            "doesntmatter",
            "",
            with_mm=False,
        )
        block_header = RskBlockHeader(mocked_block, self.netparams, mm_is_mandatory=False)
        self.assertEqual(block_header.parent_hash, "22"*32)
        self.assertEqual(block_header.receipts_trie_root, "11"*32)
        self.assertEqual(block_header.difficulty, 100)
        self.assertEqual(block_header.number, 3000)
        self.assertEqual(block_header.mm_header, "aa")
        self.assertEqual(block_header.mm_merkleproof, None)
        self.assertEqual(block_header.mm_coinbasetx, None)
        self.assertEqual(block_header.umm_root, None)

    def test_decoding_nonhex(self):
        with self.assertRaises(ValueError):
            RskBlockHeader("this-is-not-hexadecimal", self.netparams)

    def test_decoding_nonrlp(self):
        with self.assertRaises(ValueError):
            RskBlockHeader("aabbccddeeff", self.netparams)

    def test_decoding_list_length_invalid(self):
        mocked_block = rlp.encode([1, 2, 3]).hex()
        with self.assertRaises(ValueError):
            RskBlockHeader(mocked_block, self.netparams)

    def test_decoding_parent_hash_invalid(self):
        mocked_block, _, _ = self.mock_raw_block("22"*15, "11"*32, 100, 200, "aa", "bbcc",
                                                 "ddeeff", None)
        with self.assertRaises(ValueError):
            RskBlockHeader(mocked_block, self.netparams)

    def test_decoding_receipt_invalid(self):
        mocked_block, _, _ = self.mock_raw_block("22"*32, "11"*15, 100, 200, "aa", "bbcc",
                                                 "ddeeff", None)
        with self.assertRaises(ValueError):
            RskBlockHeader(mocked_block, self.netparams)

    def test_decoding_difficulty_invalid(self):
        mocked_block, _, _ = self.mock_raw_block("22"*32, "11"*32, -100, 200, "aa",
                                                 "bbcc", "ddeeff", None)
        with self.assertRaises(ValueError):
            RskBlockHeader(mocked_block, self.netparams)

    def test_decoding_mm_invalid(self):
        mocked_block, _, _ = self.mock_raw_block("22"*32, "11"*32, 100, 3000, "aa",
                                                 "bbcc", "ddeeff", "aa"*11)
        with self.assertRaises(ValueError):
            RskBlockHeader(mocked_block, self.netparams)

    def test_decoding_list_length_invalid_mm_fork_notactive(self):
        mocked_block, _, _ = self.mock_raw_block("22"*32, "11"*32, 100, 2499, "aa",
                                                 "bbcc", "ddeeff", "aa"*20)
        with self.assertRaises(ValueError):
            RskBlockHeader(mocked_block, self.netparams)

    def test_decoding_list_length_invalid_mm_fork_active(self):
        mocked_block, _, _ = self.mock_raw_block("22"*32, "11"*32, 100, 2501, "aa",
                                                 "bbcc", "ddeeff", None)
        with self.assertRaises(ValueError):
            RskBlockHeader(mocked_block, self.netparams)

    def test_decoding_error_before_wasabi(self):
        mocked_block, _, _ = self.mock_raw_block("22"*32, "11"*32, 100, 7, "aa", "bb",
                                                 "cc", None)
        with self.assertRaises(ValueError):
            RskBlockHeader(mocked_block, self.netparams)

    def test_decoding_no_umm_mm_mandatory(self):
        mocked_block, _, _ = self.mock_raw_block("22"*32,
                                                 "11"*32,
                                                 100,
                                                 2700,
                                                 "aa",
                                                 "bb",
                                                 "cc",
                                                 "dd"*20,
                                                 with_mm=False)
        with self.assertRaises(ValueError):
            RskBlockHeader(mocked_block, self.netparams)

    def test_decoding_umm_mm_mandatory(self):
        mocked_block, _, _ = self.mock_raw_block("22"*32,
                                                 "11"*32,
                                                 100,
                                                 3000,
                                                 "aa",
                                                 "bb",
                                                 "cc",
                                                 "dd"*20,
                                                 with_mm=False)
        with self.assertRaises(ValueError):
            RskBlockHeader(mocked_block, self.netparams)

    def test_decoding_large_mmmp_before_iris(self):
        mocked_block, _, _ = self.mock_raw_block(
            "22"*32,
            "11"*32,
            100,
            3000,
            "aa",
            "bb"*1024,
            "cc",
            "dd"*20,
            with_mm=True,
        )
        block = RskBlockHeader(mocked_block, self.netparams)
        self.assertEqual("bb"*1024, block.mm_merkleproof)

    def test_decoding_large_mmmp_after_iris(self):
        mocked_block, _, _ = self.mock_raw_block(
            "22"*32,
            "11"*32,
            100,
            6000,
            "aa",
            "bb"*1024,
            "cc",
            "dd"*20,
            with_mm=True,
        )
        with self.assertRaises(ValueError):
            RskBlockHeader(mocked_block, self.netparams)


@patch("comm.bitcoin.get_block_hash_as_int")
@patch("comm.pow.difficulty_to_target")
@patch("comm.pow.coinbase_tx_extract_merge_mining_hash")
@patch("comm.pow.coinbase_tx_get_hash")
@patch("comm.bitcoin.get_merkle_root")
@patch("comm.pow.is_valid_merkle_proof")
class TestRskBlockHeaderPow(TestCase):
    def setUp(self):
        self.netparams = NetworkParameters(
            NetworkUpgrades(wasabi=0, papyrus=None, iris=None))
        fields = [0]*19
        fields[0] = bytes.fromhex("22"*32)  # Receipts trie root
        fields[5] = bytes.fromhex("33"*32)  # Receipts trie root
        fields[7] = b"\x00\x7b"  # Difficulty (123)
        fields[8] = b"\x01\xc8"  # Number (456)
        fields[16] = bytes.fromhex("44"*10)  # Merge mining header
        fields[17] = bytes.fromhex("66"*10)  # Merge mining merkle proof
        fields[18] = bytes.fromhex("55"*10)  # Merge mining coinbase tx
        self.raw_fields = fields
        raw_block = rlp.encode(fields).hex()
        self.block = RskBlockHeader(raw_block, self.netparams)

    def test_pow_false_without_mm_fields(self, ivmp, gmr, cbtx_gh, cbtx_xmmh, diftt,
                                         gbhi):
        raw_block = rlp.encode(self.raw_fields[:-2]).hex()
        self.block = RskBlockHeader(raw_block, self.netparams, mm_is_mandatory=False)
        self.assertFalse(self.block.pow_is_valid())

    def test_pow_ok(self, ivmp, gmr, cbtx_gh, cbtx_xmmh, diftt, gbhi):
        gbhi.return_value = 89
        diftt.return_value = 100
        cbtx_xmmh.return_value = self.block.hash_for_merge_mining
        cbtx_gh.return_value = "cbtx_hash"
        gmr.return_value = "merkle_root"
        ivmp.return_value = True

        self.assertTrue(self.block.pow_is_valid())

        self.assertEqual(gbhi.call_args_list, [call("44"*10)])
        self.assertEqual(diftt.call_args_list, [call(123)])
        self.assertEqual(cbtx_xmmh.call_args_list, [call("55"*10)])
        self.assertEqual(cbtx_gh.call_args_list, [call("55"*10)])
        self.assertEqual(gmr.call_args_list, [call("44"*10)])
        self.assertEqual(ivmp.call_args_list, [call("66"*10, "merkle_root", "cbtx_hash")])

    def test_pow_target_mismatch(self, ivmp, gmr, cbtx_gh, cbtx_xmmh, diftt, gbhi):
        gbhi.return_value = 101
        diftt.return_value = 100

        self.assertFalse(self.block.pow_is_valid())

        self.assertEqual(gbhi.call_args_list, [call("44"*10)])
        self.assertEqual(diftt.call_args_list, [call(123)])
        self.assertFalse(cbtx_xmmh.called)
        self.assertFalse(cbtx_gh.called)
        self.assertFalse(gmr.called)
        self.assertFalse(ivmp.called)

    def test_pow_mergemining_block_header_invalid(self, ivmp, gmr, cbtx_gh, cbtx_xmmh,
                                                  diftt, gbhi):
        gbhi.side_effect = ValueError()

        self.assertFalse(self.block.pow_is_valid())

        self.assertEqual(gbhi.call_args_list, [call("44"*10)])
        self.assertFalse(diftt.called)
        self.assertFalse(cbtx_xmmh.called)
        self.assertFalse(cbtx_gh.called)
        self.assertFalse(gmr.called)
        self.assertFalse(ivmp.called)

    def test_hash_for_mm_mismatch(self, ivmp, gmr, cbtx_gh, cbtx_xmmh, diftt, gbhi):
        gbhi.return_value = 89
        diftt.return_value = 100
        cbtx_xmmh.return_value = "bb"*32

        self.assertFalse(self.block.pow_is_valid())

        self.assertEqual(gbhi.call_args_list, [call("44"*10)])
        self.assertEqual(diftt.call_args_list, [call(123)])
        self.assertEqual(cbtx_xmmh.call_args_list, [call("55"*10)])
        self.assertFalse(cbtx_gh.called)
        self.assertFalse(gmr.called)
        self.assertFalse(ivmp.called)

    def test_hash_for_mm_extraction_error(self, ivmp, gmr, cbtx_gh, cbtx_xmmh, diftt,
                                          gbhi):
        gbhi.return_value = 89
        diftt.return_value = 100
        cbtx_xmmh.side_effect = ValueError()

        self.assertFalse(self.block.pow_is_valid())

        self.assertEqual(gbhi.call_args_list, [call("44"*10)])
        self.assertEqual(diftt.call_args_list, [call(123)])
        self.assertEqual(cbtx_xmmh.call_args_list, [call("55"*10)])
        self.assertFalse(cbtx_gh.called)
        self.assertFalse(gmr.called)
        self.assertFalse(ivmp.called)

    def test_pow_invalid_merkle_proof(self, ivmp, gmr, cbtx_gh, cbtx_xmmh, diftt, gbhi):
        gbhi.return_value = 89
        diftt.return_value = 100
        cbtx_xmmh.return_value = self.block.hash_for_merge_mining
        cbtx_gh.return_value = "cbtx_hash"
        gmr.return_value = "merkle_root"
        ivmp.return_value = False

        self.assertFalse(self.block.pow_is_valid())

        self.assertEqual(gbhi.call_args_list, [call("44"*10)])
        self.assertEqual(diftt.call_args_list, [call(123)])
        self.assertEqual(cbtx_xmmh.call_args_list, [call("55"*10)])
        self.assertEqual(cbtx_gh.call_args_list, [call("55"*10)])
        self.assertEqual(gmr.call_args_list, [call("44"*10)])
        self.assertEqual(ivmp.call_args_list, [call("66"*10, "merkle_root", "cbtx_hash")])

    def test_pow_cbtx_hash_extraction_error(self, ivmp, gmr, cbtx_gh, cbtx_xmmh, diftt,
                                            gbhi):
        gbhi.return_value = 89
        diftt.return_value = 100
        cbtx_xmmh.return_value = self.block.hash_for_merge_mining
        cbtx_gh.side_effect = ValueError()

        self.assertFalse(self.block.pow_is_valid())

        self.assertEqual(gbhi.call_args_list, [call("44"*10)])
        self.assertEqual(diftt.call_args_list, [call(123)])
        self.assertEqual(cbtx_xmmh.call_args_list, [call("55"*10)])
        self.assertEqual(cbtx_gh.call_args_list, [call("55"*10)])
        self.assertFalse(gmr.called)
        self.assertFalse(ivmp.called)

    def test_pow_merkle_root_extraction_error(self, ivmp, gmr, cbtx_gh, cbtx_xmmh, diftt,
                                              gbhi):
        gbhi.return_value = 89
        diftt.return_value = 100
        cbtx_xmmh.return_value = self.block.hash_for_merge_mining
        cbtx_gh.return_value = "cbtx_hash"
        gmr.side_effect = ValueError()

        self.assertFalse(self.block.pow_is_valid())

        self.assertEqual(gbhi.call_args_list, [call("44"*10)])
        self.assertEqual(diftt.call_args_list, [call(123)])
        self.assertEqual(cbtx_xmmh.call_args_list, [call("55"*10)])
        self.assertEqual(cbtx_gh.call_args_list, [call("55"*10)])
        self.assertEqual(gmr.call_args_list, [call("44"*10)])
        self.assertFalse(ivmp.called)

    def test_pow_merkle_proof_verification_error(self, ivmp, gmr, cbtx_gh, cbtx_xmmh,
                                                 diftt, gbhi):
        gbhi.return_value = 89
        diftt.return_value = 100
        cbtx_xmmh.return_value = self.block.hash_for_merge_mining
        cbtx_gh.return_value = "cbtx_hash"
        gmr.return_value = "merkle_root"
        ivmp.side_effect = ValueError()

        self.assertFalse(self.block.pow_is_valid())

        self.assertEqual(gbhi.call_args_list, [call("44"*10)])
        self.assertEqual(diftt.call_args_list, [call(123)])
        self.assertEqual(cbtx_xmmh.call_args_list, [call("55"*10)])
        self.assertEqual(cbtx_gh.call_args_list, [call("55"*10)])
        self.assertEqual(gmr.call_args_list, [call("44"*10)])
        self.assertEqual(ivmp.call_args_list, [call("66"*10, "merkle_root", "cbtx_hash")])


class TestRskBlockHeaderRealCases(TestCase):
    def setUp(self):
        # TODO: add papyrus cases when it is activated
        self.netparams = NetworkParameters.MAINNET

    def test_hash_for_merge_mining_before_umm(self):
        # Mainnet block #2392650
        # (0xb02b95364314bd817e82ebb9c6694aa174980f023fa3bc234920c37044f97b8b)
        # https://explorer.rsk.co/block/2392650
        # This block was mined BEFORE umm (papyrus)
        block = RskBlockHeader(removespace("""
            f90432a069878041d1b78d6105862eb9efa5e6da851330f2c00fb92f3ab4a04bbea1337ca01dcc
            4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794512bfa2264b89b91
            406fff40f32f90f02d79d452a04ebbec04098cc2d397c4fc6d06ca85b4658d8f072e95c674cf42
            db23b1b6f40da00747a3109114d666be1c561740a9c2f163e67e891025e762e94cc4ced9095a7e
            a066cfdb731f620cd96e2c2cb0f7d3c3a2879c29b40014aa27efbbf3cf9cd3b0f6b90100000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            00000000000000000000000000000000000000892a6430d0e1bdc6648e8324824a8367c2808084
            5ecedda592d1018f504150595255532d3364623466313380840387ee4080b85000e0ff37ac4c05
            76dd671e0f2aa4b43b45d6db7ff7878dadc1b8100000000000000000004ad8be29fbe538aebd1f
            212199bb4d7639cb4b1d1a98288871606bffa41dcfc5b2ddce5ef6971217d419ab23b90180f3b7
            6a7fe9f9ec737a68c26d56cdcf1f8569e99761c93552a572ce34b167ce90adffb3b9d4522d59bf
            5ed7147d0acb79f759a4d8211e63a375b6849f7c2f01836f41d8c3cfbeda2c7df0979ff6206307
            dfe6bb6993b5e954af82e81b12a90727d2b5220008e3095259c91638e91fb22a96d2ccb5f5db66
            bddba92b8c7ddec2b82993407c8a091479476591b70c54b571d599bf1b1f340cdb6561407211bd
            841998764d25a6b74a31f0985cfecbc990fd724ad15e3962564179e0b1e9233802280676e6d68e
            e88e9c2188a7cbac4dc8c9ce82e8aba0776868580b41aac0f427f9b44f7d137d3cc1f4c3446603
            2529616b94062a90fa690b7286cc470d57ad10f3a189a1871bac1b1af3d5411dc655f3ca747203
            7757d4d3886fa7bae881adcd4d1bb2b90d2146c103701717a94d1234ae7e175deab161e3a2009f
            c7ec73fd89fdaa862e1fe7757709f59e89d8cab9c39fd10381c4cc143e901bc2ab75317a7cf215
            f82388a3802d20a8b1d97fa6554c9f805118ac62f6bcc0a4a397806b19348fb86c000000000000
            0100f40b78dce0050a0fefeafff218a05ad64f2a761a99fafb8aba34fc31effbe3edf76ab477ad
            aaae51298072d200000000000000002b6a2952534b424c4f434b3a2f5b356c48cd1f432d996df3
            da67f640c870f626b5b2cf313eb62b240024824aeed26c05
            """), self.netparams)

        self.assertTrue(
            block.hash_for_merge_mining_matches(
                "2f5b356c48cd1f432d996df3da67f640c870f626b5b2cf313eb62b240024824a"))
        self.assertTrue(
            block.hash_for_merge_mining_matches(
                "2f5b356c48cd1f432d996df3da67f640c870f626b5b2cfaabbcc2b240024824a")
        )  # Dif middle part (ignored)

        self.assertFalse(
            block.hash_for_merge_mining_matches(
                "2f5b356c48cd1f432d99da67f640c870f626b5b2cf313eb62b240024824a")
        )  # Shorter
        self.assertFalse(
            block.hash_for_merge_mining_matches(
                "2f5b356c48cd1f432d996df3da67f640c870f626b5b2cf313eb62b240024604a")
        )  # Dif block number
        self.assertFalse(
            block.hash_for_merge_mining_matches(
                "2f5baabb48cd1f432d996df3da67f640c870f626b5b2cf313eb62b240024824a")
        )  # Dif hash prefix

        self.assertEqual(
            block.hash_for_merge_mining,
            "2f5b356c48cd1f432d996df3da67f640c870f62600000000000000000024824a",
        )
        self.assertEqual(block.hash_for_merge_mining_mask, "ff"*20 + "00"*8 + "ff"*4)

    def test_values_block_2221171(self):
        # Mainnet block #2221171
        # (0xb85475d61835a12259d71c370eba5186a4c342f2ad0d680853c1e3896480c8e7)
        # https://explorer.rsk.co/block/2221171
        # Mined PRE papyrus
        block = RskBlockHeader(removespace("""
            f9045fa0ccd975c98950f01b915d6e005a9baf32bb8b51c4006236177a137ce851c31f57a06e7d
            85dbc1efe339c677cd6b0c363502f674e8cbc759b9c86ec509d7e761e72694fd61e17c981b8f80
            b40f0c60830779a6ce8473d3a078c234db9525c623957e8bdacfab75ed8d8009d22ccb60e34415
            f4fdc333b250a06805dc6be8f907cbbf468c086edfb741aac1c014d876516e37560e4f6e637174
            a0c7bdacce76965ab7e2e359bcf461ac780c28fb2bf0caed3324c9c9ceb9e534d8b90100000000
            000000000000000000000000004000000000000800000000000000000000000000000000000000
            000000000000400000000000000000000000000000000000000000000000000000000000000000
            000000000000000000020000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000200000000000000000000000000000000000000000
            000000000000001000200000000000000000000000000000000010000000000000000000010000
            000000000000000000000000200001000004002000001000000000000000000000000000040000
            000000000200000000000000000000400400008924a21ed8af9e5cee898321e4738367c2808084
            5e7c9df891d0018e5741534142492d6261383139343380840387ee4003b85000e0ff3fa667099c
            0900a5286fa1e543f518c1e82750cfdcc1cc0c000000000000000000bf018c0cbf29e271c854e7
            0982def173bfafe4d4b7d8927711fbc591bb9730ff2d9e7c5e413b141784c5f634b90180a9ff06
            cfcc2028e32897d12d6261cf272426714c1f2b146b93605f1b6ca74849e8be9d69823d9c70ebdc
            706d8ce178a3f73a49be9bfae5f924748705827c3ece4f67e9290907c115a71091a24e140b2e0c
            a9df01c10cc0e41b8cb9b4e79eb58551468a62b90c0297c306f70c78a5ac55f23874230ef861c3
            aa281b5e782bf5c497583d8412cc1a558e4ae9d43c3e4ddea47dcd80d6880eca083af903d44d9a
            cad6d06469b3299ef08ce53dffb90b11d424642f19a2631b98b2e8b9ff9a6c6446ea626387e03e
            77f63d1698c4d9cd8cd3db145a47ea21af9fe2659b2642e69ca67acb6930db5aed164b8337cd26
            522a1259f7097939db378343d261acac5252310c0fff1f17232d9003a8e70ded24391da550d6a0
            60f6b54bf4d6b8f50b9c2ae42d073155f8a0fb1c504c817e5567102d7efdb03ac21c0780c4dd1d
            08aa4e955fdc8b3adeb689375c9984879bb66c4aec615e031d6ff39e0618c474a99f0b0485792c
            07de65ec9c49395d7deb3f3f9a5891e3a6e90b86a6e68ec7a61a4a9743e4b89a00000000000000
            c089537475d31f9eda54e6d00192b271c89d67f6588651eaa839fa5d69f8357a97618f3cb58d83
            a7377f154400000000000000002b6a2952534b424c4f434b3a765e8796c8ca4e47bb967c24b5a2
            d71a9fbf54bce89b08cec476882b0021e4730000000000000000266a24b9e11b6d857295153b2d
            d1fd163de14567e984d75b51d969c7a933650401f4b57a515ae700000000
            """), self.netparams)
        self.assertEqual(
            block.hash,
            "b85475d61835a12259d71c370eba5186a4c342f2ad0d680853c1e3896480c8e7")
        self.assertEqual(
            block.parent_hash,
            "ccd975c98950f01b915d6e005a9baf32bb8b51c4006236177a137ce851c31f57",
        )
        self.assertEqual(block.difficulty, 675764799385777270409)
        self.assertEqual(block.number, 2221171)
        self.assertEqual(block.umm_root, None)
        self.assertEqual(
            block.mm_header,

            "00e0ff3fa667099c0900a5286fa1e543f518c1e82750cfdcc1cc0c000000000000000000bf01"
            "8c0cbf29e271c854e70982def173bfafe4d4b7d8927711fbc591bb9730ff2d9e7c5e413b1417"
            "84c5f634",
        )
        self.assertEqual(
            block.mm_merkleproof,
            removespace("""
            a9ff06cfcc2028e32897d12d6261cf272426714c1f2b146b93605f1b6ca74849e8be9d69823d9c
            70ebdc706d8ce178a3f73a49be9bfae5f924748705827c3ece4f67e9290907c115a71091a24e14
            0b2e0ca9df01c10cc0e41b8cb9b4e79eb58551468a62b90c0297c306f70c78a5ac55f23874230e
            f861c3aa281b5e782bf5c497583d8412cc1a558e4ae9d43c3e4ddea47dcd80d6880eca083af903
            d44d9acad6d06469b3299ef08ce53dffb90b11d424642f19a2631b98b2e8b9ff9a6c6446ea6263
            87e03e77f63d1698c4d9cd8cd3db145a47ea21af9fe2659b2642e69ca67acb6930db5aed164b83
            37cd26522a1259f7097939db378343d261acac5252310c0fff1f17232d9003a8e70ded24391da5
            50d6a060f6b54bf4d6b8f50b9c2ae42d073155f8a0fb1c504c817e5567102d7efdb03ac21c0780
            c4dd1d08aa4e955fdc8b3adeb689375c9984879bb66c4aec615e031d6ff39e0618c474a99f0b04
            85792c07de65ec9c49395d7deb3f3f9a5891e3a6e90b86a6e68ec7a61a4a9743e4
            """)
        )
        self.assertEqual(
            block.mm_coinbasetx,
            removespace("""
            00000000000000c089537475d31f9eda54e6d00192b271c89d67f6588651eaa839fa5d69f8357a
            97618f3cb58d83a7377f154400000000000000002b6a2952534b424c4f434b3a765e8796c8ca4e
            47bb967c24b5a2d71a9fbf54bce89b08cec476882b0021e4730000000000000000266a24b9e11b
            6d857295153b2dd1fd163de14567e984d75b51d969c7a933650401f4b57a515ae700000000
            """)
        )

    def test_values_block_2221171_no_mm(self):
        # Mainnet block #2221171
        # (0xb85475d61835a12259d71c370eba5186a4c342f2ad0d680853c1e3896480c8e7)
        # https://explorer.rsk.co/block/2221171
        # Mined POST papyrus
        block = RskBlockHeader(
            removespace("""
            f90240a0ccd975c98950f01b915d6e005a9baf32bb8b51c4006236177a137ce851c31f57a06e7d
            85dbc1efe339c677cd6b0c363502f674e8cbc759b9c86ec509d7e761e72694fd61e17c981b8f80
            b40f0c60830779a6ce8473d3a078c234db9525c623957e8bdacfab75ed8d8009d22ccb60e34415
            f4fdc333b250a06805dc6be8f907cbbf468c086edfb741aac1c014d876516e37560e4f6e637174
            a0c7bdacce76965ab7e2e359bcf461ac780c28fb2bf0caed3324c9c9ceb9e534d8b90100000000
            000000000000000000000000004000000000000800000000000000000000000000000000000000
            000000000000400000000000000000000000000000000000000000000000000000000000000000
            000000000000000000020000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000200000000000000000000000000000000000000000
            000000000000001000200000000000000000000000000000000010000000000000000000010000
            000000000000000000000000200001000004002000001000000000000000000000000000040000
            000000000200000000000000000000400400008924a21ed8af9e5cee898321e4738367c2808084
            5e7c9df891d0018e5741534142492d6261383139343380840387ee4003b85000e0ff3fa667099c
            0900a5286fa1e543f518c1e82750cfdcc1cc0c000000000000000000bf018c0cbf29e271c854e7
            0982def173bfafe4d4b7d8927711fbc591bb9730ff2d9e7c5e413b141784c5f634
            """), self.netparams, mm_is_mandatory=False)

        self.assertEqual(
            block.hash,
            "b85475d61835a12259d71c370eba5186a4c342f2ad0d680853c1e3896480c8e7")
        self.assertEqual(
            block.parent_hash,
            "ccd975c98950f01b915d6e005a9baf32bb8b51c4006236177a137ce851c31f57")
        self.assertEqual(block.difficulty, 675764799385777270409)
        self.assertEqual(block.number, 2221171)
        self.assertEqual(block.umm_root, None)
        self.assertEqual(
            block.mm_header,

            "00e0ff3fa667099c0900a5286fa1e543f518c1e82750cfdcc1cc0c000000000000000000bf01"
            "8c0cbf29e271c854e70982def173bfafe4d4b7d8927711fbc591bb9730ff2d9e7c5e413b1417"
            "84c5f634")

        self.assertEqual(block.mm_merkleproof, None)
        self.assertEqual(block.mm_coinbasetx, None)

    def test_values_block_2392715(self):
        # Mainnet block #2392715
        # (0xb85475d61835a12259d71c370eba5186a4c342f2ad0d680853c1e3896480c8e7)
        # https://explorer.rsk.co/block/2392715
        # Mined POST papyrus
        block = RskBlockHeader(
            removespace("""
            f9048ca0b1beb84b8a8cd8bdbb05206c80fadc1623387dd4bd3bad76519a060e57c8b19fa06c18
            1a09c1f25432533fd69f2b60b1b50745e55ac08d39a22047a7edcc2ef66e9412d3178a62ef1f52
            0944534ed04504609f7307a1a08de1e51020d5fdd1c73271a3e03fe3563a099ad00f57687a0a08
            1baa0c1360eaa0dbbc52bdca0e108baa0a4311657a17a3bc54998f1b086f48f91230d4677c4392
            a0df05ce88c61a7aaaed16ac17b03beba1f2ee8b2e894a3f0e619d9d5a907a229bb90100000000
            000000000000001010000000000000000000000000000000000000000000000000000100000000
            000000000000000000000000000000008000000010000000000000000000000000000000000800
            000000000000001000000000000000000000000000000000400000000000000000000000000000
            000000000000000000000000000000010000000000040000000000000000000000000000200000
            000000000002000000000000100000000000800000000000800000000000000000000000200000
            000000000000000080800000000000000000000000000000000000000000000000000020000000
            00000000000400000000000000200000000000892f213d43016f7055588324828b8367c28082f1
            9d845ecee4c392d1018f504150595255532d336462346631338603601390cb00840387d71c0380
            b8500000c02035305b7f84c04ba6b47b98d3e8fbae6d5e5cdb9e7b150200000000000000000090
            3c607c9b06086cb220600c04526fbce4c3a9730aeca7851ed7afc2c1903a15cbe4ce5ef6971217
            35524e51b90180a61277ddd3dfb8e1ee1bff75043ef3af39b706ab7d2e0646aa459c8c0fe9080c
            5abc009eb16fd64b2bc43badd0e71b81b6ac5dad368ccd176d2a05219d09dad84893c92fd86402
            fc27a95fd813070492b37d90e6724180c6902617d701ef644a9e71eeaf7a0af78909f2055165d2
            3335f67bac72259a3b706f2590d03aa5b6546ea0cdaa36c40a415227767f7f7eb1ae1d7b780d16
            5f5abe368560adec0f18e0fda2137deec39ceda98e31b97ca88db366fcd17e39fbf30d09222d74
            2fbd56f56d3b89abf5b0dc7b496da0532a8b3c84718ea5dcd0d90f2c00c8de7c4bd561b8137fc7
            44dfb5c31067e4e69657f0153552666b2fc7f03513df396e29907c818fd25931c58a340515aea9
            4930968cfbf52fafbc9fff47271427ae31946af60fca7fae7cdf08bfb487baaf2ec27508e5a79d
            525b63bcda832e78a153d2931c837745d5c6e6448377f9d049b47beaaa64a5cd26745f4e4cbf69
            25d10fd1acd31191ca69ec5f9d6cca54bada5a57ef8556893778f5daeb112c2fc75094ef8745ed
            0db8bd00000000000000c0384403f9084ff43eb8f135d1435cc6213fec8876a8c45c0a1377d67b
            37b04822aa21a9edd55f6ff89c39ba1accaa2052fcd4e0241bf15bc4d906d9dd7b5aa9c2446c8c
            1a08000000000000000000000000000000002c6a4c2952534b424c4f434b3a147befba26394e0e
            60ba29a65fd59a208ac3466b0bb5b2cf313eb61c0024828b0000000000000000266a24b9e11b6d
            1bf133d73966470db216806152e1b7f89f1d349d65efcec4279513e9616e79844ac9e83f
            """), self.netparams)

        self.assertEqual(
            block.hash,
            "ab928296e0038fab054dc5146c3c740b6d13f5cbe2c916ab847e37c20996a116")
        self.assertEqual(
            block.parent_hash,
            "b1beb84b8a8cd8bdbb05206c80fadc1623387dd4bd3bad76519a060e57c8b19f",
        )
        self.assertEqual(block.difficulty, 869392115714623559000)
        self.assertEqual(block.number, 2392715)
        self.assertEqual(block.umm_root, None)
        self.assertEqual(
            block.mm_header,
            "0000c02035305b7f84c04ba6b47b98d3e8fbae6d5e5cdb9e7b1502000000000000000000903c"
            "607c9b06086cb220600c04526fbce4c3a9730aeca7851ed7afc2c1903a15cbe4ce5ef6971217"
            "35524e51")
        self.assertEqual(
            block.mm_merkleproof,
            removespace("""
            a61277ddd3dfb8e1ee1bff75043ef3af39b706ab7d2e0646aa459c8c0fe9080c5abc009eb16fd6
            4b2bc43badd0e71b81b6ac5dad368ccd176d2a05219d09dad84893c92fd86402fc27a95fd81307
            0492b37d90e6724180c6902617d701ef644a9e71eeaf7a0af78909f2055165d23335f67bac7225
            9a3b706f2590d03aa5b6546ea0cdaa36c40a415227767f7f7eb1ae1d7b780d165f5abe368560ad
            ec0f18e0fda2137deec39ceda98e31b97ca88db366fcd17e39fbf30d09222d742fbd56f56d3b89
            abf5b0dc7b496da0532a8b3c84718ea5dcd0d90f2c00c8de7c4bd561b8137fc744dfb5c31067e4
            e69657f0153552666b2fc7f03513df396e29907c818fd25931c58a340515aea94930968cfbf52f
            afbc9fff47271427ae31946af60fca7fae7cdf08bfb487baaf2ec27508e5a79d525b63bcda832e
            78a153d2931c837745d5c6e6448377f9d049b47beaaa64a5cd26745f4e4cbf6925d10fd1acd311
            91ca69ec5f9d6cca54bada5a57ef8556893778f5daeb112c2fc75094ef8745ed0d
            """)
        )
        self.assertEqual(
            block.mm_coinbasetx,
            "00000000000000c0384403f9084ff43eb8f135d1435cc6213fec8876a8c45c0a1377d67b37b0"
            "4822aa21a9edd55f6ff89c39ba1accaa2052fcd4e0241bf15bc4d906d9dd7b5aa9c2446c8c1a"
            "08000000000000000000000000000000002c6a4c2952534b424c4f434b3a147befba26394e0e"
            "60ba29a65fd59a208ac3466b0bb5b2cf313eb61c0024828b0000000000000000266a24b9e11b"
            "6d1bf133d73966470db216806152e1b7f89f1d349d65efcec4279513e9616e79844ac9e83f",
        )

    def test_values_block_2392715_no_mm(self):
        # Mainnet block #2392715
        # (0xb85475d61835a12259d71c370eba5186a4c342f2ad0d680853c1e3896480c8e7)
        # https://explorer.rsk.co/block/2392715
        # Mined POST papyrus
        block = RskBlockHeader(
            removespace("""
            f9024aa0b1beb84b8a8cd8bdbb05206c80fadc1623387dd4bd3bad76519a060e57c8b19fa06c18
            1a09c1f25432533fd69f2b60b1b50745e55ac08d39a22047a7edcc2ef66e9412d3178a62ef1f52
            0944534ed04504609f7307a1a08de1e51020d5fdd1c73271a3e03fe3563a099ad00f57687a0a08
            1baa0c1360eaa0dbbc52bdca0e108baa0a4311657a17a3bc54998f1b086f48f91230d4677c4392
            a0df05ce88c61a7aaaed16ac17b03beba1f2ee8b2e894a3f0e619d9d5a907a229bb90100000000
            000000000000001010000000000000000000000000000000000000000000000000000100000000
            000000000000000000000000000000008000000010000000000000000000000000000000000800
            000000000000001000000000000000000000000000000000400000000000000000000000000000
            000000000000000000000000000000010000000000040000000000000000000000000000200000
            000000000002000000000000100000000000800000000000800000000000000000000000200000
            000000000000000080800000000000000000000000000000000000000000000000000020000000
            00000000000400000000000000200000000000892f213d43016f7055588324828b8367c28082f1
            9d845ecee4c392d1018f504150595255532d336462346631338603601390cb00840387d71c0380
            b8500000c02035305b7f84c04ba6b47b98d3e8fbae6d5e5cdb9e7b150200000000000000000090
            3c607c9b06086cb220600c04526fbce4c3a9730aeca7851ed7afc2c1903a15cbe4ce5ef6971217
            35524e51
            """), self.netparams, mm_is_mandatory=False)

        self.assertEqual(
            block.hash,
            "ab928296e0038fab054dc5146c3c740b6d13f5cbe2c916ab847e37c20996a116")
        self.assertEqual(
            block.parent_hash,
            "b1beb84b8a8cd8bdbb05206c80fadc1623387dd4bd3bad76519a060e57c8b19f",
        )
        self.assertEqual(block.difficulty, 869392115714623559000)
        self.assertEqual(block.number, 2392715)
        self.assertEqual(block.umm_root, None)
        self.assertEqual(
            block.mm_header,
            "0000c02035305b7f84c04ba6b47b98d3e8fbae6d5e5cdb9e7b1502000000000000000000903c"
            "607c9b06086cb220600c04526fbce4c3a9730aeca7851ed7afc2c1903a15cbe4ce5ef6971217"
            "35524e51",
        )
        self.assertEqual(block.mm_merkleproof, None)
        self.assertEqual(block.mm_coinbasetx, None)

    def test_block_pre_wasabi_fails(self):
        with self.assertRaises(ValueError):
            # Mainnet block #1234000
            # (0x9e329333d41bc95c5098518fb8b00ed8eebbce721f2294d17c34f4bdbdde7141)
            # https://explorer.rsk.co/block/1234000
            RskBlockHeader(removespace("""
            f903faa02d7d70cd87ab39fe2eb495e800987a932178445a46058bc322a9ab8accfe2dcaa0885d
            c9a77e04e474d69dd23ba7785b13dad68bca776c0cf2e603ca3bc7092e8f9407c5446adb392be1
            16f4859a722589f3fa8223e4a0a92481f7afacf66b16aa37b5cbc135d3efe53062c6845d5f9078
            648f3833a59ca02d934a6a7a82eea0fd999f8765f89da6857af5437705bb52419ebfdc812fb20c
            a0a70fc9a7d692ac80a46b23dcf81d5928dbdebc8ac097cfdbce2c03301d9e9406b90100000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            00000000000000000000000000000000000000890c7128bff3f85949868312d4508367c2808084
            5c956bfc8080840387ee4006b850000000204d210fd999c85262dc575e1fc8e46de14d1e5967ca
            e31400000000000000000098861ee97ceb9294983faa9857be09b42419a71bce3af48d6e5fde2d
            478b5409026c955c17612e1768d1e7cfb90160d386d8121fa756b700265331e24e7394b5914bd9
            6988a045978acb090db2e6600a0eb230d927cbe45738b5761f330d009fca0266098d4365e6f06c
            066d31725a31a3d8aa83ea7d8d4f3b5af82d28ae4fc45ee375e62af5cb85b6675d8bb4e046aad2
            1f23defce915c3b46d61cc8d178ad9534ab373867ba11b6f8e15b04b7b2b8722f5a4135809da7f
            702a51e2012fb118e404138f6ef442372c4db45a2f13840b75bad1f83e6ad89df1ee0d8cea9cf1
            23bf89c11e9f561898645e7f5d4f420111069b8651119755c63f383eeb0bae3675ed9dcf1909ce
            b6133894ab1543ea8499527b21a301592716f45d35c08a25dad7f77153f3dce637e38f97f1bf0e
            e94ec706e999ac6092a03ceb5e119a6a05d81d4f007ab52f9068cf53a4ef8ae2b4dd9eec3ca1dc
            6e502665754c3dbd98351d5ba569928545aeae4cdfadaaf3f956484ec93400f3066d53b4f6fb72
            993772bcb19db253f5b48fc673193da5e49de0fab86600000000000000c0f27008b5baae4999c4
            53d0026ab5a37b5ee4418a0c841c5fea068b2d45e0a8396e458a8105a48a600000000000000000
            2952534b424c4f434b3a3a87592104b8560ff1abfc041a51680bfb7fbd8b38f7349710db329c5b
            05560d00000000
            """), self.netparams)


class TestRskBlockHeaderPoWRealCases(TestCase):
    def setUp(self):
        # TODO: add papyrus cases when it is activated
        self.netparams = NetworkParameters.MAINNET

    # Mainnet block #1900456
    # (0xf9c14231ee5fb62b81878f8ad4c57514ae0c6b392563cedcd1219be228c48b3a)
    # https://explorer.rsk.co/block/1900456
    # Mined PRE papyrus
    def test_block_1900456(self):
        self.assertValidPoW(
            removespace("""
            f903faa0de5112eb17bb47241ea1d9790d44da40e69d857387f22a30c1690c81162f09d0a01dcc
            4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479432dfc7a84f24b10a
            5dded1d8b24f48b96ab77373a06b8fdf474d365f0f8e652205448bb2e05d8d5099280c1e4a0fa6
            d994e4aeee5fa099198b0a11e5ed8e0b701257bc6043cb567338bee2ef467c0204dd7f867a1268
            a066cfdb731f620cd96e2c2cb0f7d3c3a2879c29b40014aa27efbbf3cf9cd3b0f6b90100000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            00000000000000000000000000000000000000891d2cc00b65ce49e9f3831cffa88367c2808084
            5ddb40c98080840387ee4080b8500000c020358a8dc9d5512e72515a2f5da0dd690a0dcee81234
            f60b0000000000000000009f830e238617a1d7b8a23dc4923ee7d31bac36a98371fa12d6770ee0
            cd2cb4bfd240db5d3eb21517602a0dd8b90120490303c3e15da7e4d21607c020304f13eb82ea3a
            d862d95c64db66c4f576d120761f44ba8c3e0a2a443197f689c44a6f83e881bb4e02dee9ebe175
            613ec641e069637cf80ef6f6fd697392bee2fbea376fa284735c015f5837894749efe602ace43c
            7b2b0c268b9c0055057201b17018905a24cd90f8dcc473a06079b4196d6cf8c3f9a195f313bffe
            69fd397575d915ac6cd7eccb893821ca2ee78e37accf062661c606afcca5d59b058ba98ea0843f
            bdf6a4e8ecf0a26dee5002ed474d87f7839905325fc188cb6a4e909bb19a5690df500878db3843
            a431d516915d0f09f429c44dabedb001194f9be16668748ec09e1bfbbb9d958bda38ec982fe225
            8bcff7d90a5d4d51b151af1a4e23d99d0b185dfe0af7db75b6b4c83f751d9004ce66b8a6000000
            000000008094f82539e03414f1958bcd48ad612a6d635b500ee15c12332fc250fc87fc51ec7c15
            4ed1dc59609e3d26abb2df2ea3d587cd8c4188ac00000000000000002c6a4c2952534b424c4f43
            4b3a1bb0cea339ee03deaa9959589a363370688fe99576b7a6776256a423001cffa80000000000
            000000266a24aa21a9edb78b477727bd814ded8c618b716a03e0931d4bc8b9c2ba6a8cc5b93646
            39f02d00000000
            """), 1900456)

    # Mainnet block #2392654
    # (0xd2f087664530b83a95c99d9e074a78a0486095921fd3b35dcbfc846b4f88f683)
    # https://explorer.rsk.co/block/2392654
    # Mined POST papyrus
    def test_block_2392654(self):
        self.assertValidPoW(
            removespace("""
            f90483a0b142cebc0976308fc93a9b8ff0217fd0dddf4d5a97551a5b1baf7e446a8f4f11a02e94
            9cfbe3b81a4e0a92e3559e091c3f7947d28c68069fb6feec8aa9cd1ea2a29412d3178a62ef1f52
            0944534ed04504609f7307a1a00952383f12f8e21d769956c3744b402f18376dfdb2ee435f3e5c
            327466f37d46a08f54f931f51541c67c526454c9734f01a9dfe48014299f04bf52d02853a83aba
            a066cfdb731f620cd96e2c2cb0f7d3c3a2879c29b40014aa27efbbf3cf9cd3b0f6b90100000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000008928b671a5cb48ffc3e78324824e8367c2808084
            5ecede3392d1018f504150595255532d3364623466313380840387ee4002b85000000020ac4c05
            76dd671e0f2aa4b43b45d6db7ff7878dadc1b8100000000000000000003724b0313ae53374009a
            46e60680982bfa627a7b12d69407accde21fe0521b7d3bdece5ef69712173a59ad27b90180f3b7
            6a7fe9f9ec737a68c26d56cdcf1f8569e99761c93552a572ce34b167ce905087848658ae818693
            1af1988838a0460d64014f4c2526b7f01e4f1091d596e56f9043da663e69f66b31da90f0c483ea
            f2b9bdecd5c48417be2b000e6354cf1ecb35a0d3b2a2546387312b0b7bd57e62d5ca756a1d0d47
            6a4c4c7f0e7054a2b3908b07d0d0133de42a551dd7e5bef20721101bf284cbc05526dd5a6b6a7c
            b6a3b797640f72f3d7f85cace1e6e52f8a3f824453260d81b8e827ea9a4ca2fe5ea90039bef64e
            ef0b4c6cd344bbb9a2747c71b9a1762e1973cd6d04f3dd3ee4fd76d25fa19f16e639825d384cb4
            ee9aadaac8100294a4584e9b57068ae31d52c7d5fb16540f86a427a8464257f9f3209b52fd15b5
            3d12ef2d4522a56161cd61551c8a55e12a1af558907d4cfe6c546f6e434ce9f62bfee2771af621
            0f9e19a03bc248a3fe8d64c4be8d596d9e1b516068d9c20362241a221f2018331348716cd7cfaa
            543b7f6f064ca0d8b838255fc867be1c6dbfe55eb3c5392e78b55ed1038bedb8bd000000000000
            00c095307b25ef3f489bae2110bd946119ffa7d04df32faf4baaf9e48531f078e2f0aa21a9ed5a
            1cbad97052aa1ffb7a9296a5939b8512b3709c3e51dc811368f79601bde51f0800000000000000
            0000000000000000002c6a4c2952534b424c4f434b3a084da00e0d028fec46b4f197ac1bb3b310
            564c47b5b2cf313eb62b220024824e0000000000000000266a24b9e11b6d80c104eb7aa0d89d10
            11637e6dfae9ce704a6bf915093a9750d943b30d35dc32f6026342
            """), 2392654)

    def assertValidPoW(self, raw_block_header, expected_block_number):
        block_header = RskBlockHeader(raw_block_header, self.netparams)
        self.assertEqual(block_header.number, expected_block_number)
        self.assertTrue(block_header.pow_is_valid())
