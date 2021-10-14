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

import json
from unittest import TestCase
from unittest.mock import Mock, MagicMock, call, patch

import simulator.blockchain_state

import logging

logging.disable(logging.CRITICAL)


class TestBlockchainState(TestCase):
    def setUp(self):
        self.params = {
            "best_block": "11"*32,
            "newest_valid_block": "22"*32,
            "ancestor_block": "33"*32,
            "ancestor_receipts_root": "3344"*16,
            "updating": {
                "in_progress": True,
                "already_validated": True,
                "found_best_block": True,
                "total_difficulty": 1234,
                "best_block": "44"*32,
                "newest_valid_block": "55"*32,
                "next_expected_block": "66"*32,
            },
        }

    def test_construction_ok(self):
        state = simulator.blockchain_state.BlockchainState(self.params)

        self.assertEqual(state.best_block, "11"*32)
        self.assertEqual(state.newest_valid_block, "22"*32)
        self.assertEqual(state.ancestor_block, "33"*32)
        self.assertEqual(state.ancestor_receipts_root, "3344"*16)
        self.assertEqual(state.updating.in_progress, True)
        self.assertEqual(state.updating.already_validated, True)
        self.assertEqual(state.updating.found_best_block, True)
        self.assertEqual(state.updating.total_difficulty, 1234)
        self.assertEqual(state.updating.best_block, "44"*32)
        self.assertEqual(state.updating.newest_valid_block, "55"*32)
        self.assertEqual(state.updating.next_expected_block, "66"*32)

    def test_to_dict(self):
        state = simulator.blockchain_state.BlockchainState(self.params)

        self.assertEqual(state.to_dict(), self.params)

    def test_invalid_hashes(self):
        for key in ["best_block", "newest_valid_block", "ancestor_block"]:
            self.setUp()
            for value in ["jj"*32, None, 555, "aa"]:
                with self.assertRaises(ValueError):
                    self.params[key] = value
                    simulator.blockchain_state.BlockchainState(self.params)

    def test_invalid_updating(self):
        with self.assertRaises(ValueError):
            self.params["updating"] = "somethingelse"
            simulator.blockchain_state.BlockchainState(self.params)

    def test_invalid_updating_values(self):
        for key in [
                "best_block",
                "newest_valid_block",
                "next_expected_block",
                "in_progress",
                "already_validated",
                "found_best_block",
        ]:
            self.setUp()
            for value in ["jj"*32, None, 555, "aa"]:
                with self.assertRaises(ValueError):
                    self.params["updating"][key] = value
                    simulator.blockchain_state.BlockchainState(self.params)

        self.setUp()
        for value in ["jj"*32, None, "bb"*32, "aa"]:
            with self.assertRaises(ValueError):
                self.params["updating"]["total_difficulty"] = value
                simulator.blockchain_state.BlockchainState(self.params)

    def test_checkpoint_ok(self):
        state = simulator.blockchain_state.BlockchainState.checkpoint("11"*32)

        self.assertEqual(state.best_block, "11"*32)
        self.assertEqual(state.newest_valid_block, "11"*32)
        self.assertEqual(state.ancestor_block, "00"*32)
        self.assertEqual(state.ancestor_receipts_root, "00"*32)
        self.assertEqual(state.updating.in_progress, False)
        self.assertEqual(state.updating.already_validated, False)
        self.assertEqual(state.updating.found_best_block, False)
        self.assertEqual(state.updating.total_difficulty, 0)
        self.assertEqual(state.updating.best_block, "00"*32)
        self.assertEqual(state.updating.newest_valid_block, "00"*32)
        self.assertEqual(state.updating.next_expected_block, "00"*32)

    def test_checkpoint_error(self):
        with self.assertRaises(ValueError):
            simulator.blockchain_state.BlockchainState.checkpoint(123)

        with self.assertRaises(ValueError):
            simulator.blockchain_state.BlockchainState.checkpoint("11"*31)

        with self.assertRaises(ValueError):
            simulator.blockchain_state.BlockchainState.checkpoint("11"*33)

        with self.assertRaises(ValueError):
            simulator.blockchain_state.BlockchainState.checkpoint("somethingelse")

        with self.assertRaises(ValueError):
            simulator.blockchain_state.BlockchainState.checkpoint("zz"*32)

    @patch("simulator.blockchain_state.open")
    def test_save(self, mock_open):
        mock_file = MagicMock()
        mock_open.return_value = mock_file

        state = simulator.blockchain_state.BlockchainState(self.params)
        state.save_to_jsonfile("a-path-somewhere")

        self.assertEqual(mock_open.call_args_list, [call("a-path-somewhere", "w")])
        self.assertEqual(1, len(mock_file.__enter__().write.call_args_list))
        self.assertTrue(mock_file.__exit__.called)

        uniq_call = mock_file.__enter__().write.call_args_list[0]

        self.assertEqual(1, len(uniq_call[0]))
        self.assertEqual(0, len(uniq_call[1]))
        generated_json = uniq_call[0][0]
        self.assertEqual(json.loads(generated_json), self.params)

    @patch("simulator.blockchain_state.open")
    def test_save_filenotfound(self, mock_open):
        mock_open.side_effect = FileNotFoundError()

        state = simulator.blockchain_state.BlockchainState(self.params)

        with self.assertRaises(FileNotFoundError):
            state.save_to_jsonfile("a-path-somewhere")

        self.assertEqual(mock_open.call_args_list, [call("a-path-somewhere", "w")])

    @patch("simulator.blockchain_state.open")
    def test_from_jsonfile(self, mock_open):
        mock_file = MagicMock()
        mock_open.return_value = mock_file
        mock_file.__enter__().read.return_value = json.dumps(self.params)

        state = simulator.blockchain_state.BlockchainState.from_jsonfile(
            "a-path-to-a-json-file")

        self.assertEqual(state.to_dict(), self.params)
        self.assertEqual(mock_open.call_args_list, [call("a-path-to-a-json-file", "r")])
        self.assertEqual(mock_file.__enter__().read.call_args_list, [call()])
        self.assertTrue(mock_file.__exit__.called)

    @patch("simulator.blockchain_state.open")
    def test_from_jsonfile_filenotfound(self, mock_open):
        mock_open.side_effect = FileNotFoundError()

        with self.assertRaises(FileNotFoundError):
            simulator.blockchain_state.BlockchainState.from_jsonfile(
                "a-path-to-a-json-file")

        self.assertEqual(mock_open.call_args_list, [call("a-path-to-a-json-file", "r")])

    @patch("simulator.blockchain_state.open")
    def test_from_jsonfile_invalidjson(self, mock_open):
        mock_file = MagicMock()
        mock_open.return_value = mock_file
        mock_file.__enter__().read.return_value = "im-not-json\n"

        with self.assertRaises(ValueError):
            simulator.blockchain_state.BlockchainState.from_jsonfile(
                "a-path-to-a-json-file")

        self.assertEqual(mock_open.call_args_list, [call("a-path-to-a-json-file", "r")])
        self.assertEqual(mock_file.__enter__().read.call_args_list, [call()])
        self.assertTrue(mock_file.__exit__.called)

    @patch("simulator.blockchain_state.open")
    def test_from_jsonfile_bestblock_invalid(self, mock_open):
        mock_file = MagicMock()
        mock_open.return_value = mock_file
        mock_file.__enter__().read.return_value = json.dumps({
            "best_block":
            "invalid",
            "best_block_number":
            555,
            "newest_valid_block":
            "33"*32,
        })

        with self.assertRaises(ValueError):
            simulator.blockchain_state.BlockchainState.from_jsonfile(
                "a-path-to-a-json-file")

        self.assertEqual(mock_open.call_args_list, [call("a-path-to-a-json-file", "r")])
        self.assertEqual(mock_file.__enter__().read.call_args_list, [call()])
        self.assertTrue(mock_file.__exit__.called)

    @patch("simulator.blockchain_state.open")
    def test_from_jsonfile_newestvalidblock_invalid(self, mock_open):
        mock_file = MagicMock()
        mock_open.return_value = mock_file
        mock_file.__enter__().read.return_value = json.dumps({
            "best_block":
            "11"*32,
            "best_block_number":
            555,
            "newest_valid_block":
            "invalid",
        })

        with self.assertRaises(ValueError):
            simulator.blockchain_state.BlockchainState.from_jsonfile(
                "a-path-to-a-json-file")

        self.assertEqual(mock_open.call_args_list, [call("a-path-to-a-json-file", "r")])
        self.assertEqual(mock_file.__enter__().read.call_args_list, [call()])
        self.assertTrue(mock_file.__exit__.called)

    @patch("simulator.blockchain_state.open")
    def test_from_jsonfile_bestblocknumber_invalid(self, mock_open):
        mock_file = MagicMock()
        mock_open.return_value = mock_file
        mock_file.__enter__().read.return_value = json.dumps({
            "best_block":
            "11"*32,
            "best_block_number":
            "not-a-number",
            "newest_valid_block":
            "33"*32,
        })

        with self.assertRaises(ValueError):
            simulator.blockchain_state.BlockchainState.from_jsonfile(
                "a-path-to-a-json-file")

        self.assertEqual(mock_open.call_args_list, [call("a-path-to-a-json-file", "r")])
        self.assertEqual(mock_file.__enter__().read.call_args_list, [call()])
        self.assertTrue(mock_file.__exit__.called)

    def test_reset_advance(self):
        state = simulator.blockchain_state.BlockchainState(self.params)
        changed_handler = Mock()
        state.on_change(changed_handler)
        state.reset_advance()

        self.assertEqual(state.best_block, "11"*32)
        self.assertEqual(state.newest_valid_block, "22"*32)
        self.assertEqual(state.ancestor_block, "33"*32)
        self.assertEqual(state.updating.in_progress, False)
        self.assertEqual(state.updating.already_validated, False)
        self.assertEqual(state.updating.found_best_block, False)
        self.assertEqual(state.updating.total_difficulty, 0)
        self.assertEqual(state.updating.best_block, "00"*32)
        self.assertEqual(state.updating.newest_valid_block, "00"*32)
        self.assertEqual(state.updating.next_expected_block, "00"*32)
        self.assertTrue(changed_handler.called)

    def test_in_blockchain(self):
        state = simulator.blockchain_state.BlockchainState(self.params)
        self.assertFalse(state.in_blockchain(Mock(hash="aa"*32)))
        self.assertTrue(state.in_blockchain(Mock(hash="11"*32)))
        self.assertTrue(state.in_blockchain(Mock(hash="33"*32)))


class TestLoadOrCreateBlockchainState(TestCase):
    @patch("simulator.blockchain_state.BlockchainState")
    def test_file_exists(self, BlockchainStateMock):
        state = Mock()
        BlockchainStateMock.from_jsonfile.return_value = state

        self.assertEqual(
            simulator.blockchain_state.load_or_create_blockchain_state(
                "an-existing-path", "doesnt-matter", Mock()),
            state,
        )
        self.assertEqual(BlockchainStateMock.from_jsonfile.call_args_list,
                         [call("an-existing-path")])
        self.assertFalse(BlockchainStateMock.checkpoint.called)

    @patch("simulator.blockchain_state.BlockchainState")
    def test_file_does_not_exist(self, BlockchainStateMock):
        BlockchainStateMock.from_jsonfile.side_effect = FileNotFoundError()
        state = Mock()
        BlockchainStateMock.checkpoint.return_value = state

        self.assertEqual(
            simulator.blockchain_state.load_or_create_blockchain_state(
                "a-non-existing-path", "44"*32 + ":123", Mock()),
            state,
        )
        self.assertEqual(
            BlockchainStateMock.from_jsonfile.call_args_list,
            [call("a-non-existing-path")],
        )
        self.assertEqual(BlockchainStateMock.checkpoint.call_args_list,
                         [call("44"*32 + ":123")])


# Mock hash
def hs(n):
    return n.to_bytes(32, byteorder="big", signed=False).hex()


# Mock Block
def mb(hash, parent=None, number=None, difficulty=None, pow=True):
    parent = parent if parent is not None else hash - 1
    number = number if number is not None else hash
    difficulty = difficulty if difficulty is not None else hash
    result = Mock(
        hash=hs(hash),
        receipts_trie_root=hs(hash + 100),
        parent_hash=hs(parent),
        number=number,
        difficulty=difficulty,
    )
    result.pow_is_valid.return_value = pow
    return result


class TestBlockchainStateAdvance(TestCase):
    def setUp(self):
        self.params = {
            "best_block": hs(1),
            "newest_valid_block": hs(1),
            "ancestor_block": hs(1),
            "ancestor_receipts_root": hs(101),
            "updating": {
                "in_progress": False,
                "already_validated": False,
                "found_best_block": False,
                "total_difficulty": 0,
                "best_block": hs(0),
                "newest_valid_block": hs(0),
                "next_expected_block": hs(0),
            },
        }
        self.state = simulator.blockchain_state.BlockchainState(self.params)
        self.change_handler = Mock()
        self.state.on_change(self.change_handler)

    def test_minimum_cumulative_difficulty_must_be_set(self):
        with self.assertRaises(RuntimeError):
            self.state.advance("doesntmatter")
        self.assertFalse(self.change_handler.called)

    def test_empty_list(self):
        self.state.minimum_cumulative_difficulty = 1
        with self.assertRaises(RuntimeError):
            self.state.advance([])
        self.assertFalse(self.change_handler.called)

    def test_next_expected_block_mismatch(self):
        self.state.minimum_cumulative_difficulty = 1
        self.state.updating.in_progress = True
        self.state.updating.next_expected_block = hs(10)
        result = self.state.advance([mb(9)])
        self.assertEqual(result, -201)
        self.assertTrue(self.change_handler.called)

    def test_chaining_mismatch(self):
        self.state.best_block = hs(1)
        self.state.newest_valid_block = hs(1)
        self.state.ancestor_block = hs(123)
        self.state.minimum_cumulative_difficulty = 28
        bs = [
            mb(9),
            mb(8),
            mb(7),  # 7+8+9 = 24 < 28
            mb(6),  # 6+7+8+9 = 30 >= 28
            mb(5, 123),
            mb(4),
            mb(3),
            mb(2),
        ]
        result = self.state.advance(bs)
        self.assertEqual(result, -201)
        self.assertEqual(self.state.best_block, hs(1))
        self.assertEqual(self.state.newest_valid_block, hs(1))
        self.assertEqual(self.state.ancestor_block, hs(123))
        self.assertFalse(self.state.updating.in_progress)
        self.assertTrue(self.change_handler.called)

    def test_pow_invalid(self):
        self.state.best_block = hs(1)
        self.state.newest_valid_block = hs(1)
        self.state.ancestor_block = hs(123)
        self.state.minimum_cumulative_difficulty = 28
        bs = [
            mb(9),
            mb(8),
            mb(7),  # 7+8+9 = 24 < 28
            mb(6),  # 6+7+8+9 = 30 >= 28
            mb(5),
            mb(4, pow=False),
            mb(3),
            mb(2),
        ]
        result = self.state.advance(bs)
        self.assertEqual(result, -202)
        self.assertEqual(self.state.best_block, hs(1))
        self.assertEqual(self.state.newest_valid_block, hs(1))
        self.assertEqual(self.state.ancestor_block, hs(123))
        self.assertFalse(self.state.updating.in_progress)
        self.assertTrue(self.change_handler.called)

    def test_ok_pow_validated(self):
        self.state.best_block = hs(1)
        self.state.newest_valid_block = hs(1)
        self.state.ancestor_block = hs(123)
        self.state.minimum_cumulative_difficulty = 28
        bs = [
            mb(9),
            mb(8),
            mb(7),  # 7+8+9 = 24 < 28
            mb(6),  # 6+7+8+9 = 30 >= 28
            mb(5),
            mb(4),
            mb(3),
            mb(2),
        ]
        result = self.state.advance(bs)
        self.assertEqual(result, 0)
        self.assertEqual(self.state.best_block, hs(6))
        self.assertEqual(self.state.newest_valid_block, hs(9))
        self.assertEqual(self.state.ancestor_block, hs(123))
        self.assertFalse(self.state.updating.in_progress)
        for b in bs:
            self.assertEqual(b.number >= 2, b.pow_is_valid.called)
        self.assertTrue(self.change_handler.called)

    def test_ok_no_double_pow_validation(self):
        self.state.best_block = hs(1)
        self.state.newest_valid_block = hs(9)
        self.state.ancestor_block = hs(123)
        self.state.minimum_cumulative_difficulty = 28
        bs = [
            mb(12),
            mb(11),  # 11+12 = 23 < 28
            mb(10),  # 10+11+12 = 33 >= 28
            mb(9),
            mb(8),
            mb(7),
            mb(6),
            mb(5),
            mb(4),
            mb(3),
            mb(2),
        ]
        result = self.state.advance(bs)
        self.assertEqual(result, 0)
        self.assertEqual(self.state.best_block, hs(10))
        self.assertEqual(self.state.newest_valid_block, hs(12))
        self.assertEqual(self.state.ancestor_block, hs(123))
        self.assertFalse(self.state.updating.in_progress)
        for b in bs:
            self.assertEqual(b.number >= 10, b.pow_is_valid.called)
        self.assertTrue(self.change_handler.called)

    def test_extra_blocks_ok(self):
        self.state.best_block = hs(5)
        self.state.newest_valid_block = hs(8)
        self.state.ancestor_block = hs(123)
        self.state.minimum_cumulative_difficulty = 28
        bs = [
            mb(10),
            mb(9),
            mb(8),  # 27
            mb(7),  # 34
            mb(6),
            mb(5),
            mb(4),
        ]
        result = self.state.advance(bs)
        self.assertEqual(result, 0)
        self.assertEqual(self.state.best_block, hs(7))
        self.assertEqual(self.state.newest_valid_block, hs(10))
        self.assertEqual(self.state.ancestor_block, hs(123))
        self.assertFalse(self.state.updating.in_progress)
        for b in bs:
            self.assertEqual(b.number >= 9, b.pow_is_valid.called)
        self.assertTrue(self.change_handler.called)

    def test_ok_partial(self):
        self.state.best_block = hs(1)
        self.state.newest_valid_block = hs(3)
        self.state.ancestor_block = hs(123)
        self.state.minimum_cumulative_difficulty = 28
        bs = [
            mb(9),
            mb(8),
            mb(7),  # 7+8+9 = 24 < 28
            mb(6),  # 6+7+8+9 = 30 >= 28
            mb(5),
            mb(4),
        ]
        result = self.state.advance(bs)
        self.assertEqual(result, 1)
        self.assertEqual(self.state.best_block, hs(1))
        self.assertEqual(self.state.newest_valid_block, hs(3))
        self.assertEqual(self.state.ancestor_block, hs(123))
        self.assertTrue(self.state.updating.in_progress)
        self.assertTrue(self.state.updating.found_best_block)
        self.assertFalse(self.state.updating.already_validated)
        self.assertEqual(self.state.updating.best_block, hs(6))
        self.assertEqual(self.state.updating.newest_valid_block, hs(9))
        self.assertEqual(self.state.updating.next_expected_block, hs(3))
        self.assertEqual(self.state.updating.total_difficulty, 30)
        for b in bs:
            self.assertTrue(b.pow_is_valid.called)
        self.assertTrue(self.change_handler.called)

    def test_subsequent_ok(self):
        self.state.best_block = hs(1)
        self.state.newest_valid_block = hs(2)
        self.state.ancestor_block = hs(123)
        self.state.minimum_cumulative_difficulty = 28
        self.state.updating.in_progress = True
        self.state.updating.found_best_block = True
        self.state.updating.already_validated = False
        self.state.updating.best_block = hs(6)
        self.state.updating.newest_valid_block = hs(9)
        self.state.updating.next_expected_block = hs(3)
        self.state.updating.total_difficulty = 30
        bs = [
            mb(3),
            mb(2),
        ]
        result = self.state.advance(bs)
        self.assertEqual(result, 0)
        self.assertEqual(self.state.best_block, hs(6))
        self.assertEqual(self.state.newest_valid_block, hs(9))
        self.assertEqual(self.state.ancestor_block, hs(123))
        self.assertFalse(self.state.updating.in_progress)
        for b in bs:
            self.assertEqual(b.number > 2, b.pow_is_valid.called)
        self.assertTrue(self.change_handler.called)

    def test_subsequent_ok_extra_blocks(self):
        self.state.best_block = hs(1)
        self.state.newest_valid_block = hs(2)
        self.state.ancestor_block = hs(123)
        self.state.minimum_cumulative_difficulty = 28
        self.state.updating.in_progress = True
        self.state.updating.found_best_block = True
        self.state.updating.already_validated = False
        self.state.updating.best_block = hs(6)
        self.state.updating.newest_valid_block = hs(9)
        self.state.updating.next_expected_block = hs(3)
        self.state.updating.total_difficulty = 30
        bs = [
            mb(3),
            mb(2),
            mb(1, 100),
            mb(100, 90),
            mb(90, 80),
        ]
        result = self.state.advance(bs)
        self.assertEqual(result, 0)
        self.assertEqual(self.state.best_block, hs(6))
        self.assertEqual(self.state.newest_valid_block, hs(9))
        self.assertEqual(self.state.ancestor_block, hs(123))
        self.assertFalse(self.state.updating.in_progress)
        for b in bs:
            self.assertEqual(b.number == 3, b.pow_is_valid.called)
        self.assertTrue(self.change_handler.called)

    def test_subsequent_chaining_mismatch(self):
        self.state.best_block = hs(1)
        self.state.newest_valid_block = hs(2)
        self.state.ancestor_block = hs(123)
        self.state.minimum_cumulative_difficulty = 28
        self.state.updating.in_progress = True
        self.state.updating.found_best_block = True
        self.state.updating.already_validated = False
        self.state.updating.best_block = hs(6)
        self.state.updating.newest_valid_block = hs(9)
        self.state.updating.next_expected_block = hs(3)
        self.state.updating.total_difficulty = 30
        bs = [
            mb(3, 456),
            mb(2),
        ]
        result = self.state.advance(bs)
        self.assertEqual(result, -201)
        self.assertEqual(self.state.best_block, hs(1))
        self.assertEqual(self.state.newest_valid_block, hs(2))
        self.assertEqual(self.state.ancestor_block, hs(123))
        self.assertFalse(self.state.updating.in_progress)
        self.assertTrue(self.change_handler.called)

    def test_subsequent_pow_invalid(self):
        self.state.best_block = hs(1)
        self.state.newest_valid_block = hs(2)
        self.state.ancestor_block = hs(123)
        self.state.minimum_cumulative_difficulty = 28
        self.state.updating.in_progress = True
        self.state.updating.found_best_block = True
        self.state.updating.already_validated = False
        self.state.updating.best_block = hs(6)
        self.state.updating.newest_valid_block = hs(9)
        self.state.updating.next_expected_block = hs(3)
        self.state.updating.total_difficulty = 30
        bs = [
            mb(3, 100),
            mb(100, 90),
            mb(90, 80, pow=False),
            mb(80, 2),
            mb(2),
        ]
        result = self.state.advance(bs)
        self.assertEqual(result, -202)
        self.assertEqual(self.state.best_block, hs(1))
        self.assertEqual(self.state.newest_valid_block, hs(2))
        self.assertEqual(self.state.ancestor_block, hs(123))
        self.assertFalse(self.state.updating.in_progress)
        for b in bs:
            self.assertEqual(b.number in [3, 100, 90], b.pow_is_valid.called)
        self.assertTrue(self.change_handler.called)

    def test_ok_partial_no_double_pow(self):
        self.state.best_block = hs(1)
        self.state.newest_valid_block = hs(6)
        self.state.ancestor_block = hs(123)
        self.state.minimum_cumulative_difficulty = 28
        bs = [
            mb(9),
            mb(8),
            mb(7),  # 7+8+9 = 24 < 28
            mb(6),  # 6+7+8+9 = 30 >= 28
            mb(5),
            mb(4),
        ]
        result = self.state.advance(bs)
        self.assertEqual(result, 1)
        self.assertEqual(self.state.best_block, hs(1))
        self.assertEqual(self.state.newest_valid_block, hs(6))
        self.assertEqual(self.state.ancestor_block, hs(123))
        self.assertTrue(self.state.updating.in_progress)
        self.assertTrue(self.state.updating.found_best_block)
        self.assertTrue(self.state.updating.already_validated)
        self.assertEqual(self.state.updating.best_block, hs(6))
        self.assertEqual(self.state.updating.newest_valid_block, hs(9))
        self.assertEqual(self.state.updating.next_expected_block, hs(3))
        self.assertEqual(self.state.updating.total_difficulty, 30)
        for b in bs:
            self.assertEqual(b.number > 6, b.pow_is_valid.called)
        self.assertTrue(self.change_handler.called)

    def test_subsequent_ok_no_double_pow(self):
        self.state.best_block = hs(1)
        self.state.newest_valid_block = hs(6)
        self.state.ancestor_block = hs(123)
        self.state.minimum_cumulative_difficulty = 28
        self.state.updating.in_progress = True
        self.state.updating.found_best_block = True
        self.state.updating.already_validated = True
        self.state.updating.best_block = hs(6)
        self.state.updating.newest_valid_block = hs(9)
        self.state.updating.next_expected_block = hs(3)
        self.state.updating.total_difficulty = 30
        bs = [
            mb(3),
            mb(2),
        ]
        result = self.state.advance(bs)
        self.assertEqual(result, 0)
        self.assertEqual(self.state.best_block, hs(6))
        self.assertEqual(self.state.newest_valid_block, hs(9))
        self.assertEqual(self.state.ancestor_block, hs(123))
        self.assertFalse(self.state.updating.in_progress)
        for b in bs:
            self.assertFalse(b.pow_is_valid.called)
        self.assertTrue(self.change_handler.called)


class TestBlockchainStateUpdateAncestor(TestCase):
    def setUp(self):
        self.params = {
            "best_block": hs(1),
            "newest_valid_block": hs(1),
            "ancestor_block": hs(1),
            "ancestor_receipts_root": hs(2),
            "updating": {
                "in_progress": False,
                "already_validated": False,
                "found_best_block": False,
                "total_difficulty": 0,
                "best_block": hs(0),
                "newest_valid_block": hs(0),
                "next_expected_block": hs(0),
            },
        }
        self.state = simulator.blockchain_state.BlockchainState(self.params)
        self.change_handler = Mock()
        self.state.on_change(self.change_handler)

    def test_minimum_blocks(self):
        with self.assertRaises(RuntimeError):
            self.state.update_ancestor([])
        self.assertFalse(self.change_handler.called)

    def test_ok_from_best_block(self):
        self.state.best_block = hs(100)
        self.state.ancestor_block = hs(50)
        result = self.state.update_ancestor([
            mb(100),
            mb(99),
            mb(98),
            mb(97),
            mb(96),
            mb(95, 86),
            mb(86),
        ])
        self.assertEqual(result, 0)
        self.assertEqual(self.state.best_block, hs(100))
        self.assertEqual(self.state.ancestor_block, hs(86))
        self.assertEqual(self.state.ancestor_receipts_root, hs(186))
        self.assertTrue(self.change_handler.called)

    def test_ok_from_ancestor_block(self):
        self.state.best_block = hs(100)
        self.state.ancestor_block = hs(50)
        result = self.state.update_ancestor([
            mb(50),
            mb(49),
            mb(48),
            mb(47),
            mb(46),
            mb(45, 24),
            mb(24),
        ])
        self.assertEqual(result, 0)
        self.assertEqual(self.state.best_block, hs(100))
        self.assertEqual(self.state.ancestor_block, hs(24))
        self.assertEqual(self.state.ancestor_receipts_root, hs(124))
        self.assertTrue(self.change_handler.called)

    def test_ok_to_best_block(self):
        self.state.best_block = hs(100)
        self.state.ancestor_block = hs(50)
        result = self.state.update_ancestor([mb(100)])
        self.assertEqual(result, 0)
        self.assertEqual(self.state.best_block, hs(100))
        self.assertEqual(self.state.ancestor_block, hs(100))
        self.assertEqual(self.state.ancestor_receipts_root, hs(200))
        self.assertTrue(self.change_handler.called)

    def test_tip_mismatch(self):
        self.state.best_block = hs(100)
        self.state.ancestor_block = hs(50)
        result = self.state.update_ancestor([
            mb(99),
            mb(98),
            mb(97),
        ])
        self.assertEqual(result, -203)
        self.assertEqual(self.state.best_block, hs(100))
        self.assertEqual(self.state.ancestor_block, hs(50))
        self.assertFalse(self.change_handler.called)

    def test_chaining_mismatch_from_best_block(self):
        self.state.best_block = hs(100)
        self.state.ancestor_block = hs(50)
        result = self.state.update_ancestor([
            mb(100),
            mb(99),
            mb(98),
            mb(97),
            mb(23),
        ])
        self.assertEqual(result, -201)
        self.assertEqual(self.state.best_block, hs(100))
        self.assertEqual(self.state.ancestor_block, hs(50))
        self.assertFalse(self.change_handler.called)

    def test_chaining_mismatch_from_ancestor_block(self):
        self.state.best_block = hs(100)
        self.state.ancestor_block = hs(50)
        result = self.state.update_ancestor([
            mb(50),
            mb(49),
            mb(48),
            mb(47),
            mb(23),
        ])
        self.assertEqual(result, -201)
        self.assertEqual(self.state.best_block, hs(100))
        self.assertEqual(self.state.ancestor_block, hs(50))
        self.assertFalse(self.change_handler.called)
