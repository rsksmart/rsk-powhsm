import os
from unittest import TestCase

from simulator.blockchain_state import BlockchainState
from simulator.rsk.block import RskBlockHeader
from simulator.rsk.netparams import NetworkParameters
from simulator.protocol import HSM2ProtocolSimulator

import logging

logging.disable(logging.CRITICAL)


class TestSync(TestCase):
    # Contains several consecutive blocks of mainnet data
    # One raw block per line, format: "n:hhhh"
    # with n being the block number and hhhh the raw block header
    # The block number is there for sanity check when parsing the raw data
    # and also readability in case of manual inspection
    DATA_FILE = os.path.join(os.path.dirname(__file__), "./blocks.data")
    # I.e., number of blocks considered "enough confirmations"
    DIFFICULTY_MULTIPLIER = 50

    def parse_line(self, line):
        data = line.split(":")
        number = int(data[0])
        raw = data[1][2:]

        return (number, raw)

    def get_blocks(self):
        datafile = open(self.DATA_FILE, "r")
        buffer = None
        previous_number = None
        blocks = []
        while buffer != "":
            if buffer is not None:
                number, raw = self.parse_line(buffer)
                if previous_number is not None:
                    # Minimum sanity check
                    self.assertEqual(previous_number, number + 1)
                previous_number = number
                blocks.append(raw)

            buffer = datafile.readline()
        datafile.close()
        return blocks

    def get_state(self):
        result = self.protocol.handle_request({
            "version": 2,
            "command": "blockchainState",
        })
        self.assertEqual(0, result["errorcode"])
        return result["state"]

    def setUp(self):
        self.netparams = NetworkParameters.MAINNET

        # Lookup the oldest block in the data,
        # set that as the initial state
        datafile = open(self.DATA_FILE, "r")
        buffer = None
        while buffer != "":
            line = buffer
            buffer = datafile.readline()
        datafile.close()

        # Parse into a header
        number, raw = self.parse_line(line)
        self.checkpoint_header = RskBlockHeader(raw, self.netparams)
        # Minimum sanity check
        self.assertEqual(number, self.checkpoint_header.number)

        self.minimum_cumulative_difficulty = (self.DIFFICULTY_MULTIPLIER *
                                              self.checkpoint_header.difficulty)
        self.blockchain_state = BlockchainState.checkpoint(self.checkpoint_header.hash)
        self.blockchain_state.minimum_cumulative_difficulty = (
            self.minimum_cumulative_difficulty)
        # We don't need the wallet or log emitter address for these tests
        self.protocol = HSM2ProtocolSimulator(
            wallet=None,
            blockchain_state=self.blockchain_state,
            log_emitter_address="00"*20,
            network_parameters=self.netparams,
            speed_bps=999_999_999_999,  # Very fast so we don't need to mock 'time.sleep'
        )

    def test_full_sync(self):
        blocks = self.get_blocks()[:-1]  # Skip the last one which is the checkpoint
        last_block = RskBlockHeader(blocks[0], self.netparams)

        total_difficulty = 0
        i = 0
        while total_difficulty < self.minimum_cumulative_difficulty and i < len(blocks):
            header = RskBlockHeader(blocks[i], self.netparams)
            total_difficulty += header.difficulty
            i += 1
        self.assertTrue(i < len(blocks))
        expected_best = RskBlockHeader(blocks[i - 1], self.netparams)

        result = self.protocol.handle_request({
            "version": 2,
            "command": "advanceBlockchain",
            "blocks": blocks,
        })
        self.assertEqual({"errorcode": 0}, result)
        state = self.get_state()
        self.assertEqual(expected_best.hash, state["best_block"])
        self.assertEqual(last_block.hash, state["newest_valid_block"])

    def test_incremental_sync(self):
        blocks = self.get_blocks()[:-1]  # Skip the last one which is the checkpoint
        last_block = RskBlockHeader(blocks[0], self.netparams)

        total_difficulty = 0
        i = 0
        while total_difficulty < self.minimum_cumulative_difficulty and i < len(blocks):
            header = RskBlockHeader(blocks[i], self.netparams)
            total_difficulty += header.difficulty
            i += 1
        self.assertTrue(i < len(blocks))
        expected_best_index = i - 1
        expected_best = RskBlockHeader(blocks[expected_best_index], self.netparams)

        CHUNKS = 6
        chunk_size = len(blocks)//CHUNKS

        state = self.get_state()
        self.assertFalse(state["updating"]["in_progress"])
        self.assertFalse(state["updating"]["already_validated"])
        self.assertFalse(state["updating"]["found_best_block"])
        sent_best_block = False
        for i in range(CHUNKS):
            is_last_chunk = i == CHUNKS - 1
            start = i*chunk_size
            end = None if is_last_chunk else (i + 1)*chunk_size
            chunk = blocks[start:end]
            result = self.protocol.handle_request({
                "version": 2,
                "command": "advanceBlockchain",
                "blocks": chunk,
            })
            state = self.get_state()

            # Final state assertions
            if is_last_chunk:
                self.assertEqual({"errorcode": 0}, result)
                self.assertEqual(expected_best.hash, state["best_block"])
                self.assertEqual(last_block.hash, state["newest_valid_block"])
            else:
                self.assertEqual({"errorcode": 1}, result)
                self.assertEqual(self.checkpoint_header.hash, state["best_block"])
                self.assertEqual(self.checkpoint_header.hash, state["newest_valid_block"])
            self.assertEqual("00"*32, state["ancestor_block"])

            # Everything pertaining the midstate
            self.assertEqual(state["updating"]["in_progress"], not is_last_chunk)
            self.assertFalse(state["updating"]["already_validated"])
            sent_best_block = (sent_best_block or end is None
                               or expected_best_index in range(start, end))
            if not is_last_chunk:
                self.assertEqual(state["updating"]["found_best_block"], sent_best_block)
                if sent_best_block:
                    self.assertEqual(state["updating"]["best_block"], expected_best.hash)
                self.assertEqual(state["updating"]["newest_valid_block"], last_block.hash)
                self.assertEqual(
                    state["updating"]["next_expected_block"],
                    RskBlockHeader(chunk[-1], self.netparams).parent_hash,
                )
            else:
                self.assertFalse(state["updating"]["found_best_block"])

    def test_update_ancestor_block(self):
        # First do a full sync
        blocks = self.get_blocks()[:-1]  # Skip the last one which is the checkpoint
        result = self.protocol.handle_request({
            "version": 2,
            "command": "advanceBlockchain",
            "blocks": blocks,
        })
        self.assertEqual({"errorcode": 0}, result)

        newest_valid_block = self.blockchain_state.newest_valid_block
        best_block = self.blockchain_state.best_block
        best_block_index = None
        i = 0
        while best_block_index is None:
            block = RskBlockHeader(blocks[i], self.netparams)
            if block.hash == best_block:
                best_block_index = i
            i += 1

        ANCESTOR_STEP = 10
        ANCESTOR_TESTS = 20

        state = self.get_state()
        self.assertEqual(state["ancestor_block"], "00"*32)
        self.assertEqual(state["best_block"], best_block)
        self.assertEqual(state["newest_valid_block"], newest_valid_block)

        start = best_block_index
        for i in range(ANCESTOR_TESTS):
            end = start + ANCESTOR_STEP
            bs = blocks[start:end]
            expected_ancestor = RskBlockHeader(bs[-1], self.netparams).hash
            result = self.protocol.handle_request({
                "version": 2,
                "command": "updateAncestorBlock",
                "blocks": bs,
            })
            self.assertEqual({"errorcode": 0}, result)
            state = self.get_state()
            self.assertEqual(state["ancestor_block"], expected_ancestor)
            self.assertEqual(state["best_block"], best_block)
            self.assertEqual(state["newest_valid_block"], newest_valid_block)

            start = end - 1
