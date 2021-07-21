import json
import logging
from pyee import BaseEventEmitter
from comm.utils import is_hex_string_of_length, normalize_hex_string, \
                   assert_int, assert_bool, assert_dict, assert_hex_hash

class BlockchainState:
    # Error codes for the advance operation
    ADVANCE_OK = 0
    ADVANCE_OK_PARTIAL = 1
    ADVANCE_CHAINING_MISMATCH = -201
    ADVANCE_POW_INVALID = -202

    UPDATE_ANCESTOR_OK = ADVANCE_OK
    UPDATE_ANCESTOR_CHAINING_MISMATCH = ADVANCE_CHAINING_MISMATCH
    UPDATE_ANCESTOR_TIP_MISMATCH = -203

    CHANGED_EVENT = 'changed'

    @staticmethod
    def from_jsonfile(path):
        try:
            with open(path, 'r') as file:
                state = json.loads(file.read())

            if type(state) != dict:
                raise ValueError("JSON file must contain an object as a top level element")

            return BlockchainState(state)
        except (ValueError, json.JSONDecodeError) as e:
            raise ValueError("Unable to read state from '%s': %s" % (path, str(e)))

    # hash must be a hexadecimal value representing 32 bytes
    @staticmethod
    def checkpoint(hash):
        if not is_hex_string_of_length(hash, 32, allow_prefix=True):
            raise ValueError("Invalid checkpoint state hash: %s" % str(hash))

        hash = normalize_hex_string(hash)

        return BlockchainState({
            "best_block": hash,
            "newest_valid_block": hash,
            "ancestor_block": "00"*32,
            "ancestor_receipts_root": "00"*32,
            "updating": _UpdatingState.pristine().to_dict()
        })

    def __init__(self, state):
        self.logger = logging.getLogger("blockchain")
        self.event_emitter = BaseEventEmitter()

        assert_hex_hash(state, "best_block")
        assert_hex_hash(state, "newest_valid_block")
        assert_hex_hash(state, "ancestor_block")
        assert_hex_hash(state, "ancestor_receipts_root")
        assert_dict(state, "updating")

        self.best_block = state["best_block"]
        self.newest_valid_block = state["newest_valid_block"]
        self.ancestor_block = state["ancestor_block"]
        self.ancestor_receipts_root = state["ancestor_receipts_root"]
        self.updating = _UpdatingState(state["updating"])

        # The minimum cumulative difficulty for advancing the best block
        self.minimum_cumulative_difficulty = None

    def on_change(self, handler):
        self.logger.debug("On change handler attached")
        self.event_emitter.on(self.CHANGED_EVENT, handler)

    def _do_change(self):
        self.logger.debug("State changed, emitting change event")
        self.event_emitter.emit(self.CHANGED_EVENT)

    def reset_advance(self):
        self.updating = _UpdatingState.pristine()
        self._do_change()

    # Attempts to advance the state by processing the given blocks
    # blocks must be a list of simulator.rsk.RskBlockHeader objects
    def advance(self, blocks):
        if self.minimum_cumulative_difficulty is None:
            message = "Minimum cumulative difficulty not set"
            self.logger.error(message)
            raise RuntimeError(message)

        if len(blocks) == 0:
            message = "No blocks given, expecting at least one block"
            self.logger.error(message)
            raise RuntimeError(message)

        # Blocks come in newest to oldest order (the first element is the newest)
        # The first block must match the next expected block
        if self.updating.in_progress and blocks[0].hash != self.updating.next_expected_block:
            self.logger.error("Next expected block hash (%s) doesn't match first block hash (%s)" % \
                             (self.updating.next_expected_block, blocks[0].hash))
            self.reset_advance()
            return self.ADVANCE_CHAINING_MISMATCH

        # Start a new update if an update process is not already ongoing
        # and record the first block as the candidate newest
        if not self.updating.in_progress:
            self.updating.in_progress = True
            self.updating.newest_valid_block = blocks[0].hash
            self.logger.debug("Starting a new update process, candidate newest block is %s",
                             self.updating.newest_valid_block)

        # Run through the given blocks
        for i in range(len(blocks)):
            block = blocks[i]

            # Verify chaining
            if i < len(blocks)-1 and block.parent_hash != blocks[i+1].hash:
                self.logger.error("Chaining mismatch: block %s has parent %s and next block on list is %s" % \
                                 (block.hash, block.parent_hash, blocks[i+1].hash))
                self.reset_advance()
                return self.ADVANCE_CHAINING_MISMATCH

            # If we reach the newest valid block we know, then
            # moving forward we don't need to validate PoW
            # (it would have been validated on a previous advance
            # operation)
            if block.hash == self.newest_valid_block:
                self.updating.already_validated = True

            # Validate block's PoW only if we need to
            # (i.e., if we haven't already in the past)
            if not self.updating.already_validated:
                # PoW
                if not block.pow_is_valid():
                    self.logger.error("PoW invalid for block %s (at index %d)" % (block.hash, i))
                    self.reset_advance()
                    return self.ADVANCE_POW_INVALID

            if not self.updating.found_best_block:
                # Accumulate difficulty
                self.updating.total_difficulty += block.difficulty
                self.logger.debug("Cumulative difficulty is now %d", self.updating.total_difficulty)

                # Enough accumulated difficulty? Mark the new candidate best
                if self.updating.total_difficulty >= self.minimum_cumulative_difficulty:
                    self.updating.found_best_block = True
                    self.updating.best_block = block.hash
                    self.logger.debug("Candidate best block found: %s", self.updating.best_block)

            # Have we reached the current best block with a valid chain?
            # Update the best confirmed block and newest valid block in the HSM state
            if self.updating.found_best_block and block.parent_hash == self.best_block:
                self.best_block = self.updating.best_block
                self.newest_valid_block = self.updating.newest_valid_block
                # Success!
                self.logger.info("Advance success: new best block is now %s, newest valid block is %s",
                                self.best_block, self.newest_valid_block)
                self.reset_advance()
                return self.ADVANCE_OK

        # If we get to this point, then we haven't yet reached the current best block.
        # Update the oldest block within the process and ask for more blocks.
        self.updating.next_expected_block = blocks[-1].parent_hash
        self.logger.info("Partial advance success: next expected block is %s",
                         self.updating.next_expected_block)

        # Success, but we need more blocks
        self._do_change() # Signal state change
        return self.ADVANCE_OK_PARTIAL

    # Attempts to update the current ancestor block by processing the given blocks
    # blocks must be a list of simulator.rsk.RskBlockHeader objects
    def update_ancestor(self, blocks):
        if len(blocks) < 1:
            message = "Expected at least 1 block, got zero"
            self.logger.error(message)
            raise RuntimeError(message)

        tip = blocks[0].hash

        if tip not in [self.ancestor_block, self.best_block]:
            self.logger.error("Tip mismatch. Expected %s or %s but got %s",
                              self.ancestor_block, self.best_block, tip)
            return self.UPDATE_ANCESTOR_TIP_MISMATCH

        for i in range(len(blocks)-1):
            if blocks[i].parent_hash != blocks[i+1].hash:
                self.logger.error("Chaining mismatch. Expected %s but got %s",
                                  blocks[i].parent_hash, blocks[i+1].hash)
                return self.UPDATE_ANCESTOR_CHAINING_MISMATCH

        self.ancestor_block = blocks[-1].hash
        self.ancestor_receipts_root = blocks[-1].receipts_trie_root
        self.logger.info("Ancestor block updated to %s, receipts trie root updated to %s", \
                         self.ancestor_block, self.ancestor_receipts_root)

        # Success
        self._do_change() # Signal state change
        return self.UPDATE_ANCESTOR_OK

    # Given a block (instance of RskBlockHeader),
    # this function returns True iif the given block is either
    # the current best block or the current ancestor block
    def in_blockchain(self, block):
        hash = block.hash
        self.logger.debug("Verifying inclusion of block %s. Best block: %s; ancestor block: %s",
                          hash, self.best_block, self.ancestor_block)
        return hash in [self.best_block, self.ancestor_block]

    def to_dict(self):
        return {
            "best_block": self.best_block,
            "newest_valid_block": self.newest_valid_block,
            "ancestor_block": self.ancestor_block,
            "ancestor_receipts_root": self.ancestor_receipts_root,
            "updating": self.updating.to_dict()
        }

    def save_to_jsonfile(self, path):
        with open(path, 'w') as file:
            file.write('%s\n' % json.dumps(self.to_dict(), indent=2))
        self.logger.info("State saved to %s", path)

def load_or_create_blockchain_state(statefile_path, checkpoint, logger):
    try:
        logger.info("Loading blockchain state '%s'", statefile_path)
        logger.info("Using checkpoint %s", checkpoint)
        state = BlockchainState.from_jsonfile(statefile_path)
    except (FileNotFoundError, ValueError):
        logger.info("State file not found or format incorrect. Creating with the default initial state")
        state = BlockchainState.checkpoint(checkpoint)
        state.save_to_jsonfile(statefile_path)
        logger.info("State created and saved to '%s'", statefile_path)
    except Exception as e:
        message = "Error initializing blockchain state: %s" % str(e)
        logger.error(message)
        raise RuntimeError(message)

    logger.info("State loaded: best block 0x%s", state.best_block)
    return state

class _UpdatingState:
    @staticmethod
    def pristine():
        return _UpdatingState({
            "in_progress": False,
            "already_validated": False,
            "found_best_block": False,
            "total_difficulty": 0,
            "next_expected_block": "00"*32,
            "best_block": "00"*32,
            "newest_valid_block": "00"*32,
        })

    def __init__(self, state):
        assert_bool(state, "in_progress")
        assert_bool(state, "already_validated")
        assert_bool(state, "found_best_block")
        assert_int(state, "total_difficulty")
        assert_hex_hash(state, "next_expected_block")
        assert_hex_hash(state, "best_block")
        assert_hex_hash(state, "newest_valid_block")

        self.in_progress = state["in_progress"]
        self.already_validated = state["already_validated"]
        self.next_expected_block = state["next_expected_block"]
        self.total_difficulty = state["total_difficulty"]
        self.found_best_block = state["found_best_block"]
        self.best_block = state["best_block"]
        self.newest_valid_block = state["newest_valid_block"]

    def to_dict(self):
        return {
            "in_progress": self.in_progress,
            "already_validated": self.already_validated,
            "next_expected_block": self.next_expected_block,
            "total_difficulty": self.total_difficulty,
            "found_best_block": self.found_best_block,
            "best_block": self.best_block,
            "newest_valid_block": self.newest_valid_block,
        }
