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

import sha3
import rlp
from rsk_utils import rlp_decode_list_of_expected_length
from comm.utils import bitwise_and_bytes
from rsk_netparams import NetworkUpgrades
import comm.pow as pow
import comm.bitcoin
import logging


class RskBlockHeader:
    __UMM_ROOT_LENGTH = 20
    __HASH_FOR_MM_SIZE = 32
    __HASH_FOR_MM_PREFIX_SIZE = 20
    __HASH_FOR_MM_SUFFIX_SIZE = 4
    __MAX_MERKLE_PROOF_SIZE = 960  # From Iris onwards

    def __init__(self, raw_hex_string, network_parameters, mm_is_mandatory=True):
        self.logger = logging.getLogger("rskblockheader")
        self.__network_parameters = network_parameters
        self.__raw = bytes.fromhex(raw_hex_string)
        self.__decode(mm_is_mandatory)

    def __decodingerror(self, message):
        self.logger.debug(message)
        raise ValueError(message)

    def __decode(self, mm_is_mandatory):
        # An RSK block header is encoded in RLP.
        # The top-level list must have 19 or 20 elements (depending on
        # whether UMM is active for the block number), of which:
        # - Its 1st element corresponds to the parent hash
        # - Its 6th element corresponds to the receipts trie root
        # - Its 8th element corresponds to the block difficulty
        #   (big-endian two's complement integer)
        # - Its 9th element corresponds to the block number (big-endian unsigned integer)
        # - If UMM IS NOT active:
        #   - Its 17th element corresponds to the BTC merged mining header
        #   - Its 18th element corresponds to the merged mining merkle proof
        #   - Its 19th element corresponds to the BTC merged mining coinbase transaction
        # - If UMM IS active:
        #   - Its 17th element corresponds to the UMM root
        #   - Its 18th element corresponds to the BTC merged mining header
        #   - Its 19th element corresponds to the merged mining merkle proof
        #   - Its 20th element corresponds to the BTC merged mining coinbase transaction
        self.logger.debug("Decoding from %s", self.__raw.hex())

        rlp_items = rlp_decode_list_of_expected_length(self.__raw, [17, 18, 19, 20],
                                                       "block header")

        # If merge mining is mandatory, then we fail in case
        # we don't have the merged mining merkle proof and merged mining
        # coinbase transaction
        self.__has_merged_mining_fields = len(rlp_items) in [19, 20]
        if mm_is_mandatory and not self.__has_merged_mining_fields:
            self.__decodingerror("Expected merged mining fields are not present")

        # Fill in for potentially missing merged mining fields
        if not self.__has_merged_mining_fields:
            rlp_items = rlp_items + [b"", b""]

        if type(rlp_items[0]) != bytes or len(rlp_items[0]) != 32:
            self.__decodingerror("Expected a 32-byte hash as 1st element (parent hash), "
                                 "instead got '%s'" % str(rlp_items[0]))

        if type(rlp_items[5]) != bytes or len(rlp_items[5]) != 32:
            self.__decodingerror("Expected a 32-byte hash as 6th element (receipts "
                                 "trie root), instead got '%s'" % str(rlp_items[5]))

        self.__parent_hash = rlp_items[0].hex()
        self.__receipts_trie_root = rlp_items[5].hex()
        self.__difficulty = int.from_bytes(rlp_items[7], byteorder="big", signed=True)
        self.__number = int.from_bytes(rlp_items[8], byteorder="big", signed=False)

        if self.__difficulty < 0:
            self.__decodingerror("Expected a nonnegative integer as the 8th element "
                                 "(difficulty), instead got %d (0x%s)" %
                                 (self.__difficulty, rlp_items[7].hex()))

        # Blocks previous to the wasabi network upgrade are disallowed
        if not self.network_parameters.network_upgrades.is_active(
                NetworkUpgrades.wasabi, self.number):
            message = "Blocks before wasabi (#%d) are disallowed. Got #%d." % (
                self.network_parameters.network_upgrades.get(NetworkUpgrades.wasabi),
                self.number,
            )
            self.logger.info(message)
            raise ValueError(message)

        # UMM-dependent fields
        expected_nfields = 19
        umm_root_index = None
        mm_header_index = 16
        mm_merkleproof_index = 17
        mm_coinbasetx_index = 18
        umm_active = self.network_parameters.network_upgrades.is_active(
            NetworkUpgrades.papyrus, self.number)
        if umm_active:
            expected_nfields = 20
            umm_root_index = 16
            mm_header_index = 17
            mm_merkleproof_index = 18
            mm_coinbasetx_index = 19

        # Validate exact number of fields
        if len(rlp_items) != expected_nfields:
            self.__decodingerror(
                "%sUMM block header must have exactly %d fields, got %d" %
                ("" if umm_active else "Non ", expected_nfields, len(rlp_items)))

        # UMM root?
        self.__umm_root = None
        if umm_root_index is not None:
            self.__umm_root = rlp_items[umm_root_index]

            # Empty bytes => None
            if type(self.__umm_root) == bytes and len(self.__umm_root) == 0:
                self.__umm_root = None

            # Not empty => must be 20 bytes
            if self.__umm_root is not None:
                if (type(self.__umm_root) != bytes
                        or len(self.__umm_root) != self.__UMM_ROOT_LENGTH):
                    self.__decodingerror(
                        "UMM root must be either 0 bytes or %d bytes. Found '%s'" %
                        (self.__UMM_ROOT_LENGTH, self.__umm_root))

                self.__umm_root = self.__umm_root.hex()

        self.__mm_header = rlp_items[mm_header_index].hex()
        self.__mm_merkleproof = rlp_items[mm_merkleproof_index].hex()
        self.__mm_coinbasetx = rlp_items[mm_coinbasetx_index].hex()

        # Validate maximum length for merge mining merkle proof from Iris onwards
        if (self.__has_merged_mining_fields
                and self.network_parameters.network_upgrades.is_active(
                    NetworkUpgrades.iris, self.number) and
                len(bytes.fromhex(self.__mm_merkleproof)) > self.__MAX_MERKLE_PROOF_SIZE):
            message = "Maximum MM merkle proof size from Iris is %d. Got #%d." % (
                self.__MAX_MERKLE_PROOF_SIZE,
                len(bytes.fromhex(self.__mm_merkleproof)),
            )
            self.logger.info(message)
            raise ValueError(message)

        # *** Compute the block hash ***
        # The block hash is computed by hashing the RLP representation
        # of all the fields except for the merged mining merkle proof
        # and the merged mining coinbase transaction.
        # The fields to leave out are exactly the last two, regardless
        # of whether a UMM hash is present or not.
        self.__hash = sha3.keccak_256(rlp.encode(rlp_items[:-2])).digest().hex()

        # *** Compute the hash for merge mining and its comparison mask ***
        # *** IMPORTANT: this only applies if the merged mining fields are present ***
        if self.__has_merged_mining_fields:
            # These values will depend on whether a
            # UMM root (active from papyrus) is present.

            # The hash is the hash of all the fields except the
            # merge mining fields, but only the first 20 bytes are
            # considered. The last 4 bytes are the RSK block number encoded in big-endian.
            # The middle 8 bytes are to be ignored, thus the mask for the comparison.

            # After UMM, and if the UMM root is present, the first 20 bytes are computed
            # combining the first 20 bytes of the previous block hash with the UMM root.
            # The rest remains.

            # (1) Compute the hash leaving out merge mining fields.
            self.__hash_for_merge_mining = sha3.keccak_256(rlp.encode(
                rlp_items[:-3])).digest()

            # (2) Only the first 20 bytes of the original hash are to be taken
            # into account. Also, last 4 bytes must be the current block number
            # and also be taken into account.
            # Ignore the middle 8 bytes using a comparison mask.
            midhash_size = (self.__HASH_FOR_MM_SIZE - self.__HASH_FOR_MM_PREFIX_SIZE -
                            self.__HASH_FOR_MM_SUFFIX_SIZE)
            self.__hash_for_merge_mining = (
                self.__hash_for_merge_mining[:self.__HASH_FOR_MM_PREFIX_SIZE] +
                b"\x00"*midhash_size + self.number.to_bytes(
                    self.__HASH_FOR_MM_SUFFIX_SIZE, byteorder="big", signed=False))

            self.__hash_for_merge_mining_mask = (b"\xff"*self.__HASH_FOR_MM_PREFIX_SIZE +
                                                 b"\x00"*midhash_size +
                                                 b"\xff"*self.__HASH_FOR_MM_SUFFIX_SIZE)

            # (3) Depending on UMM, include the UMM root in the calculation
            # and trim to 20 bytes
            if self.is_umm:
                self.__hash_for_merge_mining = (
                    sha3.keccak_256(
                        self.__hash_for_merge_mining[:self.__HASH_FOR_MM_PREFIX_SIZE] +
                        bytes.fromhex(self.__umm_root)).digest()
                    [:self.__HASH_FOR_MM_PREFIX_SIZE] +
                    self.__hash_for_merge_mining[self.__HASH_FOR_MM_PREFIX_SIZE:])

            # (4) We represent everything in hex strings internally
            self.__hash_for_merge_mining = self.__hash_for_merge_mining.hex()
            self.__hash_for_merge_mining_mask = self.__hash_for_merge_mining_mask.hex()

            # (5) Apply the merge mining mask
            self.__hash_for_merge_mining = self.__apply_merge_mining_mask(
                self.__hash_for_merge_mining)

    @property
    def network_parameters(self):
        return self.__network_parameters

    @property
    def parent_hash(self):
        return self.__parent_hash

    @property
    def difficulty(self):
        return self.__difficulty

    @property
    def number(self):
        return self.__number

    @property
    def receipts_trie_root(self):
        return self.__receipts_trie_root

    @property
    def is_umm(self):
        return self.umm_root is not None

    @property
    def umm_root(self):
        return self.__umm_root

    @property
    def mm_header(self):
        return self.__mm_header

    @property
    def mm_merkleproof(self):
        if not self.__has_merged_mining_fields:
            return None

        return self.__mm_merkleproof

    @property
    def mm_coinbasetx(self):
        if not self.__has_merged_mining_fields:
            return None

        return self.__mm_coinbasetx

    @property
    def hash(self):
        return self.__hash

    @property
    def hash_for_merge_mining(self):
        if not self.__has_merged_mining_fields:
            return None

        return self.__hash_for_merge_mining

    @property
    def hash_for_merge_mining_mask(self):
        if not self.__has_merged_mining_fields:
            return None

        return self.__hash_for_merge_mining_mask

    # Whether the given hash matches the RSK block's hash for merge mining,
    # applying the corresponding mask.
    # *** IMPORTANT ***: hash must be a string in hex format
    def hash_for_merge_mining_matches(self, hash):
        if not self.__has_merged_mining_fields:
            return False

        return self.__hash_for_merge_mining == self.__apply_merge_mining_mask(hash)

    # Whether this block's PoW is valid
    # *** IMPORTANT ***: This method only works if merged mining fields
    # were present when creating the instance. Otherwise it will return False.
    def pow_is_valid(self):
        if not self.__has_merged_mining_fields:
            return False

        # To verify Proof Of Work for this block, one must:
        # 1. Compute the merge mining block header hash
        # 2. Check that the hash in (1) matches the block difficulty
        # 3. Extract the merge mining hash from the merge mining coinbase tx
        # 4. Check that it matches the hash for merge mining of the block
        # 5. Compute the merge mining coinbase tx hash
        # 6. Extract the merkle root from the merge mining block header
        # 7. Check that the merge mining merkle proof for the (5, 6) is valid
        try:
            # Steps 1 & 2
            mm_block_hash_int = comm.bitcoin.get_block_hash_as_int(self.mm_header)
            mm_target = pow.difficulty_to_target(self.difficulty)
            if mm_block_hash_int > mm_target:
                bh_hex = mm_block_hash_int.to_bytes(32, byteorder="big",
                                                    signed=False).hex()
                tgt_hex = mm_target.to_bytes(32, byteorder="big", signed=False).hex()
                self.logger.info("Hash %s is higher than target %s", bh_hex, tgt_hex)
                return False

            # Steps 3 & 4
            mm_hash = pow.coinbase_tx_extract_merge_mining_hash(self.mm_coinbasetx)
            if not self.hash_for_merge_mining_matches(mm_hash):
                self.logger.info(
                    "Merge mining hash mismatch. Coinbase TX has %s, "
                    "block is %s (mask %s)",
                    mm_hash,
                    self.hash_for_merge_mining,
                    self.hash_for_merge_mining_mask,
                )
                return False

            # Steps 5, 6 & 7
            cb_tx_hash = pow.coinbase_tx_get_hash(self.mm_coinbasetx)
            merkle_root = comm.bitcoin.get_merkle_root(self.mm_header)
            if not pow.is_valid_merkle_proof(self.mm_merkleproof, merkle_root,
                                             cb_tx_hash):
                self.logger.info(
                    "Invalid merkle proof of coinbase tx %s with root %s",
                    cb_tx_hash,
                    merkle_root,
                )
                return False

            # If we get here, then PoW is valid
            return True
        except ValueError as e:
            self.logger.info("PoW deemed invalid: %s", str(e))
            return False

    def __apply_merge_mining_mask(self, hash):
        return bitwise_and_bytes(bytes.fromhex(self.__hash_for_merge_mining_mask),
                                 bytes.fromhex(hash)).hex()

    def __str__(self):
        return "<RskBlockHeader mm_hash=0x%s>" % self.hash_for_merge_mining

    def __repr__(self):
        return str(self)
