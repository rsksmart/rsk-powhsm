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

import hashlib
import thirdparty.sha256
import logging

_logger = logging.getLogger("pow")

# Taken from rskj
# https://github.com/rsksmart/rskj/blob/32dbe675b2e22f1c804e2d1c8a76b37e2020f05b/rskj-core/src/main/java/co/rsk/util/DifficultyUtils.java#L32 # noqa E501
_MAX_TARGET = pow(2, 256)


def difficulty_to_target(difficulty):
    return _MAX_TARGET // max(3, difficulty)


# Given a BTC coinbase transaction, attempts to extract the RSK merge mining
# hash (if present). Otherwise it will raise a ValueErrors.
# Based on rskj.
# See https://github.com/rsksmart/rskj/blob/master/rskj-core/src/main/java/co/rsk/validators/ProofOfWorkRule.java#L162 # noqa E501
# for details.
# *** IMPORTANT ***:
# - tx_hex must be a string in hex format
# - the return value is a string in hex format
_MIDSTATE_SIZE = 52
_MIDSTATE_SIZE_TRIMMED = 40
_MIDSTATE_PREFIX_SIZE = 8
_MIDSTATE_SUFFIX_SIZE = 4
_RSK_TAG = b"RSKBLOCK:"
_MAX_RSK_TAG_POSITION = 64
_BLOCK_HEADER_HASH_SIZE = 32
_MAX_BYTES_AFTER_MERGE_MINING_HASH = 128
_BYTE_COUNT_LENGTH = 8
_MIN_COINBASE_TX_SIZE = 64


def coinbase_tx_extract_merge_mining_hash(tx_hex):
    try:
        tx = bytes.fromhex(tx_hex)
        tx_midstate = tx[:_MIDSTATE_SIZE]
        tx_tail = tx[_MIDSTATE_SIZE_TRIMMED:len(tx)]
        last_tag_pos = tx_tail.rfind(_RSK_TAG)

        if last_tag_pos == -1:
            message = "Couldn't find RSK tag '%s' in tail '%s'" % (
                _RSK_TAG.hex(),
                tx_tail.hex(),
            )
            _logger.info(message)
            raise ValueError(message)

        if last_tag_pos >= _MAX_RSK_TAG_POSITION:
            message = (
                "RSK tag '%s' position in tail '%s' is bigger than expected (%d)"
                % (_RSK_TAG.hex(), tx_tail.hex(), _MAX_RSK_TAG_POSITION)
            )
            _logger.info(message)
            raise ValueError(message)

        expected_tag_size = len(_RSK_TAG) + _BLOCK_HEADER_HASH_SIZE
        if len(tx_tail[last_tag_pos:]) < expected_tag_size:
            message = (
                "Last RSK tag '%s' found in tail '%s' is not long enough "
                "(expected at least %d bytes, got %d bytes)"
                % (
                    _RSK_TAG.hex(),
                    tx_tail.hex(),
                    expected_tag_size,
                    len(tx_tail[last_tag_pos:]),
                )
            )
            _logger.info(message)
            raise ValueError(message)

        remaining_tail = tx_tail[last_tag_pos + expected_tag_size:]

        if len(remaining_tail) > _MAX_BYTES_AFTER_MERGE_MINING_HASH:
            message = "More than %d bytes after RSK tag" % (
                _MAX_BYTES_AFTER_MERGE_MINING_HASH
            )
            _logger.info(message)
            raise ValueError(message)

        byte_count = int.from_bytes(
            tx_midstate[:_BYTE_COUNT_LENGTH], byteorder="big", signed=False
        )
        coinbase_tx_length = byte_count + len(tx_tail)
        if coinbase_tx_length <= _MIN_COINBASE_TX_SIZE:
            message = (
                "Coinbase transaction must be longer than %d bytes (got %d bytes)"
                % (_MIN_COINBASE_TX_SIZE, coinbase_tx_length)
            )
            _logger.info(message)
            raise ValueError(message)

        merged_mining_hash = tx_tail[
            last_tag_pos
            + len(_RSK_TAG):last_tag_pos
            + len(_RSK_TAG)
            + _BLOCK_HEADER_HASH_SIZE
        ].hex()
        _logger.info("Found merge mining hash in coinbase TX: %s", merged_mining_hash)

        return merged_mining_hash
    except Exception as e:
        message = "Can't extract merge mining hash from coinbase tx: %s" % str(e)
        _logger.info(message)
        raise ValueError(message)


def coinbase_tx_get_hash(tx_hex):
    try:
        tx = bytes.fromhex(tx_hex)
        tx_midstate = (
            bytes([0] * _MIDSTATE_PREFIX_SIZE)
            + tx[:_MIDSTATE_SIZE_TRIMMED]
            + bytes([0] * _MIDSTATE_SUFFIX_SIZE)
        )
        tx_tail = tx[_MIDSTATE_SIZE_TRIMMED:len(tx)]

        hash_round1 = thirdparty.sha256.SHA256()
        hash_round1.set_midstate(tx_midstate)
        hash_round1.update(tx_tail)
        hash_round1 = hash_round1.digest()

        coinbase_tx_hash = bytes(reversed(hashlib.sha256(hash_round1).digest())).hex()

        _logger.info("Coinbase TX hash: %s", coinbase_tx_hash)

        return coinbase_tx_hash
    except Exception as e:
        message = "Can't compute coinbase tx hash: %s" % str(e)
        _logger.info(message)
        raise ValueError(message)


# Given a merkle proof in the format described in RSKIP92
# (https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP92.md)
# this function returns True iif the given merkle proof is a valid
# proof of the coinbase tx for the given root hash
# *** IMPORTANT ***: all values are expected to be hex strings
_SHA256_HASH_LENGTH = 32


def is_valid_merkle_proof(merkle_proof_hex, root_hex, coinbase_tx_hash_hex):
    try:
        merkle_proof = bytes.fromhex(merkle_proof_hex)
        root = bytes.fromhex(root_hex)
        coinbase_tx_hash = bytes.fromhex(coinbase_tx_hash_hex)
    except Exception as e:
        _logger.info(str(e))
        raise ValueError(str(e))

    # Verify merkle proof length
    if len(merkle_proof) % _SHA256_HASH_LENGTH != 0:
        message = "Merkle proof length is invalid (%d)" % len(merkle_proof)
        _logger.info(message)
        return False

    # Extract merkle proof hashes
    hashes = []
    for i in range(0, len(merkle_proof) // _SHA256_HASH_LENGTH):
        start = i * _SHA256_HASH_LENGTH
        hashes.append(merkle_proof[start:start + _SHA256_HASH_LENGTH])

    # Reduce
    current_left = coinbase_tx_hash
    for right in hashes:
        current_left = combine_left_right(current_left, right)

    current_left = bytes(reversed(current_left))

    # We should have gotten to the root in case of a valid proof
    return root == current_left


# Combines two hashes (representing nodes in a merkle tree) to produce a single hash
# that would be the parent of these two nodes.
def combine_left_right(left, right):
    to_hash = bytes(reversed(left)) + bytes(reversed(right))
    double_hash = hashlib.sha256(hashlib.sha256(to_hash).digest()).digest()
    return bytes(reversed(double_hash))
