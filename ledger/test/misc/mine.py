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

import ledger.block_utils as block_utils
import comm.pow as pow
import rsk_netparams as netparams
import rsk_block as rsk_block
import rlp
import sys
import hashlib
import sha3
import json

sys.path.append("../../../../middleware")

MM_HASH_PLACEHOLDER = "<MM_HASH>"
COINBASE_TX_TEMPLATE = ("0000000000000400f1f2c62bc5bfded2c12c1696ff5ecd3d8ee4867bf5b0b5d4"
                        f"2b8ed2433fe4dec552534b424c4f434b3a{MM_HASH_PLACEHOLDER}ffffffff"
                        "0100f2052a01000000232103afcefd7798b549c7d178bac0ecb93c270f39d688"
                        "a439a642a6b2458962e5cd65ac00000000")

MERKLE_ROOT_PLACEHOLDER = "<MERKLE_ROOT>"
BTC_TX_TEMPLATE = ("711101000000000000000000000000000000000000000000000000000000000000000"
                   f"000{MERKLE_ROOT_PLACEHOLDER}22c0355fffff7f2100000000")

regtest = netparams.NetworkParameters.REGTEST


def byte_length(n):
    return ((n.bit_length()-1)//8)+1


def to_bytes(n):
    return n.to_bytes(byte_length(n), byteorder='big', signed=False)


def from_bytes(b):
    return int.from_bytes(b, byteorder='big', signed=False)


def mine(block_hex, np, mm_mp_nodes, brothers_difficulties):
    new_block = rlp.decode(
        block_utils.remove_mm_fields_if_present(
            block_hex, leave_btcblock=False, hex=False)) + [b"", b"", b""]

    # Brothers?
    brothers = []

    if type(brothers_difficulties) == list:
        brother_index = 0
        for brother_difficulty in brothers_difficulties:
            brother = new_block[:]
            # Change the uncles hash to make the block different
            brother[1] = sha3.keccak_256(
                bytes([brother_index])).digest()
            # Specified difficulty
            brother[7] = to_bytes(brother_difficulty)
            brothers.append(
                rlp.decode(bytes.fromhex(
                    mine(rlp.encode(brother).hex(), np, 1, None)[0]
                ))
            )
            brother_index += 1

    new_block_obj = rsk_block.RskBlockHeader(rlp.encode(new_block).hex(), np, False)
    cbtx = COINBASE_TX_TEMPLATE.replace(MM_HASH_PLACEHOLDER,
                                        new_block_obj.hash_for_merge_mining)
    cbtx_hash = pow.coinbase_tx_get_hash(cbtx)
    current_left = bytes.fromhex(cbtx_hash)
    mm_mp = bytes()
    for i in range(mm_mp_nodes):
        right = hashlib.sha256(bytes([i])).digest()
        mm_mp += right
        current_left = pow.combine_left_right(current_left, right)
    merkle_root = bytes(reversed(current_left)).hex()
    btctx = BTC_TX_TEMPLATE.replace(MERKLE_ROOT_PLACEHOLDER, merkle_root)
    new_block[-1] = bytes.fromhex(cbtx)
    new_block[-2] = mm_mp

    nonce = 0
    while True:
        new_block[-3] = bytes.fromhex(btctx[:-8]) + nonce.to_bytes(
            4, byteorder="big", signed=False)
        if rsk_block.RskBlockHeader(rlp.encode(new_block).hex(), np).pow_is_valid():
            break
        nonce += 1

    return (rlp.encode(new_block).hex(), list(map(
        lambda bro: rlp.encode(bro).hex(), brothers)))


def mine_chain(first_block_hex, np, total_blocks):
    current_block = mine(first_block_hex, np, 0, None)[0]
    blocks = [current_block]
    ba = rlp.decode(bytes.fromhex(current_block))
    for i in range(total_blocks - 1):
        cbo = rsk_block.RskBlockHeader(current_block, np)
        ba[0] = bytes.fromhex(cbo.hash)
        new_number = cbo.number + 1
        ba[8] = new_number.to_bytes((new_number.bit_length() + 7) // 8,
                                    byteorder="big",
                                    signed=False)
        ba[5] = bytes.fromhex("00" * 32)  # Receipts root does not matter
        current_block = mine(rlp.encode(ba).hex(), np, 0, None)[0]
        blocks.insert(0, current_block)

    return blocks


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            f"Usage: {sys.argv[0]} <BLOCK_TO_MINE> "
            "[MM_MP_NODES] [BROTHERS_DIFFICULTIES]")
        sys.exit(1)

    mm_mp_nodes = 0
    if len(sys.argv) > 2:
        mm_mp_nodes = int(sys.argv[2])

    brothers_difficulties = None
    if len(sys.argv) > 3:
        brothers_difficulties = list(map(lambda d: int(d, 10), sys.argv[3].split(",")))

    res = mine(sys.argv[1], regtest, mm_mp_nodes=mm_mp_nodes,
               brothers_difficulties=brothers_difficulties)
    print("RESULT:")
    print("=======")
    print(f"BLOCK: {res[0]}")
    print(f"BROTHERS: {json.dumps(res[1])}")
