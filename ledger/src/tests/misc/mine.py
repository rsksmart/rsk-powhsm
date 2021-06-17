import sys
sys.path.append("../../../../middleware")

import rlp
import comm.bitcoin as bitcoin
import simulator.rsk.block as rsk_block
import simulator.rsk.netparams as netparams
import comm.pow as pow
import ledger.block_utils as block_utils

MM_HASH_PLACEHOLDER = "<MM_HASH>"
COINBASE_TX_TEMPLATE = f"0000000000000400f1f2c62bc5bfded2c12c1696ff5ecd3d8ee4867bf5b0b5d42b8ed2433fe4dec552534b424c4f434b3a{MM_HASH_PLACEHOLDER}ffffffff0100f2052a01000000232103afcefd7798b549c7d178bac0ecb93c270f39d688a439a642a6b2458962e5cd65ac00000000"

MERKLE_ROOT_PLACEHOLDER = "<MERKLE_ROOT>"
BTC_TX_TEMPLATE = f"711101000000000000000000000000000000000000000000000000000000000000000000{MERKLE_ROOT_PLACEHOLDER}22c0355fffff7f2100000000"

regtest = netparams.NetworkParameters.REGTEST

def mine(block_hex, np):
    new_block = rlp.decode(block_utils.remove_mm_fields_if_present(block_hex, leave_btcblock=False, hex=False)) + \
                      [b'', b'', b'']
    new_block_obj = rsk_block.RskBlockHeader(rlp.encode(new_block).hex(), np, False)
    cbtx = COINBASE_TX_TEMPLATE.replace(MM_HASH_PLACEHOLDER, new_block_obj.hash_for_merge_mining)
    cbtx_hash = pow.coinbase_tx_get_hash(cbtx)
    merkle_root = bytes(reversed(bytes.fromhex(cbtx_hash))).hex()
    btctx = BTC_TX_TEMPLATE.replace(MERKLE_ROOT_PLACEHOLDER, merkle_root)
    new_block[-1] = bytes.fromhex(cbtx)

    nonce = 0
    while True:
        new_block[-3] = bytes.fromhex(btctx[:-8]) + nonce.to_bytes(4, byteorder='big', signed=False)
        if rsk_block.RskBlockHeader(rlp.encode(new_block).hex(), np).pow_is_valid():
            break
        nonce += 1

    return rlp.encode(new_block).hex()

def mine_chain(first_block_hex, np, total_blocks):
    current_block = mine(first_block_hex, np)
    blocks = [current_block]
    ba = rlp.decode(bytes.fromhex(current_block))
    for i in range(total_blocks-1):
        cbo = rsk_block.RskBlockHeader(current_block, np)
        ba[0] = bytes.fromhex(cbo.hash)
        new_number = cbo.number+1
        ba[8] = new_number.to_bytes((new_number.bit_length()+7)//8, byteorder='big', signed=False)
        ba[5] = bytes.fromhex('00' * 32) # Receipts root does not matter
        current_block = mine(rlp.encode(ba).hex(), np)
        blocks.insert(0, current_block)

    return blocks


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <BLOCK_TO_MINE>")
        sys.exit(1)


    print("RESULT:")
    print(mine(sys.argv[1], regtest))

    