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

import bitcoin.core


def get_unsigned_tx(raw_tx_hex, hex=True):
    unsigned_bytes = _unsign_tx(raw_tx_hex).serialize()

    if hex:
        return unsigned_bytes.hex()

    return unsigned_bytes


def get_tx_hash(raw_tx_hex):
    return _deserialize_tx(raw_tx_hex).GetHash()[::-1].hex()


def get_tx_hash_for_unsigned_tx(raw_tx_hex):
    return _unsign_tx(raw_tx_hex).GetHash()[::-1].hex()


def get_tx_version(raw_tx_hex):
    tx = _deserialize_tx(raw_tx_hex)
    return tx.nVersion


def _unsign_tx(raw_tx_hex):
    # Given a p2sh-only inputs transaction (all of them corresponding
    # to multisig outputs), this method clears any
    # existent signatures in all the inputs and then computes
    # the hash of the resulting transaction

    tx = _deserialize_tx(raw_tx_hex)

    tx.vin = list(map(_clear_all_but_last_op_from_scriptsig, tx.vin))

    return tx


def _clear_all_but_last_op_from_scriptsig(txin):
    # Given a transaction input, this returns a copy
    # with its scriptSig replaced by a script with all
    # its operations as ZERO, excepting
    # the last operation, which is left untouched.

    new_txin = bitcoin.core.CMutableTxIn.from_txin(txin)
    ops = list(new_txin.scriptSig)
    new_ops = ([0] * (len(ops) - 1)) + [ops[-1]]
    new_txin.scriptSig = bitcoin.core.CScript(new_ops)
    return new_txin


def get_signature_hash_for_p2sh_input(raw_tx_hex, input_index):
    # Given a raw BTC transaction and an input index,
    # this method computes the sighash corresponding to the given
    # input index
    # This assumes that the input at the given index has a push with the
    # redeem script as the last operation of its scriptSig

    tx = _deserialize_tx(raw_tx_hex)

    if input_index < 0 or input_index >= len(tx.vin):
        raise ValueError(
            "Asked for signature hash of input at index %d but only %d input(s) available"
            % (input_index, len(tx.vin))
        )

    script_chunks = list(tx.vin[input_index].scriptSig.raw_iter())
    if len(script_chunks) == 0:
        raise ValueError("No ScriptSig found for input index %d" % input_index)

    last_chunk = script_chunks[-1]

    last_chunk_operand = last_chunk[1]
    if last_chunk_operand is None:
        raise ValueError("Last script operation does not have an operand")

    try:
        redeem_script = bitcoin.core.CScript(last_chunk_operand)
    except Exception:
        raise ValueError("Invalid redeem script: %s" % last_chunk_operand.hex())

    sighash = bitcoin.core.script.SignatureHash(
        redeem_script, tx, input_index, bitcoin.core.script.SIGHASH_ALL
    )

    return sighash.hex()


def get_block_hash_as_int(raw_block_header_hex):
    block_header = _deserialize_block_header(raw_block_header_hex)
    return int.from_bytes(block_header.GetHash(), byteorder="little", signed=False)


def get_merkle_root(raw_block_header_hex):
    block_header = _deserialize_block_header(raw_block_header_hex)
    return block_header.hashMerkleRoot.hex()


def _deserialize_block_header(raw_block_header_hex):
    try:
        return bitcoin.core.CBlockHeader.deserialize(bytes.fromhex(raw_block_header_hex))
    except Exception as e:
        raise ValueError("Impossible to deserialize btc block header: %s" % str(e))


def _deserialize_tx(raw_tx_hex):
    try:
        return bitcoin.core.CMutableTransaction.deserialize(bytes.fromhex(raw_tx_hex))
    except Exception as e:
        raise ValueError("Impossible to deserialize btc transaction: %s" % str(e))
