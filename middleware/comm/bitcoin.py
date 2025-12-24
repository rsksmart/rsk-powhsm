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
        if not redeem_script.is_valid():
            raise ValueError()
    except Exception:
        raise ValueError("Invalid redeem script: %s" % last_chunk_operand.hex())

    sighash = bitcoin.core.script.SignatureHash(
        redeem_script, tx, input_index, bitcoin.core.script.SIGHASH_ALL
    )

    return sighash.hex()


def get_signature_hash_for_p2sh_p2wsh_input(raw_tx_hex, input_index,
                                            witness_script_hex, amount):
    # Given a raw BTC transaction, an input index, a raw witness script and
    # an amount, this method computes the sighash corresponding to the given
    # input index for segwit v0

    tx = _deserialize_tx(raw_tx_hex)

    if input_index < 0 or input_index >= len(tx.vin):
        raise ValueError(
            "Asked for signature hash of input at index %d but only %d input(s) available"
            % (input_index, len(tx.vin))
        )

    try:
        witness_script = bitcoin.core.CScript(bytes.fromhex(witness_script_hex))
    except Exception:
        raise ValueError("Invalid witness script: %s" % witness_script_hex)

    sighash = bitcoin.core.script.SignatureHash(
        witness_script, tx, input_index, bitcoin.core.script.SIGHASH_ALL,
        amount, bitcoin.core.script.SIGVERSION_WITNESS_V0
    )

    return sighash.hex()


def get_block_hash_as_int(raw_block_header_hex):
    block_header = _deserialize_block_header(raw_block_header_hex)
    return int.from_bytes(block_header.GetHash(), byteorder="little", signed=False)


def get_merkle_root(raw_block_header_hex):
    block_header = _deserialize_block_header(raw_block_header_hex)
    return block_header.hashMerkleRoot.hex()


def encode_varint(v):
    return bitcoin.core.VarIntSerializer.serialize(v).hex()


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
