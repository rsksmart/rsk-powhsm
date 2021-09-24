"""Turn a json rlp block list into a binary byte array.

This command is specially designed to produce test data for
ledger/src/simul/bc_advance_host.c
"""

import click
import json
import sys
import rlp


def rlp_mm_payload_size(block_rlp):
    block = rlp.decode(block_rlp)
    block_without_mm_fields = block[:-3]
    block_without_mm_fields_rlp = rlp.encode(block_without_mm_fields)
    b = block_without_mm_fields_rlp[0]
    if b >= 0xC0 and b <= 0xF7:
        L = b - 0xC0
    elif b >= 0xF8 and b <= 0xFF:
        N = b - 0xF7
        L = 0
        for i in range(N):
            L = (L << 8) | block_without_mm_fields_rlp[1 + i]
    else:
        assert False, "Invalid RLP encoding for block without MM fields"
    return L


def output_name(blocks_file):
    i = blocks_file.rfind(".")
    if i == -1:
        return blocks_file + ".rlp"
    else:
        return blocks_file[:i] + ".rlp"


def dump_block_offsets(file_name, binary_blocks):
    offset = 0
    first = True
    print(f"{file_name}: ", end="")
    print("{", end="")
    for block in binary_blocks:
        if first:
            first = False
        else:
            print(", ", end="")
        print(offset, end="")
        offset += len(block)
    print("}")


def dump_mm_rlp_lengths(file_name, binary_blocks):
    first = True
    print(f"{file_name}: ", end="")
    print("{", end="")
    for block in binary_blocks:
        if first:
            first = False
        else:
            print(", ", end="")
        mm_rlp_size = rlp_mm_payload_size(block)
        print(mm_rlp_size, end="")
    print("}")


@click.command()
@click.option("-b", "--blocks", "blocks_file", required=True, help="Json blocks file")
@click.option("-o", "--output", "output_file", required=False, help="Output file name")
@click.option(
    "-c",
    "--cutoff",
    "cutoff",
    required=False,
    default=sys.maxsize,
    help="How many blocks to dump",
)
def blockbin(blocks_file, output_file, cutoff):
    with open(blocks_file, "r") as f:
        blocks = json.load(f)
    binary_blocks = [bytes.fromhex(b) for i, b in enumerate(blocks) if i < cutoff]
    rlp_file = output_file if output_file is not None else output_name(blocks_file)
    with open(rlp_file, "wb") as f:
        for block in binary_blocks:
            f.write(block)
    dump_block_offsets(rlp_file, binary_blocks)
    dump_mm_rlp_lengths(rlp_file, binary_blocks)


if __name__ == "__main__":
    blockbin()
