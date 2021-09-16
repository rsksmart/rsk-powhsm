"""Dump block data.

Exclusively for solution checking only. Given a folder holding
splits named split-(dd).json (where d is a decimal digit), dump
useful data such as total difficulty and block hashes.
"""

import click
import json
import os
import re
import rlp
import sha3


@click.command()
@click.option("-s", "--splits", "split_dir", required=True, help="Splits folder")
def blockdump(split_dir):
    split_names = sorted(
        [nm for nm in os.listdir(split_dir) if re.match(r"split-(\d{2})\.json", nm)])

    total_diff = 0
    for split_name in split_names:
        split_diff = 0
        print(f"Split: {split_name}")
        with open(os.path.join(split_dir, split_name), "r") as f:
            blocks = json.load(f)
            for j, block_rlp in enumerate(blocks):
                block = rlp.decode(bytes.fromhex(block_rlp))

                block_hash = sha3.keccak_256(rlp.encode(block[:-2])).digest().hex()
                print(f"Block #{j} hash = {block_hash}")

                if j == len(blocks) - 1:
                    block_hash = sha3.keccak_256(rlp.encode(block[:-2])).digest().hex()
                    print(f"  Last block Receipt root = {block[5].hex()}")

                diff = int.from_bytes(block[7], byteorder="big", signed=False)
                split_diff += diff
            total_diff += split_diff
            print(f"  Split diff = {hex(split_diff)}")
            print(f"  Total diff = {hex(total_diff)}")


if __name__ == "__main__":
    # pylint: disable=E1123, E1120
    blockdump()
