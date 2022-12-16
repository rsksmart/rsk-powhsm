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
                    print(f"  Last block Receipt root = {block[5].hex()}")

                diff = int.from_bytes(block[7], byteorder="big", signed=False)
                split_diff += diff
            total_diff += split_diff
            print(f"  Split diff = {hex(split_diff)}")
            print(f"  Total diff = {hex(total_diff)}")


if __name__ == "__main__":
    # pylint: disable=E1123, E1120
    blockdump()
