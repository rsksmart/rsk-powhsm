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

"""Split a json rlp block list into smaller chunks."""

import click
import json


def split_name(blocks_file, curr):
    i = blocks_file.rfind(".")
    if i == -1:
        return blocks_file + f"-{curr:02d}.json"
    else:
        return blocks_file[:i] + f"-{curr:02d}.json"


@click.command()
@click.option("-b", "--blocks", "blocks_file", required=True, help="Json blocks file")
@click.option("-s",
              "--split-size",
              "split_size",
              required=True,
              type=int,
              help="Split size")
def blocksplit(blocks_file, split_size):
    with open(blocks_file, "r") as f:
        blocks = json.load(f)

    curr = 0
    N = len(blocks)
    init_size = min(N, split_size + len(blocks) % split_size)
    print(split_name(blocks_file, curr))

    with open(split_name(blocks_file, curr), "w") as f:
        print(f"Dumping {init_size} blocks")
        json.dump(blocks[:init_size], f)
        curr += 1

    for chunk in range(init_size, N, split_size):
        with open(split_name(blocks_file, curr), "w") as f:
            print(f"Dumping {split_size} blocks")
            json.dump(blocks[chunk:chunk + split_size], f)
            curr += 1


if __name__ == "__main__":
    # pylint: disable=E1123, E1120
    blocksplit()
