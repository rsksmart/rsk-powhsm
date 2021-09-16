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
