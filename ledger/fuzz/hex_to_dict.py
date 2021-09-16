#!/usr/bin/env python3

import argparse
import os

parser = argparse.ArgumentParser(description="Add a hex string to the fuzzing dictionary "
                                             "as raw bytes")
parser.add_argument('hex', type=str, help="The hex string")
parser.add_argument('description', type=str, help="The in-dictionary description of this "
                                                  "value")
args = parser.parse_args()

dir_path = os.path.dirname(os.path.realpath(__file__))
bs = bytes.fromhex(args.hex)
with open(f"{dir_path}/dict/{args.description}", "wb+") as f:
    f.write(bs)
