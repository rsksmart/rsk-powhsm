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

import sys

DIGIT_SIZE = 4  # In bytes
NUM_DIGITS = 9
MAX_BYTES = NUM_DIGITS*DIGIT_SIZE  # Difficulty length is in terms of number of ints

if len(sys.argv) < 2:
    print("No difficulty specified")
    sys.exit(1)

dif_str = sys.argv[1]

base = 10
offset = 0
if dif_str.startswith("0x"):
    base = 16
    offset = 2

try:
    dif = int(sys.argv[1][offset:], base)
except Exception as e:
    print("Invalid hex difficulty: %s" % str(e))
    sys.exit(1)

num_bytes = -(-dif.bit_length()//8)

if num_bytes > MAX_BYTES:
    print("Difficulty too big (max %d bytes but got %d)" % (MAX_BYTES, num_bytes))

# Convert to C-const definition in the bigint representation used by the signer
# (ints are big-endian, but between different ints, little-endianess is used)
result_ints = []
remaining = dif
digit_bits = DIGIT_SIZE*8
mask = (1 << digit_bits)-1
for _ in range(NUM_DIGITS):
    result_ints.append(int(remaining & mask))
    remaining = remaining >> digit_bits

print("{ %s }" % ", ".join(list(map(hex, result_ints))))
