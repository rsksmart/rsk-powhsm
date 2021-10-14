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

HASH_LENGTH = 32  # Bytes

if len(sys.argv) < 2:
    print("No hash specified")
    sys.exit(1)

hash_arg = sys.argv[1]

offset = 2 if hash_arg.startswith("0x") else 0
hash_plain = hash_arg[offset:]

try:
    int(hash_plain, 16)
    if len(hash_plain) != HASH_LENGTH*2:
        raise ValueError("Expected a %d-byte hexadecimal hash" % HASH_LENGTH)
except Exception as e:
    print("Invalid hash: %s" % str(e))
    sys.exit(1)

# Convert to C-const definition
result_hexes = []
for i in range(HASH_LENGTH):
    result_hexes.append("0x%s" % hash_plain[i*2:i*2+2])

print("{ %s }" % ", ".join(result_hexes))
