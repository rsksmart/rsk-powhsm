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
import struct

ITERATION_LENGTH = 2  # Bytes

if len(sys.argv) < 2:
    print("No iteration specified")
    sys.exit(1)

iteration_arg = sys.argv[1]

offset = 2 if iteration_arg.startswith("0x") else 0
base = 16 if iteration_arg.startswith("0x") else 10
iteration_plain = iteration_arg[offset:]

try:
    struct.pack(">H", int(iteration_plain, base))
except Exception as e:
    print("Invalid iteration: %s" % str(e))
    sys.exit(1)

# Print as hexadecimal
print(hex(int(iteration_plain, base)))
