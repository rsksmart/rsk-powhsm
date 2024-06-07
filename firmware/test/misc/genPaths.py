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

import struct

# Parse bip44 path, convert to binary representation [len][int][int][int]...


def bip44tobin(path):
    path = path[2:]
    elements = path.split("/")
    result = b""
    result = result + struct.pack(">B", len(elements))
    for pathElement in elements:
        element = pathElement.split("'")
        if len(element) == 1:
            result = result + struct.pack("<I", int(element[0]))
        else:
            result = result + struct.pack("<I", 0x80000000 | int(element[0]))
    return result


keyIds = [
    "m/44'/0'/0'/0/0",
    "m/44'/1'/0'/0/0",
    "m/44'/137'/0'/0/0",
]

for i in keyIds:
    msg = ""
    path = bip44tobin(i)
    for c in path:
        msg += "\\x%02x" % c
    print(msg)
