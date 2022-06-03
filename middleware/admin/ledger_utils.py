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

from ledgerblue.hexParser import IntelHexParser
from hashlib import sha256


def compute_app_hash(path):
    # Taken from
    # https://github.com/LedgerHQ/blue-loader-python/blob/0.1.31/ledgerblue/hashApp.py
    parser = IntelHexParser(path)
    digest = sha256()
    for a in parser.getAreas():
        digest.update(a.data)
    return digest.digest()


def encode_eth_message(msg):
    return f"\x19Ethereum Signed Message:\n{str(len(msg))}{msg}".encode("ascii")


def eth_message_to_printable(msg):
    return repr(msg.decode("ascii"))[1:-1]
