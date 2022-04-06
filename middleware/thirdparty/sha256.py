#!/usr/bin/python3

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

__base__ = 'https://github.com/thomdixon/pysha2/blob/master/sha2/sha256.py'
__author__ = 'Lukas Prokop'
__license__ = 'MIT'

import copy
import struct
import binascii

F32 = 0xFFFFFFFF

_k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

_h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]


def _pad(msglen):
    mdi = msglen & 0x3F
    length = struct.pack('!Q', msglen << 3)

    if mdi < 56:
        padlen = 55 - mdi
    else:
        padlen = 119 - mdi

    return b'\x80' + (b'\x00' * padlen) + length


def _rotr(x, y):
    return ((x >> y) | (x << (32 - y))) & F32


def _maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def _ch(x, y, z):
    return (x & y) ^ ((~x) & z)


class SHA256:
    _output_size = 8
    blocksize = 1
    block_size = 64
    digest_size = 32

    def __init__(self, m=None):
        self._counter = 0
        self._cache = b''
        self._k = copy.deepcopy(_k)
        self._h = copy.deepcopy(_h)

        self.update(m)

    # Sets the midstate of the digest.
    # Based off org.bouncycastle.crypto.digests.SHA256Digest
    # method 'getEncodedState' (as of version 1.59).
    # This state should be exactly 52 bytes long
    # The first 8 bytes will be ignored.
    # The following 8 bytes will represent the counter (unsigned big-endian)
    # The following 32 bytes will represent the current hash (8 4-byte big-endian words)
    # The last 4 bytes will be ignored.
    def set_midstate(self, state):
        if type(state) != bytes or len(state) != 52:
            raise ValueError("Invalid state given: %s" % state)

        self._counter = struct.unpack('>Q', state[8:16])[0]
        self._h = []
        for i in range(8):
            start = 16+i*4
            self._h.append(struct.unpack('>I', state[start:start+4])[0])

    def _compress(self, c):
        w = [0] * 64
        w[0:16] = struct.unpack('!16L', c)

        for i in range(16, 64):
            s0 = _rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = _rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & F32

        a, b, c, d, e, f, g, h = self._h

        for i in range(64):
            s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            t2 = s0 + _maj(a, b, c)
            s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            t1 = h + s1 + _ch(e, f, g) + self._k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + t1) & F32
            d = c
            c = b
            b = a
            a = (t1 + t2) & F32

        for i, (x, y) in enumerate(zip(self._h, [a, b, c, d, e, f, g, h])):
            self._h[i] = (x + y) & F32

    def update(self, m):
        if not m:
            return

        self._counter += len(m)
        m = self._cache + m

        for i in range(0, len(m) // 64):
            self._compress(m[64 * i:64 * (i + 1)])

        # Bugfix: cache must be empty when the message size
        # is a multiple of 64 (i.e., all the message has been consumed)
        if len(m) % 64 == 0:
            self._cache = b''
        else:
            self._cache = m[-(len(m) % 64):]

    def digest(self):
        r = copy.deepcopy(self)
        r.update(_pad(self._counter))
        data = [struct.pack('!L', i) for i in r._h[:self._output_size]]
        return b''.join(data)

    def hexdigest(self):
        return binascii.hexlify(self.digest()).decode('ascii')


if __name__ == '__main__':
    def check(msg, sig):
        m = SHA256()
        m.update(msg.encode('ascii'))
        print(m.hexdigest() == sig)

    tests = {
        "":
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        "a":
            'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
        "abc":
            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        "message digest":
            'f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650',
        "abcdefghijklmnopqrstuvwxyz":
            '71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73',
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":
            'db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0',
        ("12345678901234567890123456789012345678901234567890123456789"
         "012345678901234567890"):
            'f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e',
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":
            'ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb'
    }

    for inp, out in tests.items():
        check(inp, out)
