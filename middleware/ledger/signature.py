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

# Parses a signature received from a powHSM dongle

class HSM2DongleSignature:
    def __init__(self, signature_bytes):
        def error():
            raise ValueError("Invalid DER-encoded signature: %s" % signature_bytes.hex())

        # Decode signature_bytes, which should be in DER format
        # Format:
        #
        # 0x30 TOTAL_LENGTH
        # 0x02 R_LENGTH [R bytes]
        # 0x02 S_LENGTH [S bytes]
        # [potential rubbish]
        #
        # IMPORTANT: due to a bug, sometimes the first byte is 0x31 and not 0x30.
        # Deal with it.
        if (
            len(signature_bytes) < 2
            or signature_bytes[0] not in [0x30, 0x31]
            or len(signature_bytes[2:]) < signature_bytes[1]
        ):
            error()

        # R
        if (
            len(signature_bytes[2:]) < 2
            or signature_bytes[2] != 0x02
            or len(signature_bytes[4:]) < signature_bytes[3]
        ):
            error()
        r_len = signature_bytes[3]
        rbytes = signature_bytes[4:4 + r_len]

        # S
        if (
            len(signature_bytes[4 + r_len:]) < 2
            or signature_bytes[4 + r_len] != 0x02
            or len(signature_bytes[6 + r_len:]) < signature_bytes[5 + r_len]
        ):
            error()
        s_len = signature_bytes[5 + r_len]
        sbytes = signature_bytes[6 + r_len:6 + r_len + s_len]

        self._r = rbytes.hex()
        self._s = sbytes.hex()

    @property
    def r(self):
        return self._r

    @property
    def s(self):
        return self._s

    def __repr__(self):
        return f"{type(self).__name__}<0x{self.r}, 0x{self.s}>"

    # Self explanatory
    def __eq__(self, other):
        return (
            type(self) == type(other)
            and self.r == other.r
            and self.s == other.s
        )
