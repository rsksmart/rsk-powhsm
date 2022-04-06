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

from enum import IntEnum


class _Network(IntEnum):
    MAINNET = 0x01
    TESTNET = 0x02
    REGTEST = 0x03


# Instances of this represent parameters
# of firmware installed on a powHSM
# Parameters consist of minimum required difficulty, checkpoint and
# target network.
class HSM2FirmwareParameters:
    # Shorthand
    Network = _Network

    @staticmethod
    def from_dongle_format(param_bytes):
        if len(param_bytes) != 69:
            raise ValueError("Expected 69 bytes but got %d" % len(param_bytes))
        # Format:
        # Bytes 0-31: initial block hash
        # Bytes 32-67: minimum required difficulty (unsigned big endian)
        # Byte 68: network identifier
        checkpoint = param_bytes[0:32].hex()
        mrd = int.from_bytes(param_bytes[32:68], byteorder="big", signed=False)
        network = _Network(param_bytes[68])
        return HSM2FirmwareParameters(mrd, checkpoint, network)

    def __init__(self, min_required_difficulty, checkpoint, network):
        self.min_required_difficulty = min_required_difficulty
        self.checkpoint = checkpoint
        self.network = network
