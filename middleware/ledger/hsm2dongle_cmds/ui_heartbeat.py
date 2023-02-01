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
from .command import HSM2DongleCommand
from ..signature import HSM2DongleSignature


class Op(IntEnum):
    UD_VALUE = 0x01
    GET = 0x02
    GET_MESSAGE = 0x03
    APP_HASH = 0x04
    PUBKEY = 0x05


# Implements the UI heartbeat protocol against a
# running UI in heartbeat mode
class HSM2UIHeartbeat(HSM2DongleCommand):
    Command = 0x60

    def run(self, ud_value):
        try:
            # Send user-defined value
            self.send(Op.UD_VALUE, bytes.fromhex(ud_value))

            # Retrieve signature
            signature = self.send(Op.GET, self.NoData)[self.Offset.DATA:]

            # Retrieve message
            message = self.send(Op.GET_MESSAGE, self.NoData)[self.Offset.DATA:]

            # Retrieve UI hash
            ui_hash = self.send(Op.APP_HASH, self.NoData)[self.Offset.DATA:]

            # Retrieve attestation public key
            public_key = self.send(Op.PUBKEY, self.NoData)[self.Offset.DATA:]

            return (True, {
                "pubKey": public_key.hex(),
                "message": message.hex(),
                "signature": HSM2DongleSignature(signature),
                "tweak": ui_hash.hex(),
            })
        except self.ErrorResult as e:
            self.logger.error("UI heartbeat returned: %s", hex(e.error_code))
            # All possible error results from this operation are unexpected
            # No need for specific error code mappings or special cases
            return (False, )
