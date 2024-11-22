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


class Op(IntEnum):
    OP_GET = 0x01
    OP_GET_MESSAGE = 0x02
    OP_APP_HASH = 0x03
    OP_GET_ENVELOPE = 0x04


LEGACY_HEADER = b"HSM:SIGNER:"


# Implements the powhsm attestation protocol against a
# running powhsm
class PowHsmAttestation(HSM2DongleCommand):
    Command = 0x50

    def run(self, ud_value_hex):
        # Retrieve attestation signature
        signature = self.send(Op.OP_GET,
                              bytes.fromhex(ud_value_hex))[self.Offset.DATA:]

        # Retrieve message and envelope
        bufs = {}
        brk = False
        msgoffset = 1  # For legacy behavior handling
        for (op, name) in \
                [(Op.OP_GET_MESSAGE, "message"), (Op.OP_GET_ENVELOPE, "envelope")]:
            # Legacy behavior handling
            if brk:
                bufs["envelope"] = bufs["message"]
                break
            bufs[name] = b''
            more = True
            page = 0
            while more:
                result = self.send(op, bytes([page]))
                more = result[self.Offset.DATA] == 1
                # Legacy behavior handling
                if name == "message" and \
                   result[self.Offset.DATA:self.Offset.DATA+len(LEGACY_HEADER)] == \
                   LEGACY_HEADER:
                    msgoffset = 0
                    more = False
                    brk = True
                bufs[name] += result[self.Offset.DATA+msgoffset:]
                page += 1

        # Get signer hash
        signer_hash = self.send(Op.OP_APP_HASH)[self.Offset.DATA:]

        return {
            "app_hash": signer_hash.hex(),
            "envelope": bufs["envelope"].hex(),
            "message": bufs["message"].hex(),
            "signature": signature.hex(),
        }
