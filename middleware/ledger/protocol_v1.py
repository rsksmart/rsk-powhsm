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

from comm.protocol_v1 import HSM1Protocol
from .protocol import HSM2ProtocolLedger, HSM2ProtocolError
from ledger.hsm2dongle import (
    HSM2Dongle,
    HSM2DongleError,
    HSM2DongleErrorResult,
    HSM2DongleTimeoutError,
    HSM2DongleCommError,
)


class HSM1ProtocolLedger(HSM1Protocol):
    def __init__(self, pin, dongle):
        super().__init__()
        self.hsm2dongle = dongle
        self.pin = pin
        self.protocol_v2 = HSM2ProtocolLedger(pin, dongle)

    # Delegate initialization to the v2 protocol
    def initialize_device(self):
        return self.protocol_v2.initialize_device()

    def _get_pubkey(self, request):
        try:
            self.protocol_v2.ensure_connection()
            return (
                self.ERROR_CODE_OK,
                {"pubKey": self.hsm2dongle.get_public_key(request["keyId"])},
            )
        except HSM2DongleErrorResult:
            return (self.ERROR_CODE_INVALID_KEYID,)
        except HSM2DongleTimeoutError:
            self.logger.error("Dongle timeout getting public key")
            return (self.ERROR_CODE_DEVICE,)
        except HSM2DongleCommError:
            # Signal a communication problem and return a device error
            self.protocol_v2.report_comm_issue()
            self.logger.error("Dongle communication error getting public key")
            return (self.ERROR_CODE_DEVICE,)
        except HSM2DongleError as e:
            return self._error("Dongle error in get_pubkey: %s" % str(e))

    def _sign(self, request):
        try:
            self.protocol_v2.ensure_connection()
            sign_result = self.hsm2dongle.sign_unauthorized(
                key_id=request["keyId"], hash=request["message"]
            )
        except HSM2DongleTimeoutError:
            self.logger.error("Dongle timeout signing")
            return (self.ERROR_CODE_DEVICE,)
        except HSM2DongleCommError:
            # Signal a communication problem and return a device error
            self.protocol_v2.report_comm_issue()
            self.logger.error("Dongle communication error signing")
            return (self.ERROR_CODE_DEVICE,)
        except HSM2DongleError as e:
            self._error("Dongle error in sign: %s" % str(e))

        if not sign_result[0]:
            return (self._translate_sign_error(sign_result[1]),)
        signature = sign_result[1]

        return (self.ERROR_CODE_OK, {"signature": {"r": signature.r, "s": signature.s}})

    def _translate_sign_error(self, error_code):
        return (
            {
                HSM2Dongle.RESPONSE.SIGN.ERROR_PATH: self.ERROR_CODE_INVALID_KEYID,
                HSM2Dongle.RESPONSE.SIGN.ERROR_HASH: self.ERROR_CODE_INVALID_MESSAGE,
                HSM2Dongle.RESPONSE.SIGN.ERROR_UNEXPECTED: self.ERROR_CODE_DEVICE,
            }
        ).get(error_code, self.ERROR_CODE_UNKNOWN)

    def _error(self, msg):
        self.logger.error(msg)
        raise HSM2ProtocolError(msg)
