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

import time
from comm.protocol_v1 import HSM1Protocol
from .authorization import is_authorized_signing_path, is_auth_requiring_path


class HSM1ProtocolSimulator(HSM1Protocol):
    def __init__(self, wallet, speed_bps):
        super().__init__()
        self._wallet = wallet
        self._speed_bps = speed_bps

    def initialize_device(self):
        self.logger.debug("Device initialized")

    def _get_pubkey(self, request):
        # Simulate processing speed
        self.__do_sleep(len(request["keyId"].to_binary()))

        # Validate key id is authorized for signing (only a specific set of paths is
        # allowed to be used for signing and thus for retrieving the public key)
        if not is_authorized_signing_path(request["keyId"]):
            self.logger.info("Unauthorized Key ID: %s", str(request["keyId"]))
            return (self.ERROR_CODE_INVALID_KEYID, )

        return (
            self.ERROR_CODE_OK,
            {
                "pubKey": self._wallet.get(str(request["keyId"])).public_key()
            },
        )

    def _sign(self, request):
        # Simulate processing speed
        self.__do_sleep(len(request["keyId"].to_binary()) + len(request["message"])//2)

        # Validate key id is authorized for signing without an authorization proof
        # (only a specific set of paths is allowed to be used for unauthorized signing)
        if not is_authorized_signing_path(request["keyId"]) or is_auth_requiring_path(
                request["keyId"]):
            self.logger.info("Unauthorized Key ID: %s", str(request["keyId"]))
            return (self.ERROR_CODE_INVALID_KEYID, )

        # Actually do the signing
        try:
            self.logger.info("Trying to sign '%s'", request["message"])
            signature = self._wallet.get(str(request["keyId"])).sign(request["message"])
        except Exception as e:
            self.logger.info("Error signing '%s': %s", request["message"], str(e))
            return (self.ERROR_CODE_DEVICE, )

        self.logger.info("Signed: R:%s S:%s", signature["r"], signature["s"])
        return (
            self.ERROR_CODE_OK,
            {
                "signature": {
                    "r": signature["r"],
                    "s": signature["s"]
                }
            },
        )

    def __do_sleep(self, request_size_in_bytes):
        # Sleep depending on the configured processing speed
        # and the amount of bytes to process
        sleep_seconds = request_size_in_bytes/self._speed_bps
        self.logger.info(
            "Processing %d bytes at %d bps, sleeping for %.4f seconds",
            request_size_in_bytes,
            self._speed_bps,
            sleep_seconds,
        )
        time.sleep(sleep_seconds)
