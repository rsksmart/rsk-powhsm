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

from ledgerblue.commTCP import getDongle
from ledgerblue.commException import CommException
from .hsm2dongle import HSM2Dongle, HSM2DongleCommError


class HSM2DongleTCP(HSM2Dongle):
    def __init__(self, host, port, debug):
        self.host = host
        self.port = port
        super().__init__(debug)

    # Connect to the TCP "dongle"
    def connect(self):
        try:
            self.logger.info(f"Connecting to {self.host}:{self.port}")
            self.dongle = getDongle(self.host, self.port, self.debug)
            self.logger.info("Connected")
        except CommException as e:
            msg = "Error connecting: %s" % e.message
            self.logger.error(msg)
            raise HSM2DongleCommError(msg)

    # Disconnect from the TCP "dongle"
    def disconnect(self):
        try:
            self.logger.info("Disconnecting")
            if self.dongle and self.dongle.opened:
                self.dongle.close()
            self.logger.info("Disconnected")
        except CommException as e:
            msg = "Error disconnecting: %s" % e.message
            self.logger.error(msg)
            raise HSM2DongleCommError(msg)
