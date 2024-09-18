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

from comm.server import TCPServer, TCPServerError
from ledger.protocol import HSM2ProtocolLedger
from ledger.protocol_v1 import HSM1ProtocolLedger
from comm.logging import configure_logging
from ledger.pin import PinError
import logging


class ManagerRunner:
    def __init__(self, name, create_dongle, load_pin):
        self.name = name
        self.create_dongle = create_dongle
        self.load_pin = load_pin

    def run(self, user_options):
        configure_logging(user_options.logconfigfilepath)
        logger = logging.getLogger("hsm-ledger")

        logger.info(f"{self.name} starting")

        try:
            pin = self.load_pin(user_options)
            dongle = self.create_dongle(user_options)

            # Init protocol depending on the required version
            if user_options.version_one:
                logger.info("Using protocol version 1")
                protocol = HSM1ProtocolLedger(pin, dongle)
            else:
                logger.info("Using protocol version 2")
                protocol = HSM2ProtocolLedger(pin, dongle)
            server = TCPServer(user_options.host, user_options.port, protocol)
            server.run()
        except PinError as e:
            logger.critical("While loading PIN: %s", e)
        except TCPServerError:
            # This is a genuine error with no recovery
            # and logging is handled by the server itself
            pass
        finally:
            logger.info(f"{self.name} terminated")
