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

import sys
from comm.server import TCPServer, TCPServerError
from user.options import UserOptionParser
from simulator.protocol import HSM2ProtocolSimulator
from simulator.protocol_v1 import HSM1ProtocolSimulator
from simulator.wallet import load_or_create_wallet
from simulator.authorization import get_authorized_signing_paths
from simulator.blockchain_state import load_or_create_blockchain_state
from simulator.rsk.netparams import NetworkParameters
from comm.utils import hex_or_decimal_string_to_int
from comm.logging import configure_logging
import logging

if __name__ == "__main__":
    user_options = UserOptionParser("Start the HSM2 manager+ledger simulator",
                                    is_simulator=True, with_pin=False).parse()

    configure_logging(user_options.logconfigfilepath)
    logger = logging.getLogger("smltr")

    logger.info("Manager starting")
    logger.info("Using bridge address %s", user_options.bridge_address)

    try:
        # If using protocol v2, then init dependencies
        if not user_options.version_one:
            # Load network parameters
            netparams = NetworkParameters.from_string(user_options.netparams)
            netparams_name = "ad-hoc" if netparams.name is None else netparams.name
            logger.info("Using %s network parameters: %s", netparams_name, str(netparams))

            # Load minimum cumulative difficulty
            try:
                minimum_cumulative_difficulty = hex_or_decimal_string_to_int(
                    user_options.min_cumulative_difficulty)
                logger.info(
                    "Using %s as minimum cumulative difficulty",
                    hex(minimum_cumulative_difficulty),
                )
            except Exception as e:
                raise ValueError("Error parsing minimum cumulative difficulty: %s" %
                                 str(e))

            # Load state
            state = load_or_create_blockchain_state(user_options.statefile,
                                                    user_options.checkpoint, logger)
            state.minimum_cumulative_difficulty = minimum_cumulative_difficulty
            state.on_change(lambda: state.save_to_jsonfile(user_options.statefile))

        # Processing speed
        logger.info(
            "Using %d bps as the simulated device processing speed",
            user_options.speed_bps,
        )

        # The wallet
        wallet = load_or_create_wallet(
            user_options.keyfile, map(lambda p: str(p), get_authorized_signing_paths()))

        # Init protocol depending on the required version
        if user_options.version_one:
            logger.info("Using protocol version 1")
            protocol = HSM1ProtocolSimulator(wallet, user_options.speed_bps)
        else:
            logger.info("Using protocol version 2")
            protocol = HSM2ProtocolSimulator(
                wallet,
                state,
                user_options.bridge_address,
                netparams,
                user_options.speed_bps,
            )

        server = TCPServer(user_options.host, user_options.port, protocol)
    except Exception as e:
        logger.critical("Critical error while initializing simulator: %s", str(e))
        sys.exit(1)

    try:
        server.run()
    except TCPServerError:
        pass
    finally:
        logger.info("Manager terminated")
