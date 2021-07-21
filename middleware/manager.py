import os
from comm.server import TCPServer, TCPServerError
from user.options import UserOptionParser
from ledger.protocol import HSM2ProtocolLedger
from ledger.protocol_v1 import HSM1ProtocolLedger
from ledger.hsm2dongle import HSM2Dongle
from ledger.pin import FileBasedPin, PinError
from comm.logging import configure_logging
import logging

if __name__ == "__main__":
    user_options = UserOptionParser("Start the HSM2 manager", is_simulator=False).parse()

    configure_logging(user_options.logconfigfilepath)
    logger = logging.getLogger("hsm-ledger")

    logger.info("Manager starting")

    try:
        env_pin = os.environ.get("PIN", None)
        if env_pin is not None:
            env_pin = env_pin.encode()
        pin = FileBasedPin(user_options.pin_file, \
                           default_pin=env_pin, \
                           force_change=user_options.force_pin_change)
        dongle = HSM2Dongle(user_options.dongle_debug)
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
        pass
    finally:
        logger.info("Manager terminated")
