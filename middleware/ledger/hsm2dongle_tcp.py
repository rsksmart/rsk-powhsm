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
