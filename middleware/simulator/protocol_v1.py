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
            return (self.ERROR_CODE_INVALID_KEYID,)

        return (self.ERROR_CODE_OK, {
            "pubKey": self._wallet.get(str(request["keyId"])).public_key()
        })

    def _sign(self, request):
        # Simulate processing speed
        self.__do_sleep(len(request["keyId"].to_binary()) + len(request["message"])//2)

        # Validate key id is authorized for signing without an authorization proof 
        # (only a specific set of paths is allowed to be used for unauthorized signing)
        if not is_authorized_signing_path(request["keyId"]) or is_auth_requiring_path(request["keyId"]):
            self.logger.info("Unauthorized Key ID: %s", str(request["keyId"]))
            return (self.ERROR_CODE_INVALID_KEYID,)

        # Actually do the signing
        try:
            self.logger.info("Trying to sign '%s'", request["message"])
            signature = self._wallet.get(str(request["keyId"])).sign(request["message"])
        except Exception as e:
            self.logger.info("Error signing '%s': %s", request["message"], str(e))
            return (self.ERROR_CODE_DEVICE, )

        self.logger.info("Signed: R:%s S:%s", signature["r"], signature["s"])
        return (self.ERROR_CODE_OK, {
            "signature": {
                "r": signature["r"],
                "s": signature["s"]
            }
        })

    def __do_sleep(self, request_size_in_bytes):
        # Sleep depending on the configured processing speed
        # and the amount of bytes to process
        sleep_seconds = request_size_in_bytes / self._speed_bps
        self.logger.info("Processing %d bytes at %d bps, sleeping for %.4f seconds",
                         request_size_in_bytes, self._speed_bps, sleep_seconds)
        time.sleep(sleep_seconds)
