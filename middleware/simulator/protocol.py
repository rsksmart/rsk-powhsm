import time
from comm.protocol import HSM2Protocol
from simulator.rsk.block import RskBlockHeader
from .authorization import authorize_signature_and_get_message_to_sign,\
    is_authorized_signing_path, is_auth_requiring_path
from comm.utils import normalize_hex_string, is_hex_string_of_length

class HSM2ProtocolSimulator(HSM2Protocol):
    def __init__(self, wallet, blockchain_state, log_emitter_address, network_parameters, speed_bps):
        super().__init__()
        self._wallet = wallet
        self._blockchain_state = blockchain_state

        if not is_hex_string_of_length(log_emitter_address, 20, allow_prefix=True):
            raise ValueError("Invalid log emitter address '%s'" % log_emitter_address)
        self._log_emitter_address = normalize_hex_string(log_emitter_address.lower())

        self._network_parameters = network_parameters
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
        # Simulate processing speed for the keyId
        self.__do_sleep(len(request["keyId"].to_binary()))

        # Validate key id is authorized for signing (only a specific set of paths is
        # allowed to be used for signing)
        if not is_authorized_signing_path(request["keyId"]):
            self.logger.info("Unauthorized Key ID: %s", str(request["keyId"]))
            return (self.ERROR_CODE_INVALID_KEYID,)

        # Authorize signature (only if needed)
        if is_auth_requiring_path(request["keyId"]):
            # First validate the required fields are OK
            auth_validation = self._validate_auth(request, mandatory=True)
            if auth_validation < self.ERROR_CODE_OK:
                return (auth_validation,)

            message_validation = self._validate_message(request, what="tx")
            if message_validation < self.ERROR_CODE_OK:
                return (message_validation,)

            # Simulate processing speed for the bulk of the request
            # (We assume the input index is 1 byte in length)
            self.__do_sleep(len(request["auth"]["receipt"])//2 +
                            len(request["auth"]["receipt_merkle_proof"])//2 +
                            len(request["message"]["tx"])//2 + 1)

            # Perform actual authorization
            # This method returns a tuple with two elements.
            # The first element is a boolean indicating success.
            # In case of success, the second element is the hash that is to be signed.
            # In case of failure, the second element is a negative integer indicating the
            # error type.
            auth_result = authorize_signature_and_get_message_to_sign(\
                request["auth"]["receipt"], \
                request["auth"]["receipt_merkle_proof"], \
                request["message"]["tx"], \
                request["message"]["input"], \
                self._log_emitter_address, \
                self._blockchain_state, \
                self.logger)
        else:
            # No authorization required, good to go (but first check required
            # fields are OK)
            message_validation = self._validate_message(request, what="hash")
            if message_validation < self.ERROR_CODE_OK:
                return (message_validation,)

            # Simulate processing speed for the bulk of the request
            self.__do_sleep(len(request["message"]["hash"])//2)

            auth_result = (True, request["message"]["hash"])

        # Authorization failed?
        if auth_result[0] == False:
            return (auth_result[1],)

        # Actually do the signing
        try:
            self.logger.info("Trying to sign '%s'", auth_result[1])
            signature = self._wallet.get(str(request["keyId"])).sign(auth_result[1])
        except Exception as e:
            self.logger.info("Error signing '%s': %s", auth_result[1], str(e))
            return (self.ERROR_CODE_DEVICE, )

        self.logger.info("Signed: R:%s S:%s", signature["r"], signature["s"])
        return (self.ERROR_CODE_OK, {
            "signature": {
                "r": signature["r"],
                "s": signature["s"]
            }
        })

    def _blockchain_state(self, request):
        return (self.ERROR_CODE_OK, { "state": self._blockchain_state.to_dict() })

    def _advance_blockchain(self, request):
        return self.__do_block_operation(request, self._blockchain_state.advance,
                                         "advancing blockchain", mm_is_mandatory=True)

    def _reset_advance_blockchain(self, request):
        self._blockchain_state.reset_advance()
        return (self.ERROR_CODE_OK, {})

    def _update_ancestor_block(self, request):
        return self.__do_block_operation(request, self._blockchain_state.update_ancestor,
                                         "updating the ancestor block", mm_is_mandatory=False)

    def __do_block_operation(self, request, processor, operation_name, mm_is_mandatory):
        # Simulate processing speed
        self.__do_sleep(sum(map(lambda b: len(b)//2, request["blocks"])))

        # Parse raw blocks into RskBlockHeader instances
        try:
            blocks = list(map(lambda rb: RskBlockHeader(rb, self._network_parameters, mm_is_mandatory=mm_is_mandatory), request["blocks"]))
        except ValueError as e:
            self.logger.info("Error parsing blocks: %s" % format(e))
            return (self.ERROR_CODE_INVALID_INPUT_BLOCKS, )

        # Do the actual processing
        try:
            operation_result = processor(blocks)
            return (operation_result, {})
        except RuntimeError as e:
            self.logger.info("Unexpected error %s: %s" % (operation_name, format(e)))
            return (self.ERROR_CODE_UNKNOWN, )

    def __do_sleep(self, request_size_in_bytes):
        # Sleep depending on the configured processing speed
        # and the amount of bytes to process
        sleep_seconds = request_size_in_bytes / self._speed_bps
        self.logger.info("Processing %d bytes at %d bps, sleeping for %.4f seconds",
                         request_size_in_bytes, self._speed_bps, sleep_seconds)
        time.sleep(sleep_seconds)
