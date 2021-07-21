from enum import IntEnum

class _Network(IntEnum):
    MAINNET = 0x01
    TESTNET = 0x02
    REGTEST = 0x03

# Instances of this represent parameters
# of firmware installed on an HSM2
# Parameters consist of minimum required difficulty, checkpoint and
# target network.
class HSM2FirmwareParameters:
    # Shorthand
    Network = _Network

    @staticmethod
    def from_dongle_format(param_bytes):
        if len(param_bytes) != 69:
            raise ValueError("Expected 69 bytes but got %d" % len(param_bytes))
        # Format:
        # Bytes 0-31: initial block hash
        # Bytes 32-67: minimum required difficulty (unsigned big endian)
        # Byte 68: network identifier
        checkpoint = param_bytes[0:32].hex()
        mrd = int.from_bytes(param_bytes[32:68], byteorder='big', signed=False)
        network = _Network(param_bytes[68])
        return HSM2FirmwareParameters(mrd, checkpoint, network)

    def __init__(self, min_required_difficulty, checkpoint, network):
        self.min_required_difficulty = min_required_difficulty
        self.checkpoint = checkpoint
        self.network = network
