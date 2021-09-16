# Parses a signature received from an HSM 2 dongle
class HSM2DongleSignature:
    def __init__(self, signature_bytes):
        def error():
            raise ValueError("Invalid DER-encoded signature: %s" % signature_bytes.hex())

        # Decode signature_bytes, which should be in DER format
        # Format:
        #
        # 0x30 TOTAL_LENGTH
        # 0x02 R_LENGTH [R bytes]
        # 0x02 S_LENGTH [S bytes]
        # [potential rubbish]
        #
        # IMPORTANT: due to a bug, sometimes the first byte is 0x31 and not 0x30.
        # Deal with it.
        if (
            len(signature_bytes) < 2
            or signature_bytes[0] not in [0x30, 0x31]
            or len(signature_bytes[2:]) < signature_bytes[1]
        ):
            error()

        # R
        if (
            len(signature_bytes[2:]) < 2
            or signature_bytes[2] != 0x02
            or len(signature_bytes[4:]) < signature_bytes[3]
        ):
            error()
        r_len = signature_bytes[3]
        rbytes = signature_bytes[4:4 + r_len]

        # S
        if (
            len(signature_bytes[4 + r_len:]) < 2
            or signature_bytes[4 + r_len] != 0x02
            or len(signature_bytes[6 + r_len:]) < signature_bytes[5 + r_len]
        ):
            error()
        s_len = signature_bytes[5 + r_len]
        sbytes = signature_bytes[6 + r_len:6 + r_len + s_len]

        self._r = rbytes.hex()
        self._s = sbytes.hex()

    @property
    def r(self):
        return self._r

    @property
    def s(self):
        return self._s
