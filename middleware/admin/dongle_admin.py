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

import os
import struct
from enum import IntEnum
import secp256k1 as ec
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException


class DongleAdminError(RuntimeError):
    pass


class DongleAdminTimeout(RuntimeError):
    @staticmethod
    def is_timeout(exc):
        if type(exc) == CommException and exc.sw == 0x6F00 and exc.message == "Timeout":
            return True
        return False


# Dongle commands
class _Command(IntEnum):
    IDENTIFY = 0x04
    NONCE = 0x50
    SEND_KEY = 0x51
    GET_KEY = 0x52
    SETUP_ENDO = 0xC0
    SETUP_ENDO_ACK = 0xC2


class _SubCommand(IntEnum):
    SEND_KEY_MASTER = 0x00
    SEND_KEY_EPHEMERAL = 0x80
    GET_KEY_DEVICE = 0x00
    GET_KEY_EPHEMERAL = 0x80


class _Role(IntEnum):
    MASTER = 0x01
    DEVICE = 0x02
    EPHEMERAL = 0x11
    ENDORSEMENT = 0xFF


class _EndorsementScheme(IntEnum):
    SCHEME_ONE = 1
    SCHEME_TWO = 2


# Handles low-level communication with an powHSM dongle for
# some factory/legacy commands
class DongleAdmin:
    # APDU prefix
    CLA = 0xE0

    TARGET_ID = bytes.fromhex("31100002")
    NONCE_LENGTH = 8

    # Enumeration shorthands
    CMD = _Command
    SUBCMD = _SubCommand
    ROLE = _Role
    ENDORSEMENT_SCHEME = _EndorsementScheme

    # Dongle exchange timeout
    DONGLE_TIMEOUT = 10  # seconds

    def __init__(self, debug):
        self.debug = debug

    # Send command to device
    def _send_command(self, command, data=b"", timeout=DONGLE_TIMEOUT):
        try:
            cmd = struct.pack("BB%ds" % len(data), self.CLA, command, data)
            result = self.dongle.exchange(cmd, timeout=timeout)
        except (CommException, BaseException) as e:
            # If this is a dongle timeout, raise a timeout exception
            if DongleAdminTimeout.is_timeout(e):
                raise DongleAdminTimeout()

            # Otherwise, raise a standard error
            msg = "Error sending command: %s" % str(e)
            raise DongleAdminError(msg)
        return result

    # Connect to the dongle
    def connect(self):
        try:
            self.dongle = getDongle(self.debug)
        except CommException as e:
            msg = "Error connecting: %s" % e.message
            raise DongleAdminError(msg)

    # Disconnect from dongle
    def disconnect(self):
        try:
            if self.dongle and self.dongle.opened:
                self.dongle.close()
        except CommException as e:
            msg = "Error disconnecting: %s" % e.message
            raise DongleAdminError(msg)

    def _ensure_connected(self):
        if self.dongle is None or not self.dongle.opened:
            raise DongleAdminError("Connect to dongle first")

    # Handshake for an interaction
    # (optional master key can be given so that a
    # subsequent authorization from user is not needed)
    def handshake(self, master_key=None):
        self._ensure_connected()

        # Identify
        self._send_command(self.CMD.IDENTIFY,
                           bytes([0x00, 0x00, len(self.TARGET_ID)]) + self.TARGET_ID)

        # Exchange nonces
        nonce = os.urandom(self.NONCE_LENGTH)
        response = self._send_command(self.CMD.NONCE,
                                      bytes([0x00, 0x00, self.NONCE_LENGTH]) + nonce)
        device_nonce = response[
            4:12]  # First 4 bytes are the device batch, we don't need it

        # Inform master key
        if master_key is None:
            master_key = ec.PrivateKey()
        master_key_pub = master_key.pubkey.serialize(compressed=False)

        to_sign = bytes([self.ROLE.MASTER]) + master_key_pub
        signature = master_key.ecdsa_serialize(master_key.ecdsa_sign(bytes(to_sign)))
        certificate = (bytes([len(master_key_pub)]) + master_key_pub +
                       bytes([len(signature)]) + signature)
        self._send_command(
            self.CMD.SEND_KEY,
            bytes([self.SUBCMD.SEND_KEY_MASTER, 0x00,
                   len(certificate)]) + certificate,
        )

        # Generate and inform ephemeral key
        ephemeral_key = ec.PrivateKey()
        ephemeral_key_pub = ephemeral_key.pubkey.serialize(compressed=False)
        to_sign = bytes([self.ROLE.EPHEMERAL]) + nonce + device_nonce + ephemeral_key_pub
        signature = master_key.ecdsa_serialize(master_key.ecdsa_sign(bytes(to_sign)))
        certificate = (bytes([len(ephemeral_key_pub)]) + ephemeral_key_pub +
                       bytes([len(signature)]) + signature)
        self._send_command(
            self.CMD.SEND_KEY,
            bytes([self.SUBCMD.SEND_KEY_EPHEMERAL, 0x00,
                   len(certificate)]) + certificate,
        )

        # Return the ephemeral key
        return ephemeral_key

    # Get the device key alongside its issuer's certificate
    def get_device_key(self):
        self._ensure_connected()

        response = self._send_command(self.CMD.GET_KEY,
                                      bytes([self.SUBCMD.GET_KEY_DEVICE, 0x00, 0x00]))

        # Response has 3 components: certificate header, device public key and signature
        cert_header_length = response[0]
        cert_header = bytes(response[1:1 + cert_header_length])
        response = response[1 + cert_header_length:]
        dev_key_pub_length = response[0]
        dev_key_pub = bytes(response[1:1 + dev_key_pub_length])
        response = response[1 + dev_key_pub_length:]
        signature_length = response[0]
        signature = bytes(response[1:1 + signature_length])

        # Expected signed data is: key role, certificate header, device public key
        signed_data = bytes([self.ROLE.DEVICE]) + cert_header + dev_key_pub

        # Don't really know whether this is needed, but request what
        # should be the device's ephemeral key (for this session?)
        # Anyway, just ignore the response
        self._send_command(self.CMD.GET_KEY,
                           bytes([self.SUBCMD.GET_KEY_EPHEMERAL, 0x00, 0x00]))

        # Return the raw device key along with the raw signature and raw signed data
        return {
            "pubkey": dev_key_pub.hex(),
            "message": signed_data.hex(),
            "signature": signature.hex(),
        }

    def setup_endorsement_key(self, scheme, endorsement_certificate):
        self._ensure_connected()

        if scheme not in [1, 2]:
            raise DongleAdminError(f"Invalid endorsement scheme {scheme}, must be 1 or 2")

        response = self._send_command(self.CMD.SETUP_ENDO, bytes([scheme, 0x00, 0x00]))

        endorsement_key_pub = bytes(response[:65])
        signature = bytes(response[65:])

        # Expected signed data is: endorsement role + endorsement public key
        signed_data = bytes([self.ROLE.ENDORSEMENT]) + endorsement_key_pub

        # Send endorsement certificate in order to confirm setup
        self._send_command(
            self.CMD.SETUP_ENDO_ACK,
            bytes([0x00, 0x00, len(endorsement_certificate)]) + endorsement_certificate,
        )

        # Return the raw endorsement public key along with the raw signature
        # and raw signed data
        return {
            "pubkey": endorsement_key_pub.hex(),
            "message": signed_data.hex(),
            "signature": signature.hex(),
        }
