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

from enum import IntEnum
from ledger.hsm2dongle import HSM2DongleError
from ledger.hsm2dongle_tcp import HSM2DongleTCP


class SgxCommand(IntEnum):
    SGX_ONBOARD = 0xA0,
    SGX_RETRIES = 0xA2,
    SGX_UNLOCK = 0xA3,
    SGX_ECHO = 0xA4,
    SGX_CHANGE_PASSWORD = 0xA5,
    SGX_UPGRADE = 0xA6,


class SgxUpgradeOps(IntEnum):
    START = 0x01,
    SPEC_SIG = 0x02,
    IDENTIFY_SELF = 0x03,
    IDENTIFY_PEER = 0x04,
    PROCESS_DATA = 0x05,


class SgxUpgradeRoles(IntEnum):
    EXPORTER = 0x01,
    IMPORTER = 0x02,


EVIDENCE_LEN_BYTES = 2
EVIDENCE_CHUNK_SIZE = 80


class HSM2DongleSGX(HSM2DongleTCP):
    # Echo message
    def echo(self):
        message = bytes([0x41, 0x42, 0x43])
        result = bytes(self._send_command(SgxCommand.SGX_ECHO, message))
        # Result should be the command plus the message
        expected_result = bytes([self.CLA, SgxCommand.SGX_ECHO]) + message
        return result == expected_result

    # Unlock the device with the given pin
    def unlock(self, pin):
        response = self._send_command(SgxCommand.SGX_UNLOCK, bytes([0]) + pin)

        # Nonzero indicates device unlocked
        return response[2] != 0

    # change pin
    def new_pin(self, pin):
        response = self._send_command(SgxCommand.SGX_CHANGE_PASSWORD, bytes([0]) + pin)

        # One indicates pin changed
        return response[2] == 1

    # returns the number of pin retries available
    def get_retries(self):
        apdu_rcv = self._send_command(SgxCommand.SGX_RETRIES)
        return apdu_rcv[2]

    # Attempt to onboard the device using the given seed and pin
    def onboard(self, seed, pin):
        if type(seed) != bytes or len(seed) != self.ONBOARDING.SEED_LENGTH:
            raise HSM2DongleError("Invalid seed given")

        if type(pin) != bytes:
            raise HSM2DongleError("Invalid pin given")

        self.logger.info("Sending onboard command")
        response = self._send_command(SgxCommand.SGX_ONBOARD, bytes([0x0]) + seed + pin)

        if response[2] != 1:
            raise HSM2DongleError("Error onboarding. Got '%s'" % response.hex())

        return True

    # Migration operations
    def migrate_db_spec(self, role, source_mre, destination_mre, signatures):
        # Send spec and role
        self._send_command(
            SgxCommand.SGX_UPGRADE,
            bytes([SgxUpgradeOps.START]) +
            bytes([role]) + source_mre + destination_mre)

        # Send signatures
        for signature in signatures:
            response = self._send_command(
                SgxCommand.SGX_UPGRADE,
                bytes([SgxUpgradeOps.SPEC_SIG]) + signature)

            if response[2] == 0:
                break

        if response[2] != 0:
            raise HSM2DongleError("Not enough correct signatures gathered")

    def migrate_db_get_evidence(self):
        evidence = bytes([])
        while True:
            response = self._send_command(
                SgxCommand.SGX_UPGRADE,
                bytes([SgxUpgradeOps.IDENTIFY_SELF]))

            evidence += response[3:]

            if response[2] == 0:
                break

        return evidence

    def migrate_db_send_evidence(self, evidence):
        evlen = len(evidence).to_bytes(
                EVIDENCE_LEN_BYTES, byteorder="big", signed=False)
        offset = 0
        while True:
            response = self._send_command(
                SgxCommand.SGX_UPGRADE,
                bytes([SgxUpgradeOps.IDENTIFY_PEER]) +
                (evlen if offset == 0 else bytes([])) +
                evidence[offset:offset+EVIDENCE_CHUNK_SIZE])
            offset += EVIDENCE_CHUNK_SIZE
            if response[2] == 0 or offset >= len(evidence):
                break

        if response[2] != 0:
            raise HSM2DongleError("Failed to receive evidence ack")

    def migrate_db_get_data(self):
        data = self._send_command(
            SgxCommand.SGX_UPGRADE,
            bytes([SgxUpgradeOps.PROCESS_DATA]))[3:]

        if len(data) == 0:
            raise HSM2DongleError("Migration data gathering failed."
                                  "Expected data but got 0 bytes instead")

        return data

    def migrate_db_send_data(self, data):
        self._send_command(
            SgxCommand.SGX_UPGRADE,
            bytes([SgxUpgradeOps.PROCESS_DATA]) + data)

    # Map from standard commands to SGX-specific commands
    SGX_SPECIFIC_COMMANDS = [
        HSM2DongleTCP.CMD.ADVANCE, HSM2DongleTCP.CMD.UPD_ANCESTOR
    ]

    # Send a specific piece of data in chunks to the device
    # as the device requests bytes from it.
    # Validate responses wrt current operation and next possible expected operations
    # Exceptions are to be handled by the caller
    def _send_data_in_chunks(
        self,
        command,
        operation,
        next_operations,
        data,
        expect_full_data,
        initial_bytes,
        operation_name,
        data_description,
    ):
        # Same old behavior for anything that hasn't got an SGX-specific
        # mapping
        if command not in self.SGX_SPECIFIC_COMMANDS:
            return super()._send_data_in_chunks(
                command,
                operation,
                next_operations,
                data, expect_full_data,
                initial_bytes,
                operation_name,
                data_description)

        # Send data in full
        response = self._send_command(command, bytes([operation]) + data)

        # We expect the device to ask for one of the next operations but
        # not the current chunk operation
        # If it doesn't happen, error out
        if response[self.OFF.OP] not in next_operations or \
           response[self.OFF.OP] == operation:
            self.logger.debug(
                "Current operation %s, next operations %s, ledger requesting %s",
                hex(operation),
                str(list(map(hex, next_operations))),
                hex(response[2]),
            )
            self.logger.error(
                "%s: unexpected response %s",
                operation_name.capitalize(),
                response.hex(),
            )
            return (False, response)

        # All is good
        return (True, response)
