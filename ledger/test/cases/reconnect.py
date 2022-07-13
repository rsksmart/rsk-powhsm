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

from .case import TestCase, TestCaseError
from ledger.hsm2dongle import HSM2Dongle
import time


class ReconnectDongle(TestCase):
    @classmethod
    def op_name(cls):
        return "reconnectDongle"

    def __init__(self, spec):
        super().__init__(spec)

    def wait_for_reconnection(self):
        time.sleep(3)

    def assert_dongle_mode(self, dongle, expected_mode):
        curr_mode = dongle.get_current_mode()
        if curr_mode != expected_mode:
            raise TestCaseError(f'Unexpected dongle mode: {curr_mode} '
                                f'(expected {expected_mode})')

    def run(self, dongle, debug, run_args):
        try:
            if run_args[TestCase.RUN_ARGS_PIN_KEY] is None:
                raise TestCaseError('Device pin missing!')
            pin = run_args[TestCase.RUN_ARGS_PIN_KEY].encode()
            manual_unlock = run_args[TestCase.RUN_ARGS_MANUAL_KEY]

            print()
            print('Dongle reconnection test')

            # STEP 1: Device is expected to be connected and in APP mode at the begining
            self.assert_dongle_mode(dongle, HSM2Dongle.MODE.APP)

            # STEP 2: user reconnects the device
            dongle.disconnect()
            print('Please disconnect and re-connect the device.')
            input('Press [Enter] to continue')
            self.wait_for_reconnection()
            dongle.connect()

            # STEP 3: Device is expected to be in BOOTLOADER mode after reconnection
            self.assert_dongle_mode(dongle, HSM2Dongle.MODE.BOOTLOADER)

            # STEP 4: unlock device (can be performed automatically or manually by user)
            if manual_unlock:
                print('Please unlock the device...')
            else:
                if not dongle.echo():
                    raise TestCaseError("Echo error")
                if not dongle.unlock(pin):
                    raise TestCaseError('Failed to unlock device')
                try:
                    dongle.exit_menu(autoexec=True)
                except Exception:
                    pass
                print('Device unlocked')
            input('Press [Enter] to continue')

            # Disconnect from bootloader, connect to app
            dongle.disconnect()
            self.wait_for_reconnection()
            dongle.connect()

            # Device is expected to be connected and in APP mode at the end of this test
            self.assert_dongle_mode(dongle, HSM2Dongle.MODE.APP)
        except RuntimeError as e:
            raise TestCaseError(str(e))
