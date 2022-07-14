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
            manual_unlock = run_args[TestCase.RUN_ARGS_MANUAL_KEY]
            if not manual_unlock:
                pin = run_args[TestCase.RUN_ARGS_PIN_KEY].encode()

            print()
            print('Dongle reconnection test')

            # Device is expected to be connected and in APP mode at the begining
            self.assert_dongle_mode(dongle, HSM2Dongle.MODE.APP)
            dongle.disconnect()

            # Unlock device (can be performed automatically or manually by user)
            if manual_unlock:
                print('Please disconnect and re-connect the device, unlock it '
                      'and open the signer')
                input('Press [Enter] to continue')
                self.wait_for_reconnection()
                dongle.connect()
            else:
                print('Please disconnect and re-connect the device.')
                input('Press [Enter] to continue')
                self.wait_for_reconnection()
                dongle.connect()
                self.assert_dongle_mode(dongle, HSM2Dongle.MODE.BOOTLOADER)
                if not dongle.echo():
                    raise TestCaseError("Echo error")
                if not dongle.unlock(pin):
                    raise TestCaseError('Failed to unlock device')
                try:
                    dongle.exit_menu(autoexec=True)
                except Exception:
                    pass
                print('Device unlocked')

            # Disconnect from bootloader, connect to app
            dongle.disconnect()
            self.wait_for_reconnection()
            dongle.connect()

            # Device is expected to be connected and in APP mode at the end of this test
            self.assert_dongle_mode(dongle, HSM2Dongle.MODE.APP)
        except RuntimeError as e:
            raise TestCaseError(str(e))
