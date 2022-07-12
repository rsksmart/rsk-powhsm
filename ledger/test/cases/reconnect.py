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
from ledger.hsm2dongle import HSM2FirmwareVersion
import time


class ReconnectDongle(TestCase):
    @classmethod
    def op_name(cls):
        return "reconnectDongle"

    def __init__(self, spec):
        self.version = HSM2FirmwareVersion(3, 0, 0)
        self.pin = spec["pin"].encode()
        self.auto_unlock = spec.get("autoUnlock", True)
        super().__init__(spec)

    def wait_for_reconnection(self):
        time.sleep(3)

    def assert_connected(self, dongle):
        try:
            # We use get_version to make sure the dongle is actually connected
            version = dongle.get_version()
        except RuntimeError:
            raise TestCaseError('Device not connected')
        if version != self.version:
            raise TestCaseError('Wrong version')

    def run(self, dongle, debug):
        try:
            print()
            print('Dongle reconnection test')
            # STEP 1: assert device is connected
            self.assert_connected(dongle)

            # STEP 2: user unplugs the device
            dongle.disconnect()
            print('Please disconnect the device.')
            input('Press [Enter] to continue')

            # STEP 3: user plugs the device again
            print('Please reconnect the device.')
            input('Press [Enter] to continue')

            # Connect to bootloader, unlock proccess will fail if user skips reconnection
            self.wait_reconnection()
            dongle.connect()
            if self.auto_unlock:
                if not dongle.echo():
                    raise TestCaseError("Echo error")
                if not dongle.unlock(self.pin):
                    raise TestCaseError('Failed to unlock device')
                try:
                    dongle.exit_menu(autoexec=True)
                except Exception:
                    pass
                print('Device unlocked')
            else:
                print('Please unlock the device...')
            input('Press [Enter] to continue')

            # Disconnect from bootloader, connect to app
            dongle.disconnect()
            self.wait_reconnection()
            dongle.connect()

            self.assert_connected(dongle)
        except RuntimeError as e:
            raise TestCaseError(str(e))
